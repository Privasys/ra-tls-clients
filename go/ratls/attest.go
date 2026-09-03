// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// RA-TLS v2: attestation evidence after the handshake (docs/ratls-v2.md).
//
// The certificate identifies the enclave (leaf key, chain to the Privasys
// intermediate, Privasys OIDs) and carries no evidence. After the handshake the
// client asks for a quote on the same connection, before any application data,
// and checks that its report_data commits to the leaf key and, in challenge
// mode, to a value only the two ends of this TLS connection can derive
// (an RFC 8446 section 7.5 exporter keyed by exporter_master_secret).

package ratls

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// AttestPath is the reserved path of the evidence endpoint on every
	// RA-TLS v2 server (HTTP binding).
	AttestPath = "/__privasys/attest"
	// ProtocolVersion is the "v" field of every attest message.
	ProtocolVersion = 2
	// ExporterLabelServer keys the server evidence of a connection.
	ExporterLabelServer = "EXPORTER-privasys-ratls-attest-v2"
	// ExporterLabelClient keys the client evidence of a connection (mutual leg).
	ExporterLabelClient = "EXPORTER-privasys-ratls-attest-v2-client"
	// QuoteTimeLayout is the minute-precision layout of quote_time.
	QuoteTimeLayout = "2006-01-02T15:04Z"
	// ContextLen is the length of a challenge context in bytes.
	ContextLen = 32
	// HctxLen is the length of the exporter output in bytes.
	HctxLen = 32
	// MaxFrame is the largest raw-binding frame accepted, in bytes.
	MaxFrame = 65536

	// quoteMaxAge bounds a deterministic quote_time: the runtime caches a
	// quote for 24 hours; 5 minutes of skew are allowed on both sides.
	quoteMaxAge = 24*time.Hour + 5*time.Minute
	quoteSkew   = 5 * time.Minute
)

// AttestationMode selects what the client asks the server for after the
// handshake. The zero value is Challenge, the safe default.
type AttestationMode int

const (
	// AttestationChallenge asks for a quote bound to this connection through
	// the TLS exporter and a fresh context (Level 3 binding).
	AttestationChallenge AttestationMode = iota
	// AttestationDeterministic asks for the runtime's cached quote, bound to
	// the leaf key and a minute timestamp only (the "trust the TEE" tier).
	AttestationDeterministic
	// AttestationNone sends no request; the connection is tagged by the
	// server as attestation-not-requested and VerifyCertificate checks the
	// certificate extensions only.
	AttestationNone
)

func (m AttestationMode) String() string {
	switch m {
	case AttestationChallenge:
		return "challenge"
	case AttestationDeterministic:
		return "deterministic"
	case AttestationNone:
		return "none"
	}
	return fmt.Sprintf("AttestationMode(%d)", int(m))
}

// Framing selects how the attest messages are carried on the connection.
type Framing int

const (
	// FramingHTTP sends POST /__privasys/attest as an HTTP/1.1 request.
	FramingHTTP Framing = iota
	// FramingRaw sends one u32 big-endian length-prefixed JSON frame in each
	// direction as the first application records, for legs that do not
	// speak HTTP (KMIP, raft peer link).
	FramingRaw
)

// Evidence is the verified-or-not evidence a server returned for a connection.
type Evidence struct {
	// Mode the evidence was requested in.
	Mode AttestationMode
	// TEE is the evidence family: "sgx", "tdx", "tdx-gpu".
	TEE string
	// Quote is the raw DCAP quote.
	Quote []byte
	// GPUEvidence is the NVIDIA CC evidence bundle, nil when absent.
	GPUEvidence []byte
	// QuoteTime is the minute the quote was minted, as parsed from QuoteTimeRaw.
	QuoteTime time.Time
	// QuoteTimeRaw is the 17-byte ASCII quote_time, an input of report_data
	// in deterministic mode.
	QuoteTimeRaw string
	// Context is the client's 32-byte context (challenge mode).
	Context []byte
	// Hctx is this connection's exporter output for Context (challenge mode).
	// It never travels; both ends compute it.
	Hctx []byte
	// ClientEvidenceRequired reports that the server asked for client evidence
	// (mutual leg) and ClientContext holds the context it chose.
	ClientEvidenceRequired bool
	ClientContext          []byte
}

// ClientEvidenceRequest is what a ClientEvidenceSource receives when the
// server requires client evidence on a mutual leg.
type ClientEvidenceRequest struct {
	// SPKIDER is the DER SubjectPublicKeyInfo of the client certificate this
	// connection presented.
	SPKIDER []byte
	// Context is the server-chosen 32-byte client_context.
	Context []byte
	// Hctx is this connection's exporter output under ExporterLabelClient.
	Hctx []byte
	// ReportData is the value the quote must carry:
	// SHA-512( SHA-256(SPKIDER) || Context || Hctx ) [|| SHA-256(gpu_evidence)].
	// A source that returns GPU evidence must recompute it with the fold.
	ReportData []byte
}

// ClientEvidence is what a ClientEvidenceSource returns.
type ClientEvidence struct {
	TEE         string
	Quote       []byte
	GPUEvidence []byte
	QuoteTime   string
}

// ClientEvidenceSource produces this client's own evidence for a mutual leg.
// Containers use ManagerEvidenceSource; an enclave runtime implements it with
// its own quote provider.
type ClientEvidenceSource func(ClientEvidenceRequest) (*ClientEvidence, error)

// -- messages ---------------------------------------------------------------

type attestRequest struct {
	V       int    `json:"v"`
	Mode    string `json:"mode"`
	Leaf    string `json:"leaf"`
	Context string `json:"context,omitempty"`
}

type attestResponse struct {
	V              int     `json:"v"`
	Mode           string  `json:"mode"`
	TEE            string  `json:"tee"`
	Quote          string  `json:"quote"`
	GPUEvidence    *string `json:"gpu_evidence"`
	QuoteTime      string  `json:"quote_time"`
	ClientEvidence string  `json:"client_evidence"`
	ClientContext  *string `json:"client_context"`
	Error          string  `json:"error,omitempty"`
}

type presentRequest struct {
	V           int     `json:"v"`
	Mode        string  `json:"mode"`
	Context     string  `json:"context"`
	TEE         string  `json:"tee"`
	Quote       string  `json:"quote"`
	GPUEvidence *string `json:"gpu_evidence"`
	QuoteTime   string  `json:"quote_time"`
}

var b64 = base64.RawURLEncoding

func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(strings.TrimRight(s, "="))
}

// -- report_data ------------------------------------------------------------

// ExpectedReportData computes the report_data a quote must carry for the leaf
// whose SubjectPublicKeyInfo is spkiDER and the evidence ev:
//
//	deterministic: SHA-512( SHA-256(SPKI_DER) || quote_time )
//	challenge:     SHA-512( SHA-256(SPKI_DER) || context || hctx )
//
// with SHA-256(gpu_evidence) appended to the binding when GPU evidence is
// present. The verifier predicts this value; it never accepts one from the peer.
func ExpectedReportData(spkiDER []byte, ev *Evidence) ([]byte, error) {
	binding, err := reportDataBinding(ev)
	if err != nil {
		return nil, err
	}
	return computeReportDataHash(spkiDER, binding), nil
}

func reportDataBinding(ev *Evidence) ([]byte, error) {
	var binding []byte
	switch ev.Mode {
	case AttestationDeterministic:
		if len(ev.QuoteTimeRaw) != len(QuoteTimeLayout) {
			return nil, fmt.Errorf("ratls: deterministic evidence needs a quote_time")
		}
		binding = []byte(ev.QuoteTimeRaw)
	case AttestationChallenge:
		if len(ev.Context) != ContextLen || len(ev.Hctx) != HctxLen {
			return nil, fmt.Errorf("ratls: challenge evidence needs a %d-byte context and a %d-byte exporter value", ContextLen, HctxLen)
		}
		binding = append(append([]byte(nil), ev.Context...), ev.Hctx...)
	default:
		return nil, fmt.Errorf("ratls: no report_data for attestation mode %s", ev.Mode)
	}
	if len(ev.GPUEvidence) > 0 {
		s := sha256.Sum256(ev.GPUEvidence)
		binding = append(binding, s[:]...)
	}
	return binding, nil
}

// ClientReportData is ExpectedReportData for the client evidence of a mutual
// leg: SHA-512( SHA-256(client SPKI) || client_context || hctx_c ) with the
// same GPU fold.
func ClientReportData(spkiDER, clientContext, hctx, gpuEvidence []byte) []byte {
	binding := append(append([]byte(nil), clientContext...), hctx...)
	if len(gpuEvidence) > 0 {
		s := sha256.Sum256(gpuEvidence)
		binding = append(binding, s[:]...)
	}
	return computeReportDataHash(spkiDER, binding)
}

// QuoteReportData extracts the 64-byte report_data of a raw quote of the
// given evidence family.
func QuoteReportData(tee string, quote []byte) ([]byte, error) {
	switch tee {
	case "sgx":
		format := DetectSgxFormat(quote)
		_, _, _, _, rdOff, rdEnd, _ := sgxOffsets(format)
		if len(quote) < rdEnd {
			return nil, fmt.Errorf("SGX quote too small to contain report_data")
		}
		return quote[rdOff:rdEnd], nil
	case "tdx", "tdx-gpu":
		if len(quote) < TDXQuoteReportDataEnd {
			return nil, fmt.Errorf("TDX quote too small to contain report_data")
		}
		return quote[TDXQuoteReportDataOff:TDXQuoteReportDataEnd], nil
	case "sev-snp":
		if len(quote) < SEVSNPReportDataEnd {
			return nil, fmt.Errorf("SEV-SNP report too small to contain report_data")
		}
		return quote[SEVSNPReportDataOff:SEVSNPReportDataEnd], nil
	}
	return nil, fmt.Errorf("unknown evidence family %q", tee)
}

// teeTypeOf maps an evidence family string to a TeeType.
func teeTypeOf(tee string) (TeeType, bool) {
	switch tee {
	case "sgx":
		return TeeTypeSGX, true
	case "tdx", "tdx-gpu":
		return TeeTypeTDX, true
	case "sev-snp":
		return TeeTypeSEVSNP, true
	}
	return 0, false
}

// String names the TEE family as it appears in attest messages.
func (t TeeType) String() string {
	switch t {
	case TeeTypeSGX:
		return "sgx"
	case TeeTypeTDX:
		return "tdx"
	case TeeTypeSEVSNP:
		return "sev-snp"
	case TeeTypeNVIDIAGPU:
		return "nvidia-gpu"
	}
	return fmt.Sprintf("TeeType(%d)", int(t))
}

// ExportHctx derives the 32-byte exporter value of a connection for label and
// context (RFC 8446 section 7.5), keyed by exporter_master_secret.
func ExportHctx(cs tls.ConnectionState, label string, context []byte) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("ratls: exporter needs TLS 1.3, negotiated 0x%04x", cs.Version)
	}
	out, err := cs.ExportKeyingMaterial(label, context, HctxLen)
	if err != nil {
		return nil, fmt.Errorf("ratls: exporter: %w", err)
	}
	return out, nil
}

// CheckQuoteTime rejects a quote_time older than the cache lifetime or ahead
// of the clock beyond the allowed skew.
func CheckQuoteTime(raw string, now time.Time) (time.Time, error) {
	t, err := time.Parse(QuoteTimeLayout, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("ratls: quote_time %q: %w", raw, err)
	}
	if t.After(now.Add(quoteSkew)) {
		return t, fmt.Errorf("ratls: quote_time %s is in the future", raw)
	}
	if now.Sub(t) > quoteMaxAge {
		return t, fmt.Errorf("ratls: quote_time %s is older than 24 hours", raw)
	}
	return t, nil
}

// -- the exchange -----------------------------------------------------------

// leafID is the "leaf" field: SHA-256 of the SPKI DER of the received leaf.
func leafID(spkiDER []byte) string {
	h := sha256.Sum256(spkiDER)
	return b64.EncodeToString(h[:])
}

// attest runs the evidence exchange for c in mode and stores the result in
// c.evidence. It verifies nothing beyond message well-formedness; policy
// verification is VerifyCertificate.
func (c *Client) attest(mode AttestationMode) error {
	if mode == AttestationNone {
		c.evidence = nil
		return nil
	}
	if len(c.peerCerts) == 0 {
		return fmt.Errorf("ratls: no peer certificate")
	}
	spki, err := spkiDEROf(c.peerCerts[0])
	if err != nil {
		return err
	}
	req := attestRequest{V: ProtocolVersion, Mode: mode.String(), Leaf: leafID(spki)}
	ev := &Evidence{Mode: mode}
	if mode == AttestationChallenge {
		ctx := make([]byte, ContextLen)
		if _, err := rand.Read(ctx); err != nil {
			return fmt.Errorf("ratls: context: %w", err)
		}
		hctx, err := ExportHctx(c.conn.ConnectionState(), ExporterLabelServer, ctx)
		if err != nil {
			return err
		}
		ev.Context, ev.Hctx = ctx, hctx
		req.Context = b64.EncodeToString(ctx)
	}
	body, _ := json.Marshal(req)
	status, respBody, err := c.attestRoundTrip(body)
	if err != nil {
		return err
	}
	var resp attestResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return fmt.Errorf("ratls: attest response: %w", err)
	}
	if status != http.StatusOK || resp.Error != "" {
		if resp.Error == "" {
			resp.Error = strings.TrimSpace(string(respBody))
		}
		if status == http.StatusNotFound {
			return fmt.Errorf("ratls: server has no RA-TLS v2 evidence endpoint (%s): %s", AttestPath, resp.Error)
		}
		return fmt.Errorf("ratls: attest failed (%d): %s", status, resp.Error)
	}
	if resp.V != ProtocolVersion {
		return fmt.Errorf("ratls: attest response version %d, want %d", resp.V, ProtocolVersion)
	}
	if resp.Mode != mode.String() {
		return fmt.Errorf("ratls: attest response mode %q, requested %q", resp.Mode, mode)
	}
	if _, ok := teeTypeOf(resp.TEE); !ok {
		return fmt.Errorf("ratls: attest response: unknown tee %q", resp.TEE)
	}
	ev.TEE = resp.TEE
	if ev.Quote, err = b64Decode(resp.Quote); err != nil || len(ev.Quote) == 0 {
		return fmt.Errorf("ratls: attest response: quote is not base64url")
	}
	if resp.GPUEvidence != nil && *resp.GPUEvidence != "" {
		if ev.GPUEvidence, err = b64Decode(*resp.GPUEvidence); err != nil {
			return fmt.Errorf("ratls: attest response: gpu_evidence is not base64url")
		}
	}
	ev.QuoteTimeRaw = resp.QuoteTime
	if ev.QuoteTime, err = CheckQuoteTime(resp.QuoteTime, time.Now().UTC()); err != nil {
		return err
	}
	switch resp.ClientEvidence {
	case "", "none":
	case "required":
		ev.ClientEvidenceRequired = true
		if resp.ClientContext == nil {
			return fmt.Errorf("ratls: server requires client evidence without a client_context")
		}
		if ev.ClientContext, err = b64Decode(*resp.ClientContext); err != nil || len(ev.ClientContext) != ContextLen {
			return fmt.Errorf("ratls: client_context is not a %d-byte base64url value", ContextLen)
		}
	default:
		return fmt.Errorf("ratls: attest response: unknown client_evidence %q", resp.ClientEvidence)
	}
	c.evidence = ev
	if ev.ClientEvidenceRequired {
		return c.present(ev)
	}
	return nil
}

// present answers a server that requires client evidence.
func (c *Client) present(ev *Evidence) error {
	if c.clientEvidence == nil {
		return fmt.Errorf("ratls: server requires client evidence and Options.ClientEvidence is not set")
	}
	if c.presentedCert == nil || len(c.presentedCert.Certificate) == 0 {
		return fmt.Errorf("ratls: server requires client evidence but no client certificate was presented")
	}
	leaf, err := parseLeaf(c.presentedCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("ratls: presented client certificate: %w", err)
	}
	spki, err := spkiDEROf(leaf)
	if err != nil {
		return err
	}
	hctx, err := ExportHctx(c.conn.ConnectionState(), ExporterLabelClient, ev.ClientContext)
	if err != nil {
		return err
	}
	req := ClientEvidenceRequest{SPKIDER: spki, Context: ev.ClientContext, Hctx: hctx}
	req.ReportData = ClientReportData(spki, ev.ClientContext, hctx, nil)
	ce, err := c.clientEvidence(req)
	if err != nil {
		return fmt.Errorf("ratls: client evidence: %w", err)
	}
	if ce == nil || len(ce.Quote) == 0 {
		return fmt.Errorf("ratls: client evidence source returned no quote")
	}
	msg := presentRequest{
		V: ProtocolVersion, Mode: "present",
		Context:   b64.EncodeToString(ev.ClientContext),
		TEE:       ce.TEE,
		Quote:     b64.EncodeToString(ce.Quote),
		QuoteTime: ce.QuoteTime,
	}
	if len(ce.GPUEvidence) > 0 {
		s := b64.EncodeToString(ce.GPUEvidence)
		msg.GPUEvidence = &s
	}
	body, _ := json.Marshal(msg)
	status, respBody, err := c.attestRoundTrip(body)
	if err != nil {
		return err
	}
	if c.framing == FramingRaw {
		var ack struct {
			V     int    `json:"v"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(respBody, &ack); err != nil || ack.V != ProtocolVersion || ack.Error != "" {
			return fmt.Errorf("ratls: client evidence rejected: %s", strings.TrimSpace(string(respBody)))
		}
		return nil
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("ratls: client evidence rejected (%d): %s", status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// attestRoundTrip sends one attest message and returns the status and body.
func (c *Client) attestRoundTrip(body []byte) (int, []byte, error) {
	if c.framing == FramingRaw {
		if err := writeFrame(c.conn, body); err != nil {
			return 0, nil, fmt.Errorf("ratls: attest frame: %w", err)
		}
		resp, err := readFrame(c.conn)
		if err != nil {
			return 0, nil, fmt.Errorf("ratls: attest frame: %w", err)
		}
		return http.StatusOK, resp, nil
	}
	host := c.hostHeader
	if host == "" {
		host = c.conn.RemoteAddr().String()
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+host+AttestPath, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	if err := req.Write(c.conn); err != nil {
		return 0, nil, fmt.Errorf("ratls: attest request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c.conn), req)
	if err != nil {
		return 0, nil, fmt.Errorf("ratls: attest response: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxFrame))
	if err != nil {
		return 0, nil, fmt.Errorf("ratls: attest response body: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := w.Write(frame)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Evidence returns the evidence obtained for this connection, nil in
// AttestationNone mode. It is verified only after VerifyCertificate returned
// without error.
func (c *Client) Evidence() *Evidence {
	return c.evidence
}

// AttestationMode returns the mode this connection was attested in.
func (c *Client) AttestationMode() AttestationMode {
	return c.mode
}

// Reattest repeats the evidence exchange with a fresh context and, when a
// policy was verified before, verifies the new evidence against it. Long-lived
// connections call it every few minutes and drop the connection on error.
func (c *Client) Reattest() error {
	if c.mode == AttestationNone {
		return fmt.Errorf("ratls: connection was opened with AttestationNone")
	}
	if c.framing == FramingRaw {
		return fmt.Errorf("ratls: re-attestation is not possible on the raw binding; reconnect instead")
	}
	if err := c.attest(c.mode); err != nil {
		return err
	}
	if c.lastPolicy != nil {
		_, err := c.VerifyCertificate(c.lastPolicy)
		return err
	}
	return nil
}
