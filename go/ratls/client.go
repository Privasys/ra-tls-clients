// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Package ratls provides an RA-TLS client connector for enclave-os-mini.
//
// Features:
//   - TLS connection with optional CA certificate verification
//   - RA-TLS certificate inspection (SGX / TDX quote extraction)
//   - Length-delimited framing (4-byte big-endian prefix)
//   - Typed request/response helpers matching the Rust protocol
//
// Usage:
//
//	client, _ := ratls.Connect("141.94.219.130", 443, &ratls.Options{CACertPath: "ca.pem"})
//	defer client.Close()
//	info := client.InspectCertificate()
//	resp, _ := client.SendData([]byte("hello"))
package ratls

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
//  RA-TLS OIDs
// ---------------------------------------------------------------------------

const (
	// OidSGXQuote is the OID for Intel SGX quotes (enclave-os-mini).
	OidSGXQuote = "1.2.840.113741.1.13.1.0"
	// OidTDXQuote is the OID for Intel TDX quotes (ra-tls-caddy).
	OidTDXQuote = "1.2.840.113741.1.5.5.1.6"

	// Privasys configuration OIDs (PEN 1337)

	// OidConfigMerkleRoot proves all config inputs.
	OidConfigMerkleRoot = "1.3.6.1.4.1.1337.1.1"
	// OidEgressCAHash proves the outbound trust anchors.
	OidEgressCAHash = "1.3.6.1.4.1.1337.2.1"
	// OidWasmAppsHash proves the application code.
	OidWasmAppsHash = "1.3.6.1.4.1.1337.2.3"
)

// privasysOIDs is the set of Privasys configuration OIDs.
var privasysOIDs = map[string]bool{
	OidConfigMerkleRoot: true,
	OidEgressCAHash:     true,
	OidWasmAppsHash:     true,
}

// OidLabel returns a human-readable label for a known RA-TLS OID.
func OidLabel(oid string) string {
	switch oid {
	case OidSGXQuote:
		return "SGX Quote"
	case OidTDXQuote:
		return "TDX Quote"
	case OidConfigMerkleRoot:
		return "Config Merkle Root"
	case OidEgressCAHash:
		return "Egress CA Hash"
	case OidWasmAppsHash:
		return "WASM Apps Hash"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
//  DCAP quote byte-offset constants
// ---------------------------------------------------------------------------

// SGX DCAP Quote v3: QuoteHeader(48) + ReportBody(384).
const (
	SGXQuoteMinSize       = 432
	SGXQuoteMRENCLAVEOff  = 112
	SGXQuoteMRENCLAVEEnd  = 144
	SGXQuoteMRSIGNEROff   = 176
	SGXQuoteMRSIGNEREnd   = 208
	SGXQuoteReportDataOff = 368
	SGXQuoteReportDataEnd = 432
)

// TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584).
const (
	TDXQuoteMinSize       = 632
	TDXQuoteMRTDOff       = 184
	TDXQuoteMRTDEnd       = 232
	TDXQuoteReportDataOff = 568
	TDXQuoteReportDataEnd = 632
)

// ---------------------------------------------------------------------------
//  RA-TLS verification types
// ---------------------------------------------------------------------------

// TeeType is the target TEE type for RA-TLS verification.
type TeeType int

const (
	// TeeTypeSGX targets Intel SGX enclaves.
	TeeTypeSGX TeeType = iota
	// TeeTypeTDX targets Intel TDX VMs.
	TeeTypeTDX
)

// ReportDataMode controls how the verifier reproduces the quote's ReportData.
type ReportDataMode int

const (
	// ReportDataSkip does not verify ReportData.
	ReportDataSkip ReportDataMode = iota
	// ReportDataDeterministic reproduces ReportData from the certificate alone.
	ReportDataDeterministic
	// ReportDataChallengeResponse uses a client-supplied nonce.
	ReportDataChallengeResponse
)

// ExpectedOid is an expected X.509 extension OID and its value.
type ExpectedOid struct {
	OID           string
	ExpectedValue []byte
}

// VerificationPolicy configures RA-TLS certificate verification.
type VerificationPolicy struct {
	// TEE is the expected TEE type.
	TEE TeeType
	// MRENCLAVE is the expected SGX MRENCLAVE (32 bytes). Nil to skip.
	MRENCLAVE []byte
	// MRSIGNER is the expected SGX MRSIGNER (32 bytes). Nil to skip.
	MRSIGNER []byte
	// MRTD is the expected TDX MRTD (48 bytes). Nil to skip.
	MRTD []byte
	// ReportData controls how ReportData is verified.
	ReportData ReportDataMode
	// Nonce is the client-supplied nonce for ChallengeResponse mode.
	Nonce []byte
	// ExpectedOids are custom OID values to verify.
	ExpectedOids []ExpectedOid
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

// QuoteInfo contains parsed attestation quote data from the certificate.
type QuoteInfo struct {
	OID        string
	Label      string
	Critical   bool
	Raw        []byte
	IsMock     bool
	Version    *uint16
	ReportData []byte
}

// OidExtension is a custom X.509 extension (e.g. Privasys configuration OID).
type OidExtension struct {
	OID   string
	Label string
	Value []byte
}

// CertInfo contains a summary of the server's RA-TLS certificate.
type CertInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	SigAlgo      string
	PubKeySHA256 string
	Extensions   []string
	Quote        *QuoteInfo
	// CustomOids holds Privasys configuration OIDs found in the certificate.
	CustomOids []OidExtension
}

// InspectCertificate inspects an X.509 certificate for RA-TLS extensions.
func InspectCertificate(cert *x509.Certificate) CertInfo {
	pubDER, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	h := sha256.Sum256(pubDER)

	info := CertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SigAlgo:      cert.SignatureAlgorithm.String(),
		PubKeySHA256: hex.EncodeToString(h[:]),
	}

	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		info.Extensions = append(info.Extensions, oidStr)

		if oidStr == OidSGXQuote || oidStr == OidTDXQuote {
			info.Quote = parseQuote(oidStr, ext.Critical, ext.Value)
		} else if privasysOIDs[oidStr] {
			info.CustomOids = append(info.CustomOids, OidExtension{
				OID:   oidStr,
				Label: OidLabel(oidStr),
				Value: ext.Value,
			})
		}
	}

	return info
}

func parseQuote(oid string, critical bool, raw []byte) *QuoteInfo {
	q := &QuoteInfo{
		OID:      oid,
		Label:    OidLabel(oid),
		Critical: critical,
		Raw:      raw,
	}

	if len(raw) >= 11 && string(raw[:11]) == "MOCK_QUOTE:" {
		q.IsMock = true
		end := len(raw)
		if end > 75 {
			end = 75
		}
		q.ReportData = raw[11:end]
	} else if oid == OidSGXQuote && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
		if len(raw) >= 432 {
			q.ReportData = raw[368:432]
		}
	} else if oid == OidTDXQuote && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
		if len(raw) >= TDXQuoteMinSize {
			q.ReportData = raw[TDXQuoteReportDataOff:TDXQuoteReportDataEnd]
		}
	}

	return q
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

// VerifyRaTlsCert verifies an X.509 certificate against a VerificationPolicy.
// Returns the CertInfo on success or an error describing the first failure.
func VerifyRaTlsCert(cert *x509.Certificate, policy *VerificationPolicy) (CertInfo, error) {
	info := InspectCertificate(cert)

	// 1. Quote must be present
	if info.Quote == nil {
		return info, fmt.Errorf("no RA-TLS attestation quote in certificate")
	}
	if info.Quote.IsMock {
		return info, fmt.Errorf("certificate contains a MOCK quote")
	}

	// 2. Correct TEE type
	switch policy.TEE {
	case TeeTypeSGX:
		if info.Quote.OID != OidSGXQuote {
			return info, fmt.Errorf("expected SGX quote (%s), found %s", OidSGXQuote, info.Quote.OID)
		}
	case TeeTypeTDX:
		if info.Quote.OID != OidTDXQuote {
			return info, fmt.Errorf("expected TDX quote (%s), found %s", OidTDXQuote, info.Quote.OID)
		}
	}

	// 3. Measurement registers
	if err := verifyMeasurements(info.Quote.Raw, policy); err != nil {
		return info, err
	}

	// 4. ReportData
	if err := verifyReportData(cert, info.Quote.Raw, policy); err != nil {
		return info, err
	}

	// 5. Custom OID values
	if err := verifyExpectedOids(info.CustomOids, policy.ExpectedOids); err != nil {
		return info, err
	}

	return info, nil
}

func verifyMeasurements(raw []byte, policy *VerificationPolicy) error {
	switch policy.TEE {
	case TeeTypeSGX:
		if len(raw) < SGXQuoteMinSize {
			return fmt.Errorf("SGX quote too small: %d < %d", len(raw), SGXQuoteMinSize)
		}
		if policy.MRENCLAVE != nil {
			actual := raw[SGXQuoteMRENCLAVEOff:SGXQuoteMRENCLAVEEnd]
			if !bytesEqual(actual, policy.MRENCLAVE) {
				return fmt.Errorf("MRENCLAVE mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.MRENCLAVE))
			}
		}
		if policy.MRSIGNER != nil {
			actual := raw[SGXQuoteMRSIGNEROff:SGXQuoteMRSIGNEREnd]
			if !bytesEqual(actual, policy.MRSIGNER) {
				return fmt.Errorf("MRSIGNER mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.MRSIGNER))
			}
		}
	case TeeTypeTDX:
		if len(raw) < TDXQuoteMinSize {
			return fmt.Errorf("TDX quote too small: %d < %d", len(raw), TDXQuoteMinSize)
		}
		if policy.MRTD != nil {
			actual := raw[TDXQuoteMRTDOff:TDXQuoteMRTDEnd]
			if !bytesEqual(actual, policy.MRTD) {
				return fmt.Errorf("MRTD mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.MRTD))
			}
		}
	}
	return nil
}

func verifyReportData(cert *x509.Certificate, raw []byte, policy *VerificationPolicy) error {
	var binding []byte

	switch policy.ReportData {
	case ReportDataSkip:
		return nil
	case ReportDataDeterministic:
		if policy.TEE == TeeTypeSGX {
			// Deterministic mode is not applicable for SGX.
			return nil
		}
		// TDX: binding is NotBefore formatted as "YYYY-MM-DDTHH:MMZ"
		nb := cert.NotBefore.UTC()
		binding = []byte(fmt.Sprintf("%04d-%02d-%02dT%02d:%02dZ",
			nb.Year(), nb.Month(), nb.Day(), nb.Hour(), nb.Minute()))
	case ReportDataChallengeResponse:
		binding = policy.Nonce
	}

	// Build the pubkey input
	var pubkeyInput []byte
	switch policy.TEE {
	case TeeTypeSGX:
		// SGX: raw EC point (65 bytes from SPKI)
		pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		// Extract raw EC point from SPKI (last 65 bytes for P-256 uncompressed)
		if len(pubDER) >= 65 {
			pubkeyInput = pubDER[len(pubDER)-65:]
		} else {
			pubkeyInput = pubDER
		}
	case TeeTypeTDX:
		// TDX: full SPKI DER
		pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		pubkeyInput = pubDER
	}

	expected := computeReportDataHash(pubkeyInput, binding)

	// Get actual ReportData
	var actual []byte
	switch policy.TEE {
	case TeeTypeSGX:
		if len(raw) < SGXQuoteReportDataEnd {
			return fmt.Errorf("quote too small to contain ReportData")
		}
		actual = raw[SGXQuoteReportDataOff:SGXQuoteReportDataEnd]
	case TeeTypeTDX:
		if len(raw) < TDXQuoteReportDataEnd {
			return fmt.Errorf("quote too small to contain ReportData")
		}
		actual = raw[TDXQuoteReportDataOff:TDXQuoteReportDataEnd]
	}

	if !bytesEqual(actual, expected) {
		return fmt.Errorf("ReportData mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(actual), hex.EncodeToString(expected))
	}
	return nil
}

func verifyExpectedOids(actual []OidExtension, expected []ExpectedOid) error {
	for _, exp := range expected {
		var found *OidExtension
		for i := range actual {
			if actual[i].OID == exp.OID {
				found = &actual[i]
				break
			}
		}
		if found == nil {
			return fmt.Errorf("expected OID %s (%s) not found in certificate",
				exp.OID, OidLabel(exp.OID))
		}
		if !bytesEqual(found.Value, exp.ExpectedValue) {
			return fmt.Errorf("%s (%s) mismatch: got %s, expected %s",
				OidLabel(exp.OID), exp.OID,
				hex.EncodeToString(found.Value), hex.EncodeToString(exp.ExpectedValue))
		}
	}
	return nil
}

// computeReportDataHash computes SHA-512( SHA-256(pubkey) || binding ).
func computeReportDataHash(pubkeyInput, binding []byte) []byte {
	pkHash := sha256.Sum256(pubkeyInput)
	buf := make([]byte, 0, 32+len(binding))
	buf = append(buf, pkHash[:]...)
	buf = append(buf, binding...)
	h := sha512.Sum512(buf)
	return h[:]
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyCertificate verifies the server's leaf certificate against a policy.
func (c *Client) VerifyCertificate(policy *VerificationPolicy) (CertInfo, error) {
	if len(c.peerCerts) == 0 {
		return CertInfo{}, fmt.Errorf("no peer certificate")
	}
	return VerifyRaTlsCert(c.peerCerts[0], policy)
}

// ---------------------------------------------------------------------------
//  Framing
// ---------------------------------------------------------------------------

func encodeFrame(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func decodeFrame(buf []byte) (payload []byte, consumed int, ok bool) {
	if len(buf) < 4 {
		return nil, 0, false
	}
	length := int(binary.BigEndian.Uint32(buf[:4]))
	if len(buf) < 4+length {
		return nil, 0, false
	}
	return buf[4 : 4+length], 4 + length, true
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

// Options configures the RA-TLS client connection.
type Options struct {
	// CACertPath is the path to a PEM CA certificate for chain verification.
	// If empty, certificate verification is disabled (dev mode).
	CACertPath string
	// Timeout is the connection/read timeout (default: 10s).
	Timeout time.Duration
}

// Client is an RA-TLS client for enclave-os-mini.
type Client struct {
	conn      *tls.Conn
	peerCerts []*x509.Certificate
}

// Connect establishes a TLS connection to the server.
func Connect(host string, port int, opts *Options) (*Client, error) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{}

	if opts.CACertPath != "" {
		caPEM, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		block, _ := pem.Decode(caPEM)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in CA cert file")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA cert: %w", err)
		}
		pool.AddCert(caCert)
		tlsConfig.RootCAs = pool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connect: %w", err)
	}

	return &Client{
		conn:      conn,
		peerCerts: conn.ConnectionState().PeerCertificates,
	}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// TLSVersion returns the negotiated TLS version string.
func (c *Client) TLSVersion() string {
	state := c.conn.ConnectionState()
	switch state.Version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return fmt.Sprintf("0x%04x", state.Version)
	}
}

// CipherSuite returns the negotiated cipher suite name.
func (c *Client) CipherSuite() string {
	return tls.CipherSuiteName(c.conn.ConnectionState().CipherSuite)
}

// InspectCert returns RA-TLS certificate info for the server's leaf cert.
func (c *Client) InspectCert() CertInfo {
	if len(c.peerCerts) == 0 {
		return CertInfo{}
	}
	return InspectCertificate(c.peerCerts[0])
}

// -- Protocol -------------------------------------------------------------

func (c *Client) sendFrame(payload []byte) error {
	_, err := c.conn.Write(encodeFrame(payload))
	return err
}

func (c *Client) recvFrame() ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if payload, _, ok := decodeFrame(buf); ok {
				return payload, nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("connection closed before frame received")
			}
			return nil, err
		}
	}
}

// Ping sends a Ping request and expects Pong.
func (c *Client) Ping() (bool, error) {
	payload, _ := json.Marshal("Ping")
	if err := c.sendFrame(payload); err != nil {
		return false, err
	}
	resp, err := c.recvFrame()
	if err != nil {
		return false, err
	}
	var s string
	if err := json.Unmarshal(resp, &s); err != nil {
		return false, err
	}
	return s == "Pong", nil
}

// SendData sends Data(payload) and returns the response bytes.
func (c *Client) SendData(data []byte) ([]byte, error) {
	ints := make([]int, len(data))
	for i, b := range data {
		ints[i] = int(b)
	}
	req := map[string]interface{}{"Data": ints}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := c.sendFrame(payload); err != nil {
		return nil, err
	}

	resp, err := c.recvFrame()
	if err != nil {
		return nil, err
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(resp, &m); err != nil {
		return nil, err
	}

	if d, ok := m["Data"]; ok {
		var nums []int
		if err := json.Unmarshal(d, &nums); err != nil {
			return nil, err
		}
		result := make([]byte, len(nums))
		for i, n := range nums {
			result[i] = byte(n)
		}
		return result, nil
	}
	if e, ok := m["Error"]; ok {
		var nums []int
		if err := json.Unmarshal(e, &nums); err != nil {
			return nil, fmt.Errorf("error response: %s", string(e))
		}
		errBytes := make([]byte, len(nums))
		for i, n := range nums {
			errBytes[i] = byte(n)
		}
		return nil, fmt.Errorf("server error: %s", string(errBytes))
	}
	return nil, fmt.Errorf("unexpected response: %s", string(resp))
}

// ---------------------------------------------------------------------------
//  Pretty-print
// ---------------------------------------------------------------------------

// PrintCertInfo prints certificate and quote info to stdout.
func PrintCertInfo(info CertInfo) {
	fmt.Printf("  Subject      : %s\n", info.Subject)
	fmt.Printf("  Issuer       : %s\n", info.Issuer)
	fmt.Printf("  Serial       : %s\n", info.SerialNumber)
	fmt.Printf("  Not Before   : %s\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After    : %s\n", info.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Sig Algo     : %s\n", info.SigAlgo)
	fmt.Printf("  PubKey SHA256: %s\n", info.PubKeySHA256)

	if info.Quote != nil {
		q := info.Quote
		fmt.Println()
		fmt.Println("  ** RA-TLS Extension found! **")
		fmt.Printf("    OID       : %s  (%s)\n", q.OID, q.Label)
		fmt.Printf("    Critical  : %v\n", q.Critical)
		fmt.Printf("    Size      : %d bytes\n", len(q.Raw))
		if q.IsMock {
			fmt.Println("    ** MOCK QUOTE **")
		}
		if q.Version != nil {
			fmt.Printf("    Version   : %d\n", *q.Version)
		}
		if q.ReportData != nil {
			fmt.Printf("    ReportData: %s\n", hex.EncodeToString(q.ReportData))
		}

		// Display measurement registers
		if q.OID == OidSGXQuote && len(q.Raw) >= SGXQuoteMinSize {
			fmt.Printf("    MRENCLAVE : %s\n", hex.EncodeToString(q.Raw[SGXQuoteMRENCLAVEOff:SGXQuoteMRENCLAVEEnd]))
			fmt.Printf("    MRSIGNER  : %s\n", hex.EncodeToString(q.Raw[SGXQuoteMRSIGNEROff:SGXQuoteMRSIGNEREnd]))
		} else if q.OID == OidTDXQuote && len(q.Raw) >= TDXQuoteMinSize {
			fmt.Printf("    MRTD      : %s\n", hex.EncodeToString(q.Raw[TDXQuoteMRTDOff:TDXQuoteMRTDEnd]))
		}

		previewLen := 32
		if len(q.Raw) < previewLen {
			previewLen = len(q.Raw)
		}
		fmt.Printf("    Preview   : %s...\n", hex.EncodeToString(q.Raw[:previewLen]))
	} else {
		fmt.Println()
		fmt.Println("  No RA-TLS extension found.")
	}

	if len(info.CustomOids) > 0 {
		fmt.Println()
		fmt.Println("  ** Privasys Configuration OIDs **")
		for _, ext := range info.CustomOids {
			fmt.Printf("    %s (%s): %s\n", ext.Label, ext.OID, hex.EncodeToString(ext.Value))
		}
	}
}
