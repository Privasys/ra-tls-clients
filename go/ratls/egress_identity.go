// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Mutual RA-TLS from inside an enclave-os-virtual container.
//
// A container never mints its own identity and cannot produce a TDX quote. The
// measured manager does both:
//
//   - POST /api/v1/egress-identity returns the container's client certificate
//     (leaf key, chain, app-id and code-digest OIDs, no evidence). The
//     certificate is cached here for its validity; it carries no per-session
//     value in v2.
//   - POST /api/v1/egress-evidence returns a quote whose report_data commits to
//     the certificate's key, the callee's client_context and this connection's
//     exporter value, computed by the container (only the two TLS ends can).
//     The manager checks that the key belongs to a certificate it issued to
//     this container before quoting.
//
// Usage:
//
//	id := ratls.NewEgressIdentity(mgrURL, token)
//	client, err := ratls.Connect(host, port, &ratls.Options{
//	    ServerName:           calleeHostname,
//	    GetClientCertificate: id.GetClientCertificate,
//	    ClientEvidence:       id.ClientEvidence,
//	})

// EgressIdentity holds a container's manager-minted client certificate and
// produces its client evidence on demand.
type EgressIdentity struct {
	managerURL string
	token      string
	http       *http.Client

	mu       sync.Mutex
	cert     *tls.Certificate
	notAfter time.Time
}

// NewEgressIdentity returns an identity backed by the in-container manager at
// managerURL (PRIVASYS_MANAGER_URL) authenticated with the per-container
// bearer containerToken (PRIVASYS_CONTAINER_TOKEN).
func NewEgressIdentity(managerURL, containerToken string) *EgressIdentity {
	return &EgressIdentity{
		managerURL: managerURL,
		token:      containerToken,
		http:       &http.Client{Timeout: 5 * time.Second},
	}
}

// GetClientCertificate is the tls.Config callback: it returns the cached
// certificate or fetches a new one from the manager.
func (e *EgressIdentity) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cert != nil && time.Now().Add(time.Minute).Before(e.notAfter) {
		return e.cert, nil
	}
	cert, err := e.fetchCertificate()
	if err != nil {
		return nil, err
	}
	leaf, err := parseLeaf(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("ratls: egress identity: %w", err)
	}
	e.cert, e.notAfter = cert, leaf.NotAfter
	return cert, nil
}

func (e *EgressIdentity) fetchCertificate() (*tls.Certificate, error) {
	raw, err := e.post("/api/v1/egress-identity", map[string]any{"v": ProtocolVersion})
	if err != nil {
		return nil, err
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ratls: parse egress-identity response: %w", err)
	}
	cert, err := tls.X509KeyPair([]byte(out.CertPEM), []byte(out.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("ratls: assemble egress client certificate: %w", err)
	}
	return &cert, nil
}

// ClientEvidence is the ClientEvidenceSource: it asks the manager for a quote
// over the report_data this connection needs.
func (e *EgressIdentity) ClientEvidence(req ClientEvidenceRequest) (*ClientEvidence, error) {
	spkiHash := sha256.Sum256(req.SPKIDER)
	raw, err := e.post("/api/v1/egress-evidence", map[string]any{
		"v":           ProtocolVersion,
		"spki_sha256": base64.RawURLEncoding.EncodeToString(spkiHash[:]),
		"context":     base64.RawURLEncoding.EncodeToString(req.Context),
		"hctx":        base64.RawURLEncoding.EncodeToString(req.Hctx),
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		TEE         string  `json:"tee"`
		Quote       string  `json:"quote"`
		GPUEvidence *string `json:"gpu_evidence"`
		QuoteTime   string  `json:"quote_time"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ratls: parse egress-evidence response: %w", err)
	}
	ce := &ClientEvidence{TEE: out.TEE, QuoteTime: out.QuoteTime}
	if ce.Quote, err = b64Decode(out.Quote); err != nil {
		return nil, fmt.Errorf("ratls: egress-evidence quote is not base64url")
	}
	if out.GPUEvidence != nil && *out.GPUEvidence != "" {
		if ce.GPUEvidence, err = b64Decode(*out.GPUEvidence); err != nil {
			return nil, fmt.Errorf("ratls: egress-evidence gpu_evidence is not base64url")
		}
	}
	return ce, nil
}

func (e *EgressIdentity) post(path string, body any) ([]byte, error) {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, e.managerURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("ratls: build %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ratls: call %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ratls: %s returned %d: %s", path, resp.StatusCode, string(raw))
	}
	return raw, nil
}
