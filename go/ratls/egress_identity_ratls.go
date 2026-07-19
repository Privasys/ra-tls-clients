// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//go:build ratls

// This file is compiled only with the Privasys/go fork, which surfaces
// tls.CertificateRequestInfo.RATLSChannelBinder — the per-session channel binder
// a mutual-RA-TLS caller folds into its client certificate.
//
// Build with:
//   GOROOT=~/go-ratls go build -tags ratls

package ratls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// EgressClientCert returns the (challenge, GetClientCertificate) pair to set on
// Options for an app-to-app mutual-RA-TLS call from inside an enclave-os-virtual
// container.
//
//   - challenge is a fresh 32-byte nonce sent in the ClientHello (extension
//     0xFFBB). It puts the callee into bidirectional mode so its TLS 1.3 server
//     derives this session's channel binder; without it the callee never binds
//     the session and the caller cannot prove freshness.
//   - getCert is a GetClientCertificate callback: when the callee requests a
//     client certificate it hands the caller this session's channel binder
//     (CertificateRequestInfo.RATLSChannelBinder), which the callback forwards
//     to the local manager's POST /api/v1/egress-identity. The measured manager
//     mints the container's attested identity (TDX quote + image digest OID 3.2
//     + app-id OID 3.6) with report_data folding the binder, so the callee's
//     verification is bound to this exact session and a relayed certificate
//     fails closed. The app never mints its own identity.
//
// managerURL is the in-container manager base URL (PRIVASYS_MANAGER_URL) and
// containerToken is the per-container bearer (PRIVASYS_CONTAINER_TOKEN).
//
// Usage:
//
//	ch, getCert, err := ratls.EgressClientCert(mgrURL, token)
//	client, err := ratls.Connect(host, port, &ratls.Options{
//	    ServerName:           calleeHostname,
//	    Challenge:            ch,
//	    GetClientCertificate: getCert,
//	    CACertPath:           caPath, // callee's chain, if pinned
//	})
func EgressClientCert(managerURL, containerToken string) (challenge []byte, getCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error), err error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("ratls: generate egress challenge: %w", err)
	}
	get := func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if len(info.RATLSChannelBinder) == 0 {
			return nil, fmt.Errorf("ratls: no channel binder in CertificateRequest " +
				"(the callee did not drive RA-TLS mutual binding; is Options.Challenge set " +
				"and the callee mutual-RA-TLS enabled?)")
		}
		cert, err := mintEgressIdentity(managerURL, containerToken, info.RATLSChannelBinder)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}
	return nonce, get, nil
}

// mintEgressIdentity asks the local manager to mint the container's attested
// client identity bound to this session's channel binder.
func mintEgressIdentity(managerURL, token string, binder []byte) (*tls.Certificate, error) {
	body, _ := json.Marshal(map[string]string{
		"binder_b64": base64.StdEncoding.EncodeToString(binder),
	})
	req, err := http.NewRequest(http.MethodPost,
		managerURL+"/api/v1/egress-identity", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ratls: build egress-identity request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ratls: call egress-identity: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ratls: egress-identity returned %d: %s", resp.StatusCode, string(raw))
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
