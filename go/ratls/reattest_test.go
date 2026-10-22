// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// reattestServer is a loopback RA-TLS server whose first evidence exchange
// succeeds and every later one fails. It records each request path.
type reattestServer struct {
	port   int
	caPath string
	mu     sync.Mutex
	paths  []string
	calls  int
}

func (s *reattestServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

func startReattestServer(t *testing.T) *reattestServer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test anchor"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "enclave.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "anchor.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &reattestServer{caPath: caPath}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.Path)
		if r.URL.Path == AttestPath {
			s.calls++
		}
		first := s.calls == 1
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != AttestPath {
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if !first {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"v":2,"error":"evidence unavailable"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"v": ProtocolVersion, "mode": "deterministic", "tee": "tdx",
			"quote":      b64.EncodeToString(tdxQuoteWith(make([]byte, 64))),
			"quote_time": time.Now().UTC().Format(QuoteTimeLayout), "client_evidence": "none",
		})
	})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	s.port = ln.Addr().(*net.TCPAddr).Port
	return s
}

// A re-attestation that fails closes the connection, as Connect does: a
// caller that ignores the error and carries on sends nothing.
func TestFailedReattestClosesTheConnection(t *testing.T) {
	srv := startReattestServer(t)
	c, err := Connect("127.0.0.1", srv.port, &Options{
		CACertPath: srv.caPath, ServerName: "enclave.test", Attestation: AttestationDeterministic,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if err := c.Reattest(); err == nil {
		t.Fatal("re-attestation succeeded against failing evidence")
	}
	if _, err := c.HTTPDo("POST", "/after-failure", "enclave.test", []byte("must not be sent"), ""); err == nil {
		t.Fatal("a request went out after a failed re-attestation")
	}
	for _, p := range srv.seen() {
		if p == "/after-failure" {
			t.Fatalf("the server received %s after the failed re-attestation", p)
		}
	}
}
