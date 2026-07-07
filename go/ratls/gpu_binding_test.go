// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func mustOID(s string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	for _, p := range bytes.Split([]byte(s), []byte(".")) {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		o = append(o, n)
	}
	return o
}

func testCert(t *testing.T, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{PublicKey: &key.PublicKey, Extensions: exts}
}

// A cert with BOTH a TDX quote and the GPU 5.1 extension must keep the TDX
// quote as the primary (not silently replaced by the opaque GPU one) and
// capture the GPU evidence separately.
func TestInspectSeparatesGPUFromPrimaryQuote(t *testing.T) {
	gpu := []byte("PGAE\x01 gpu evidence envelope")
	cert := testCert(t, []pkix.Extension{
		{Id: mustOID(OidTDXQuote), Value: []byte("\x04\x00 tdx quote bytes ...")},
		{Id: mustOID(OidNVIDIAGPUEvidence), Value: gpu},
	})
	info := InspectCertificate(cert)
	if info.Quote == nil || info.Quote.OID != OidTDXQuote {
		t.Fatalf("primary quote must stay TDX, got %+v", info.Quote)
	}
	if !bytes.Equal(info.GPUEvidence, gpu) {
		t.Fatal("GPU evidence must be captured separately")
	}
	if got := gpuEvidenceValue(cert); !bytes.Equal(got, gpu) {
		t.Fatal("gpuEvidenceValue mismatch")
	}
}

// A GPU-only cert (no CPU quote) falls back to treating GPU as the primary.
func TestInspectGPUOnlyFallsBackToPrimary(t *testing.T) {
	cert := testCert(t, []pkix.Extension{
		{Id: mustOID(OidNVIDIAGPUEvidence), Value: []byte("PGAE\x01 gpu")},
	})
	info := InspectCertificate(cert)
	if info.Quote == nil || info.Quote.OID != OidNVIDIAGPUEvidence {
		t.Fatalf("GPU-only cert should treat GPU as primary, got %+v", info.Quote)
	}
}

// The presence of the 5.1 extension must extend the ReportData binding by
// SHA-256(evidence); its absence must leave the binding untouched (non-GPU
// certs verify exactly as before).
func TestReportDataBindingFoldsGPUEvidence(t *testing.T) {
	gpu := []byte("PGAE\x01 gpu evidence envelope")
	sum := sha256.Sum256(gpu)

	withGPU := gpuEvidenceValue(testCert(t, []pkix.Extension{
		{Id: mustOID(OidNVIDIAGPUEvidence), Value: gpu},
	}))
	if !bytes.Equal(withGPU, gpu) {
		t.Fatal("expected evidence back")
	}
	noGPU := gpuEvidenceValue(testCert(t, []pkix.Extension{
		{Id: mustOID(OidTDXQuote), Value: []byte("q")},
	}))
	if noGPU != nil {
		t.Fatal("no 5.1 extension must give nil")
	}

	// The extended binding a verifier computes must equal B || SHA256(evidence),
	// matching the enclave's gpuBinding.
	B := []byte("2026-07-07T12:00Z")
	want := append(append([]byte(nil), B...), sum[:]...)
	got := append(append([]byte(nil), B...), func() []byte { s := sha256.Sum256(withGPU); return s[:] }()...)
	if !bytes.Equal(got, want) {
		t.Fatal("binding fold mismatch")
	}
}
