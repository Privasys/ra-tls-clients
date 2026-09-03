// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"
)

func mustOID(s string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
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

// tdxQuoteWith returns a minimal raw TDX quote carrying reportData.
func tdxQuoteWith(reportData []byte) []byte {
	raw := make([]byte, TDXQuoteMinSize)
	raw[0], raw[1] = 4, 0
	copy(raw[TDXQuoteReportDataOff:TDXQuoteReportDataEnd], reportData)
	return raw
}

func spkiOf(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A leaf that carries a quote extension is a v1 leaf and is never accepted.
func TestInspectMarksV1Leaf(t *testing.T) {
	for _, oid := range []string{OidTDXQuote, OidSGXQuote} {
		cert := testCert(t, []pkix.Extension{{Id: mustOID(oid), Value: []byte("\x04\x00 evidence")}})
		info := InspectCertificate(cert)
		if !info.V1Leaf {
			t.Fatalf("extension %s must mark a v1 leaf", oid)
		}
		if _, err := VerifyCertificateExtensions(cert, &VerificationPolicy{}); err == nil {
			t.Fatalf("a v1 leaf (%s) must be rejected", oid)
		}
	}
	v2 := testCert(t, []pkix.Extension{{Id: mustOID(OidWorkloadAppID), Value: bytes.Repeat([]byte{1}, 16)}})
	info := InspectCertificate(v2)
	if info.V1Leaf || info.Quote != nil || len(info.CustomOids) != 1 || info.CustomOids[0].OID != OidWorkloadAppID {
		t.Fatalf("v2 leaf inspection wrong: %+v", info)
	}
}

// report_data recipes of docs/ratls-v2.md section 3.5.
func TestExpectedReportDataRecipes(t *testing.T) {
	cert := testCert(t, nil)
	spki := spkiOf(t, cert)
	pk := sha256.Sum256(spki)

	det := &Evidence{Mode: AttestationDeterministic, QuoteTimeRaw: "2026-09-04T10:15Z"}
	got, err := ExpectedReportData(spki, det)
	if err != nil {
		t.Fatal(err)
	}
	want := sha512.Sum512(append(append([]byte(nil), pk[:]...), []byte("2026-09-04T10:15Z")...))
	if !bytes.Equal(got, want[:]) {
		t.Fatal("deterministic recipe mismatch")
	}

	ctx := bytes.Repeat([]byte{0xC0}, ContextLen)
	hctx := bytes.Repeat([]byte{0xE1}, HctxLen)
	ch := &Evidence{Mode: AttestationChallenge, Context: ctx, Hctx: hctx}
	got, err = ExpectedReportData(spki, ch)
	if err != nil {
		t.Fatal(err)
	}
	pre := append(append(append([]byte(nil), pk[:]...), ctx...), hctx...)
	want = sha512.Sum512(pre)
	if !bytes.Equal(got, want[:]) {
		t.Fatal("challenge recipe mismatch")
	}

	gpu := []byte("PGAE\x01 gpu evidence envelope")
	gs := sha256.Sum256(gpu)
	ch.GPUEvidence = gpu
	got, err = ExpectedReportData(spki, ch)
	if err != nil {
		t.Fatal(err)
	}
	want = sha512.Sum512(append(pre, gs[:]...))
	if !bytes.Equal(got, want[:]) {
		t.Fatal("GPU fold must append SHA-256(gpu_evidence) after the binding")
	}

	// Malformed evidence never yields a value.
	if _, err := ExpectedReportData(spki, &Evidence{Mode: AttestationChallenge, Context: ctx[:31], Hctx: hctx}); err == nil {
		t.Fatal("short context must be rejected")
	}
	if _, err := ExpectedReportData(spki, &Evidence{Mode: AttestationDeterministic}); err == nil {
		t.Fatal("missing quote_time must be rejected")
	}
	if _, err := ExpectedReportData(spki, &Evidence{Mode: AttestationNone}); err == nil {
		t.Fatal("mode none has no report_data")
	}
}

// VerifyEvidence accepts a quote whose report_data it predicted and nothing else.
func TestVerifyEvidencePredictsReportData(t *testing.T) {
	cert := testCert(t, []pkix.Extension{{Id: mustOID(OidImageProfile), Value: []byte("production")}})
	spki := spkiOf(t, cert)
	ctx := bytes.Repeat([]byte{7}, ContextLen)
	hctx := bytes.Repeat([]byte{9}, HctxLen)
	ev := &Evidence{Mode: AttestationChallenge, TEE: "tdx", Context: ctx, Hctx: hctx, QuoteTimeRaw: "2026-09-04T10:15Z"}
	rd, _ := ExpectedReportData(spki, ev)
	ev.Quote = tdxQuoteWith(rd)

	info, err := VerifyEvidence(cert, ev, &VerificationPolicy{TEE: TeeTypeTDX})
	if err != nil {
		t.Fatalf("predicted report_data must verify: %v", err)
	}
	if info.Attestation != AttestationChallenge || info.Quote == nil || info.Evidence != ev {
		t.Fatalf("result not filled: %+v", info)
	}

	// A quote minted for another connection (other exporter value) fails.
	other := *ev
	other.Hctx = bytes.Repeat([]byte{10}, HctxLen)
	if _, err := VerifyEvidence(cert, &other, &VerificationPolicy{TEE: TeeTypeTDX}); err == nil {
		t.Fatal("evidence bound to another exporter value must be rejected")
	}
	// Wrong family against the policy.
	if _, err := VerifyEvidence(cert, ev, &VerificationPolicy{TEE: TeeTypeSGX}); err == nil {
		t.Fatal("tdx evidence must not satisfy an SGX policy")
	}
	// No evidence at all.
	if _, err := VerifyEvidence(cert, nil, &VerificationPolicy{TEE: TeeTypeTDX}); err == nil {
		t.Fatal("nil evidence must be rejected")
	}
	// tdx-gpu needs gpu_evidence.
	bad := *ev
	bad.TEE = "tdx-gpu"
	if _, err := VerifyEvidence(cert, &bad, &VerificationPolicy{TEE: TeeTypeTDX}); err == nil {
		t.Fatal("tdx-gpu without gpu_evidence must be rejected")
	}
	// Certificate extension policy still applies.
	dev := testCert(t, []pkix.Extension{{Id: mustOID(OidImageProfile), Value: []byte("dev")}})
	spkiDev := spkiOf(t, dev)
	evDev := &Evidence{Mode: AttestationChallenge, TEE: "tdx", Context: ctx, Hctx: hctx}
	rdDev, _ := ExpectedReportData(spkiDev, evDev)
	evDev.Quote = tdxQuoteWith(rdDev)
	if _, err := VerifyEvidence(dev, evDev, &VerificationPolicy{TEE: TeeTypeTDX}); err == nil {
		t.Fatal("dev image must be rejected without AllowDebugImages")
	}
	if _, err := VerifyEvidence(dev, evDev, &VerificationPolicy{TEE: TeeTypeTDX, AllowDebugImages: true}); err != nil {
		t.Fatalf("dev image allowed by policy: %v", err)
	}
}

func TestCheckQuoteTime(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	if _, err := CheckQuoteTime("2026-09-04T11:59Z", now); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckQuoteTime("2026-09-03T12:03Z", now); err != nil {
		t.Fatal("23h57m old is within 24h + skew")
	}
	if _, err := CheckQuoteTime("2026-09-03T11:50Z", now); err == nil {
		t.Fatal("older than 24h + 5m must be rejected")
	}
	if _, err := CheckQuoteTime("2026-09-04T12:06Z", now); err == nil {
		t.Fatal("more than 5m in the future must be rejected")
	}
	if _, err := CheckQuoteTime("2026-09-04T12:00:00Z", now); err == nil {
		t.Fatal("seconds are not part of the layout")
	}
}

func TestRawFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&buf)
	if err != nil || string(got) != `{"v":2}` {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if err := writeFrame(&buf, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized frame must be refused")
	}
}

func TestClientReportDataMatchesServerRecipe(t *testing.T) {
	cert := testCert(t, nil)
	spki := spkiOf(t, cert)
	ctx := bytes.Repeat([]byte{1}, ContextLen)
	hctx := bytes.Repeat([]byte{2}, HctxLen)
	ev := &Evidence{Mode: AttestationChallenge, Context: ctx, Hctx: hctx}
	want, _ := ExpectedReportData(spki, ev)
	if got := ClientReportData(spki, ctx, hctx, nil); !bytes.Equal(got, want) {
		t.Fatal("client and server challenge recipes must coincide")
	}
}
