// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPIID = "c055fc7b49bd4185dda796bf1795af32"

func TestPlatformIDPrecedence(t *testing.T) {
	r := &QuoteVerificationResult{PPID: "aa", PlatformInstanceID: testPIID, ChipID: "cc"}
	if r.PlatformID() != testPIID {
		t.Errorf("Platform Instance ID first, got %s", r.PlatformID())
	}
	r.PlatformInstanceID = ""
	if r.PlatformID() != "aa" {
		t.Errorf("PPID next, got %s", r.PlatformID())
	}
	r.PPID = ""
	if r.PlatformID() != "cc" {
		t.Errorf("CHIP_ID last, got %s", r.PlatformID())
	}
	var nilResult *QuoteVerificationResult
	if nilResult.PlatformID() != "" {
		t.Error("nil result has no identity")
	}
}

func TestPlatformAllowed(t *testing.T) {
	r := &QuoteVerificationResult{PPID: "414afbe506e8ac361add41f3133aab6f", PlatformInstanceID: testPIID}
	if err := platformAllowed(r, nil); err != nil {
		t.Errorf("empty list allows: %v", err)
	}
	for _, ok := range []string{testPIID, strings.ToUpper(testPIID), "c055fc7b-49bd-4185-dda7-96bf1795af32"} {
		if err := platformAllowed(r, []string{"deadbeef", ok}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if err := platformAllowed(r, []string{r.PPID}); err == nil {
		t.Error("the PPID does not stand in for a reported Platform Instance ID")
	}
	if err := platformAllowed(&QuoteVerificationResult{}, []string{testPIID}); err == nil || !strings.Contains(err.Error(), "no platform identity") {
		t.Errorf("no identity must fail closed: %v", err)
	}
}

// fakeAttestationServer answers like the Privasys attestation server: records
// the request, reports a platform identity, and enforces the request's
// allow-list with PLATFORM_NOT_ALLOWED.
func fakeAttestationServer(t *testing.T, platform map[string]string) (*httptest.Server, *map[string]interface{}) {
	t.Helper()
	var last map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		last = map[string]interface{}{}
		_ = json.Unmarshal(body, &last)
		resp := map[string]interface{}{"success": true, "status": "OK", "teeType": "tdx", "tcbStatus": "UpToDate"}
		if platform != nil {
			resp["platform"] = platform
		}
		// An older server (no platform identity) ignores the list; a current one enforces it.
		if allowed, ok := last["allowedPlatformIds"].([]interface{}); ok && len(allowed) > 0 && platform != nil {
			found := false
			for _, a := range allowed {
				if strings.EqualFold(a.(string), platform["platformInstanceId"]) {
					found = true
				}
			}
			if !found {
				resp["success"], resp["status"], resp["error"] = false, "PLATFORM_NOT_ALLOWED", "platform not in the allow-list"
			}
		}
		if last["type"] == "tdx-gpu" {
			resp["gpuAttestation"] = map[string]interface{}{"verified": true, "status": "OK"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return srv, &last
}

func TestVerifyQuoteReportsAndEnforcesThePlatform(t *testing.T) {
	platform := map[string]string{"ppid": "414afbe506e8ac361add41f3133aab6f", "platformInstanceId": testPIID, "fmspc": "00806f050000"}
	srv, last := fakeAttestationServer(t, platform)
	defer srv.Close()
	config := &QuoteVerificationConfig{Endpoint: srv.URL}
	quote := []byte("quote-bytes")

	// No list: the identity is reported, nothing enforced.
	r, err := verifyQuote(quote, config, nil, "tdx")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.PlatformID() != testPIID || r.FMSPC != "00806f050000" || r.PPID != platform["ppid"] {
		t.Errorf("platform not parsed: %+v", r)
	}
	if _, sent := (*last)["allowedPlatformIds"]; sent {
		t.Error("an empty list must not be sent")
	}

	// The list is sent and the platform is on it.
	if _, err := verifyQuote(quote, config, []string{"0000", strings.ToUpper(testPIID)}, "tdx"); err != nil {
		t.Errorf("allowed platform: %v", err)
	}
	if sent, _ := (*last)["allowedPlatformIds"].([]interface{}); len(sent) != 2 {
		t.Errorf("allow-list not sent: %v", (*last)["allowedPlatformIds"])
	}

	// Not on the list: the server refuses and the client agrees.
	if _, err := verifyQuote(quote, config, []string{"0000"}, "tdx"); err == nil || !strings.Contains(err.Error(), "PLATFORM_NOT_ALLOWED") {
		t.Errorf("want the server's refusal, got %v", err)
	}
	// tdx-gpu path: same behaviour.
	if r, _, err := verifyTDXGPU(quote, []byte("gpu"), config, []string{testPIID}, "tdx-gpu"); err != nil || r.PlatformID() != testPIID {
		t.Errorf("tdx-gpu: %v %+v", err, r)
	}
	if _, _, err := verifyTDXGPU(quote, []byte("gpu"), config, []string{"0000"}, "tdx-gpu"); err == nil {
		t.Error("tdx-gpu: platform off the list must fail")
	}
}

func TestVerifyQuoteFailsClosedOnAServerWithoutPlatformIdentity(t *testing.T) {
	srv, _ := fakeAttestationServer(t, nil) // an older server: no "platform" object, list ignored
	defer srv.Close()
	config := &QuoteVerificationConfig{Endpoint: srv.URL}
	if r, err := verifyQuote([]byte("q"), config, nil, "tdx"); err != nil || r.PlatformID() != "" {
		t.Errorf("without a list an old server is fine: %v %+v", err, r)
	}
	if _, err := verifyQuote([]byte("q"), config, []string{testPIID}, "tdx"); err == nil || !strings.Contains(err.Error(), "no platform identity") {
		t.Errorf("a list against an old server with an opaque quote must fail closed: %v", err)
	}
}

func TestAllowedPlatformIDsNeedQuoteVerification(t *testing.T) {
	policy := &VerificationPolicy{TEE: TeeTypeTDX, AllowedPlatformIDs: []string{testPIID}}
	_, err := VerifyEvidence(nil, nil, policy)
	if err == nil || !strings.Contains(err.Error(), "AllowedPlatformIDs needs QuoteVerification") {
		t.Errorf("the policy gate must fire before anything else: %v", err)
	}
}

// -- identity read from the quote itself (tests/vectors/ratls-v2/platform.json) --

type platformVector struct {
	PEM                string `json:"pck_leaf_pem"`
	PPID               string `json:"ppid"`
	PlatformInstanceID string `json:"platform_instance_id"`
	FMSPC              string `json:"fmspc"`
	PlatformID         string `json:"platform_id"`
	SevSnp             struct {
		ReportSize   int    `json:"report_size"`
		ChipIDOffset int    `json:"chip_id_offset"`
		ChipID       string `json:"chip_id"`
	} `json:"sev_snp"`
}

func loadPlatformVector(t *testing.T) platformVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "ratls-v2", "platform.json"))
	if err != nil {
		t.Skipf("vector: %v", err)
	}
	var v platformVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// quoteWithChain wraps the vector's PCK leaf the way a DCAP quote does: opaque
// bytes, then the PEM chain in the certification data.
func quoteWithChain(v platformVector) []byte {
	return append(append(bytes.Repeat([]byte{0x11}, 632), []byte(v.PEM)...), bytes.Repeat([]byte{0x22}, 8)...)
}

func TestPlatformIdentityFromQuote(t *testing.T) {
	v := loadPlatformVector(t)
	p, err := PlatformIdentityFromQuote("tdx", quoteWithChain(v))
	if err != nil || p == nil {
		t.Fatalf("tdx: %v %+v", err, p)
	}
	if p.PPID != v.PPID || p.PlatformInstanceID != v.PlatformInstanceID || p.FMSPC != v.FMSPC || p.ID() != v.PlatformID {
		t.Errorf("got %+v, want %+v", *p, v)
	}
	// A quote whose certification data is not a PEM chain carries no identity.
	if p, err := PlatformIdentityFromQuote("sgx", []byte("no chain here")); err != nil || p != nil {
		t.Errorf("opaque quote: %v %+v", err, p)
	}
	// A PEM certificate without the SGX extension is refused, not silently empty.
	if _, err := PlatformIdentityFromQuote("tdx", []byte(testLeafWithoutSgxExtPEM())); err == nil {
		t.Error("a non-PCK certificate must be an error")
	}
	// SEV-SNP: CHIP_ID from the report body.
	chip, _ := hex.DecodeString(v.SevSnp.ChipID)
	report := make([]byte, v.SevSnp.ReportSize)
	copy(report[v.SevSnp.ChipIDOffset:], chip)
	p, err = PlatformIdentityFromQuote("sev-snp", report)
	if err != nil || p.ChipID != v.SevSnp.ChipID || p.ID() != v.SevSnp.ChipID {
		t.Errorf("sev-snp: %v %+v", err, p)
	}
	if _, err := PlatformIdentityFromQuote("sev-snp", report[:100]); err == nil {
		t.Error("a short SEV-SNP report must be an error")
	}
}

// testLeafWithoutSgxExtPEM is a self-signed certificate with no SGX extension.
func testLeafWithoutSgxExtPEM() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not a PCK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestLocalPlatformIsAuthoritativeAndCrossChecked(t *testing.T) {
	v := loadPlatformVector(t)
	quote := quoteWithChain(v)

	// The server agrees: the quote's identity is used and marked as read from the quote.
	srv, _ := fakeAttestationServer(t, map[string]string{"ppid": v.PPID, "platformInstanceId": v.PlatformInstanceID, "fmspc": v.FMSPC})
	defer srv.Close()
	r, err := verifyQuote(quote, &QuoteVerificationConfig{Endpoint: srv.URL}, []string{v.PlatformID}, "tdx")
	if err != nil || !r.PlatformFromQuote || r.PlatformID() != v.PlatformID {
		t.Fatalf("agreeing server: %v %+v", err, r)
	}

	// An older server that reports nothing: the quote alone satisfies the list.
	old, _ := fakeAttestationServer(t, nil)
	defer old.Close()
	r, err = verifyQuote(quote, &QuoteVerificationConfig{Endpoint: old.URL}, []string{v.PlatformID}, "tdx")
	if err != nil || !r.PlatformFromQuote {
		t.Fatalf("old server with a readable quote: %v %+v", err, r)
	}
	if _, err := verifyQuote(quote, &QuoteVerificationConfig{Endpoint: old.URL}, []string{"0000"}, "tdx"); err == nil {
		t.Error("the quote's identity is enforced even when the server reports none")
	}

	// A server that disagrees with the quote is an error, whatever the list says.
	liar, _ := fakeAttestationServer(t, map[string]string{"ppid": v.PPID, "platformInstanceId": testPIID, "fmspc": v.FMSPC})
	defer liar.Close()
	if _, err := verifyQuote(quote, &QuoteVerificationConfig{Endpoint: liar.URL}, nil, "tdx"); err == nil || !strings.Contains(err.Error(), "platform identity mismatch") {
		t.Errorf("disagreeing server: %v", err)
	}
}
