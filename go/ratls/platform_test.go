// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if err := platformAllowed(&QuoteVerificationResult{}, []string{testPIID}); err == nil || !strings.Contains(err.Error(), "reported no platform identity") {
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
	r, err := verifyQuote(quote, config, nil)
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
	if _, err := verifyQuote(quote, config, []string{"0000", strings.ToUpper(testPIID)}); err != nil {
		t.Errorf("allowed platform: %v", err)
	}
	if sent, _ := (*last)["allowedPlatformIds"].([]interface{}); len(sent) != 2 {
		t.Errorf("allow-list not sent: %v", (*last)["allowedPlatformIds"])
	}

	// Not on the list: the server refuses and the client agrees.
	if _, err := verifyQuote(quote, config, []string{"0000"}); err == nil || !strings.Contains(err.Error(), "PLATFORM_NOT_ALLOWED") {
		t.Errorf("want the server's refusal, got %v", err)
	}
	// tdx-gpu path: same behaviour.
	if r, _, err := verifyTDXGPU(quote, []byte("gpu"), config, []string{testPIID}); err != nil || r.PlatformID() != testPIID {
		t.Errorf("tdx-gpu: %v %+v", err, r)
	}
	if _, _, err := verifyTDXGPU(quote, []byte("gpu"), config, []string{"0000"}); err == nil {
		t.Error("tdx-gpu: platform off the list must fail")
	}
}

func TestVerifyQuoteFailsClosedOnAServerWithoutPlatformIdentity(t *testing.T) {
	srv, _ := fakeAttestationServer(t, nil) // an older server: no "platform" object, list ignored
	defer srv.Close()
	config := &QuoteVerificationConfig{Endpoint: srv.URL}
	if r, err := verifyQuote([]byte("q"), config, nil); err != nil || r.PlatformID() != "" {
		t.Errorf("without a list an old server is fine: %v %+v", err, r)
	}
	if _, err := verifyQuote([]byte("q"), config, []string{testPIID}); err == nil || !strings.Contains(err.Error(), "reported no platform identity") {
		t.Errorf("a list against an old server must fail closed: %v", err)
	}
}

func TestAllowedPlatformIDsNeedQuoteVerification(t *testing.T) {
	policy := &VerificationPolicy{TEE: TeeTypeTDX, AllowedPlatformIDs: []string{testPIID}}
	_, err := VerifyEvidence(nil, nil, policy)
	if err == nil || !strings.Contains(err.Error(), "AllowedPlatformIDs needs QuoteVerification") {
		t.Errorf("the policy gate must fire before anything else: %v", err)
	}
}
