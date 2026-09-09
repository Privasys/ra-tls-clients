// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package spend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeIdP issues spend tokens for any consenting sub with its own P-256 key.
type fakeIdP struct {
	key      *ecdsa.PrivateKey
	srv      *httptest.Server
	consents map[string]bool
	appJWKS  func() []byte
	requests int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeIdP{key: key, consents: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []JWK{JWKOf(&key.PublicKey)}})
	})
	mux.HandleFunc("POST "+TokenPath, func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		var req struct {
			Sub       string `json:"sub"`
			Assertion string `json:"client_assertion"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Resolve the app key from the app's published JWKS, as the real IdP does.
		var doc struct {
			Keys []JWK `json:"keys"`
		}
		_ = json.Unmarshal(f.appJWKS(), &doc)
		_, body, err := verifyJWS(req.Assertion, func(kid, typ string) (*ecdsa.PublicKey, error) {
			for _, k := range doc.Keys {
				if k.Kid == kid {
					return k.PublicKey()
				}
			}
			return nil, http.ErrNoCookie
		})
		if err != nil {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		var a struct {
			Iss string `json:"iss"`
			Aud string `json:"aud"`
		}
		_ = json.Unmarshal(body, &a)
		if a.Aud != f.srv.URL+TokenPath {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if !f.consents[req.Sub] {
			http.Error(w, `{"error":"consent_required"}`, http.StatusForbidden)
			return
		}
		now := time.Now()
		tok, _ := SignJWT(key, JWKOf(&key.PublicKey).Kid, TokenTyp, map[string]any{
			"iss": f.srv.URL, "sub": req.Sub, "azp": a.Iss, "sid": "sid-" + req.Sub, "cap": 1000,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": "t1",
			"cnf": map[string]any{"jwk": doc.Keys[0]},
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"spend_token": tok, "expires_in": 3600, "cap": 1000, "sid": "sid-" + req.Sub})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func TestSignerDecorateAndVerify(t *testing.T) {
	idp := newFakeIdP(t)
	signer, err := NewSigner("0123456789abcdef0123456789abcdef", idp.srv.URL, WithHTTPClient(idp.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	idp.appJWKS = signer.JWKS
	idp.consents["alice"] = true

	req, _ := http.NewRequest(http.MethodPost, "https://Confidential-AI.apps.privasys.org:443/v1/chat", nil)
	if err := signer.Decorate(context.Background(), req, "alice"); err != nil {
		t.Fatalf("decorate: %v", err)
	}
	if req.Header.Get(HeaderToken) == "" || req.Header.Get(HeaderProof) == "" {
		t.Fatal("headers not set")
	}
	// Second decorate reuses the cached token.
	req2, _ := http.NewRequest(http.MethodPost, "https://confidential-ai.apps.privasys.org/v1/chat", nil)
	_ = signer.Decorate(context.Background(), req2, "alice")
	if idp.requests != 1 {
		t.Fatalf("token fetched %d times", idp.requests)
	}

	v := NewVerifier(idp.srv.URL, idp.srv.Client())
	payer, err := v.Verify(req, "confidential-ai.apps.privasys.org")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if payer.Sub != "alice" || payer.AppID != "0123456789abcdef0123456789abcdef" || payer.SID != "sid-alice" || payer.Cap != 1000 {
		t.Fatalf("payer: %+v", payer)
	}
	// Replaying the same proof is refused.
	if _, err := v.Verify(req, "confidential-ai.apps.privasys.org"); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay: %v", err)
	}
	// A fresh proof for another host is refused at this host.
	if _, err := v.Verify(req2, "drive.apps.privasys.org"); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("audience: %v", err)
	}
	// A proof signed by another key with the same token is refused.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged, _ := SignJWT(other, JWKOf(&other.PublicKey).Kid, ProofTyp, map[string]any{
		"aud": "confidential-ai.apps.privasys.org", "iat": time.Now().Unix(), "jti": "x"})
	req3, _ := http.NewRequest(http.MethodPost, "https://confidential-ai.apps.privasys.org/v1/chat", nil)
	req3.Header.Set(HeaderToken, req.Header.Get(HeaderToken))
	req3.Header.Set(HeaderProof, forged)
	if _, err := v.Verify(req3, "confidential-ai.apps.privasys.org"); err == nil {
		t.Fatal("forged proof accepted")
	}
	// Token without proof is refused; no headers at all is not an error.
	req4, _ := http.NewRequest(http.MethodGet, "https://confidential-ai.apps.privasys.org/", nil)
	req4.Header.Set(HeaderToken, req.Header.Get(HeaderToken))
	if _, err := v.Verify(req4, ""); err == nil {
		t.Fatal("token without proof accepted")
	}
	req5, _ := http.NewRequest(http.MethodGet, "https://confidential-ai.apps.privasys.org/", nil)
	if p, err := v.Verify(req5, ""); err != nil || p != nil {
		t.Fatalf("no headers: %v %v", p, err)
	}
	// Revocation feed.
	v.Revoked = func(sid string) bool { return sid == "sid-alice" }
	req6, _ := http.NewRequest(http.MethodPost, "https://confidential-ai.apps.privasys.org/v1/chat", nil)
	_ = signer.Decorate(context.Background(), req6, "alice")
	if _, err := v.Verify(req6, ""); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked: %v", err)
	}
}

func TestSignerNoConsent(t *testing.T) {
	idp := newFakeIdP(t)
	signer, _ := NewSigner("0123456789abcdef0123456789abcdef", idp.srv.URL, WithHTTPClient(idp.srv.Client()))
	idp.appJWKS = signer.JWKS
	if _, err := signer.Token(context.Background(), "bob"); err != ErrNoConsent {
		t.Fatalf("want ErrNoConsent, got %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://x.test/", nil)
	if err := signer.Decorate(context.Background(), req, ""); err != nil || req.Header.Get(HeaderToken) != "" {
		t.Fatal("empty sub must leave the request untouched")
	}
}

func TestProofFreshness(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := JWKOf(&key.PublicKey)
	old, _ := SignJWT(key, jwk.Kid, ProofTyp, map[string]any{"aud": "a.test", "iat": time.Now().Add(-2 * time.Minute).Unix(), "jti": "o"})
	if _, err := VerifyProof(old, jwk, "a.test", time.Now()); err == nil {
		t.Fatal("stale proof accepted")
	}
	fresh, _ := SignJWT(key, jwk.Kid, ProofTyp, map[string]any{"aud": "A.TEST", "iat": time.Now().Unix(), "jti": "f"})
	if jti, err := VerifyProof(fresh, jwk, "a.test:8443", time.Now()); err != nil || jti != "f" {
		t.Fatalf("fresh: %v %q", err, jti)
	}
}

func TestNormaliseHost(t *testing.T) {
	for in, want := range map[string]string{
		"Drive.apps.privasys.org:443": "drive.apps.privasys.org",
		"[::1]:8080":                  "::1",
		" x.test ":                    "x.test",
	} {
		if got := NormaliseHost(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestPayerFromRequest(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	if PayerFromRequest(r) != nil {
		t.Fatal("no headers")
	}
	r.Header.Set(HeaderPayer, "alice")
	r.Header.Set(HeaderPayerApp, "ABC")
	if p := PayerFromRequest(r); p.Sub != "alice" || p.AppID != "abc" {
		t.Fatalf("%+v", p)
	}
	StripPayerHeaders(r)
	if PayerFromRequest(r) != nil {
		t.Fatal("strip")
	}
}
