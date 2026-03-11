// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Integration test for RA-TLS + attestation verification using a Zitadel service user JWT.
//
// Required environment variables:
//
//	ZITADEL_KEY_FILE  — path to the Zitadel service user key JSON file
//	                    (downloaded from Zitadel: User → Keys → New)
//	OIDC_ISSUER       — Zitadel issuer URL (e.g. https://auth.privasys.org)
//	SGX_HOST          — SGX vault hostname (e.g. m-fr-1.privasys.org)
//	SGX_PORT          — SGX vault port (default: 8443)
//	ATTESTATION_URL   — attestation server URL (e.g. https://as.privasys.org)
//
// Run:
//
//	go test -v -tags integration -run TestAttestationWithJWT -timeout 30s
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// zitadelKey is the JSON key file format for Zitadel service users.
type zitadelKey struct {
	Type   string `json:"type"`
	KeyID  string `json:"keyId"`
	Key    string `json:"key"`
	UserID string `json:"userId"`
}

// loadZitadelKey loads and parses a Zitadel service user key JSON file.
func loadZitadelKey(path string) (*zitadelKey, *rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}

	var key zitadelKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, nil, fmt.Errorf("parse key JSON: %w", err)
	}

	block, _ := pem.Decode([]byte(key.Key))
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, nil, fmt.Errorf("parse private key: %w (pkcs8: %w)", err, err2)
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("expected RSA key, got %T", k)
		}
		privKey = rsaKey
	}

	return &key, privKey, nil
}

// buildJWTAssertion creates a signed JWT assertion for the Zitadel token endpoint.
// The assertion uses the jwt-bearer grant (RFC 7523) format that Zitadel expects.
func buildJWTAssertion(keyID, userID, issuer string, privKey *rsa.PrivateKey) (string, error) {
	now := time.Now()

	header := map[string]string{
		"alg": "RS256",
		"kid": keyID,
	}
	claims := map[string]interface{}{
		"iss": userID,
		"sub": userID,
		"aud": issuer,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// fetchJWT exchanges a JWT assertion for an access token via the jwt-bearer grant.
func fetchJWT(issuer, projectID, assertion string) (string, error) {
	tokenURL := strings.TrimRight(issuer, "/") + "/oauth/v2/token"

	scope := "openid urn:zitadel:iam:org:projects:roles"
	if projectID != "" {
		scope += " urn:zitadel:iam:org:project:id:" + projectID + ":aud"
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"scope":      {scope},
		"assertion":  {assertion},
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response: %s", string(body))
	}

	return tokenResp.AccessToken, nil
}

func TestAttestationWithJWT(t *testing.T) {
	keyFile := os.Getenv("ZITADEL_KEY_FILE")
	if keyFile == "" {
		t.Skip("ZITADEL_KEY_FILE not set — skipping integration test")
	}
	issuer := os.Getenv("OIDC_ISSUER")
	if issuer == "" {
		t.Skip("OIDC_ISSUER not set — skipping integration test")
	}
	sgxHost := os.Getenv("SGX_HOST")
	if sgxHost == "" {
		t.Skip("SGX_HOST not set — skipping integration test")
	}
	attestationURL := os.Getenv("ATTESTATION_URL")
	if attestationURL == "" {
		t.Skip("ATTESTATION_URL not set — skipping integration test")
	}
	projectID := os.Getenv("ZITADEL_PROJECT_ID")

	sgxPort := 8443
	if p := os.Getenv("SGX_PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			sgxPort = parsed
		}
	}

	// --- Step 1: Load Zitadel service user key ---
	t.Log("Loading Zitadel service user key...")
	zKey, privKey, err := loadZitadelKey(keyFile)
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}
	t.Logf("Key loaded: keyId=%s userId=%s", zKey.KeyID, zKey.UserID)

	// --- Step 2: Build JWT assertion ---
	t.Log("Building JWT assertion...")
	assertion, err := buildJWTAssertion(zKey.KeyID, zKey.UserID, issuer, privKey)
	if err != nil {
		t.Fatalf("Failed to build assertion: %v", err)
	}
	t.Logf("Assertion built (%d chars)", len(assertion))

	// --- Step 3: Exchange for access token ---
	t.Log("Fetching JWT access token from Zitadel...")
	accessToken, err := fetchJWT(issuer, projectID, assertion)
	if err != nil {
		t.Fatalf("Failed to fetch JWT: %v", err)
	}
	t.Logf("Access token received (%d chars)", len(accessToken))
	// Verify it's actually a JWT (3 dot-separated parts)
	parts := strings.SplitN(accessToken, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("Access token is not a JWT (got %d parts)", len(parts))
	}
	t.Log("Access token is a valid JWT")

	// --- Step 4: Connect to SGX vault via RA-TLS ---
	t.Logf("Connecting to SGX vault at %s:%d...", sgxHost, sgxPort)
	client, err := ratls.Connect(sgxHost, sgxPort, &ratls.Options{})
	if err != nil {
		t.Fatalf("RA-TLS connection failed: %v", err)
	}
	defer client.Close()
	t.Logf("TLS handshake complete: %s / %s", client.TLSVersion(), client.CipherSuite())

	// --- Step 5: Inspect certificate ---
	info := client.InspectCert()
	if info.Quote == nil {
		t.Fatal("No attestation quote in certificate")
	}
	t.Logf("Quote: %s (%d bytes)", info.Quote.Label, len(info.Quote.Raw))
	for _, oid := range info.CustomOids {
		t.Logf("  %s: %x", oid.Label, oid.Value)
	}

	// --- Step 6: Verify certificate + attestation ---
	t.Log("Verifying RA-TLS certificate with attestation server...")
	policy := &ratls.VerificationPolicy{
		TEE:        ratls.TeeTypeSGX,
		ReportData: ratls.ReportDataDeterministic,
		QuoteVerification: &ratls.QuoteVerificationConfig{
			Endpoint:    attestationURL,
			Token:       accessToken,
			TimeoutSecs: 15,
			AcceptedStatuses: []ratls.QuoteVerificationStatus{
				ratls.QvsTcbOutOfDate,
				ratls.QvsSwHardeningNeeded,
				ratls.QvsConfigurationAndSwHardeningNeeded,
				ratls.QvsConfigurationNeeded,
			},
		},
	}

	verifiedInfo, err := client.VerifyCertificate(policy)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	t.Log("=== VERIFICATION PASSED ===")
	if verifiedInfo.QuoteVerification != nil {
		t.Logf("Attestation status: %s", verifiedInfo.QuoteVerification.Status)
		if verifiedInfo.QuoteVerification.TcbDate != "" {
			t.Logf("TCB date: %s", verifiedInfo.QuoteVerification.TcbDate)
		}
		if len(verifiedInfo.QuoteVerification.AdvisoryIDs) > 0 {
			t.Logf("Advisory IDs: %v", verifiedInfo.QuoteVerification.AdvisoryIDs)
		}
	}
}

// TestOidcBootstrap tests the full OIDC bootstrap flow:
//
//  1. Obtain a manager JWT (with enclave-os-mini:manager + ORG_USER_MANAGER).
//  2. Connect to the SGX instance via RA-TLS.
//  3. Send SetAttestationServers with an oidc_bootstrap config.
//  4. The enclave generates a keypair, registers it with Zitadel via the
//     manager JWT, then self-provisions a token via jwt-bearer grant.
//  5. Verify AttestationServersUpdated response.
//
// Required environment variables:
//
//	ZITADEL_MANAGER_KEY_FILE — path to the manager's Zitadel key JSON
//	OIDC_ISSUER              — Zitadel issuer URL (e.g. https://auth.privasys.org)
//	SGX_HOST                 — SGX hostname (e.g. 141.94.219.130)
//	SGX_PORT                 — SGX port (default: 8445)
//	SERVICE_ACCOUNT_ID       — Zitadel service account to bootstrap (e.g. 363482218703618052)
//	ATTESTATION_URL          — attestation server URL (e.g. https://as.privasys.org/)
//	ZITADEL_PROJECT_ID       — (optional) Zitadel project ID for audience scoping
//
// Run:
//
//	go test -v -tags integration -run TestOidcBootstrap -timeout 60s
func TestOidcBootstrap(t *testing.T) {
	managerKeyFile := os.Getenv("ZITADEL_MANAGER_KEY_FILE")
	if managerKeyFile == "" {
		t.Skip("ZITADEL_MANAGER_KEY_FILE not set — skipping OIDC bootstrap test")
	}
	issuer := os.Getenv("OIDC_ISSUER")
	if issuer == "" {
		t.Skip("OIDC_ISSUER not set — skipping")
	}
	sgxHost := os.Getenv("SGX_HOST")
	if sgxHost == "" {
		t.Skip("SGX_HOST not set — skipping")
	}
	serviceAccountID := os.Getenv("SERVICE_ACCOUNT_ID")
	if serviceAccountID == "" {
		t.Skip("SERVICE_ACCOUNT_ID not set — skipping")
	}
	attestationURL := os.Getenv("ATTESTATION_URL")
	if attestationURL == "" {
		t.Skip("ATTESTATION_URL not set — skipping")
	}

	projectID := os.Getenv("ZITADEL_PROJECT_ID")

	sgxPort := 8445
	if p := os.Getenv("SGX_PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			sgxPort = parsed
		}
	}

	// --- Step 1: Obtain manager JWT ---
	t.Log("Loading manager Zitadel key...")
	mgrKey, mgrPriv, err := loadZitadelKey(managerKeyFile)
	if err != nil {
		t.Fatalf("Failed to load manager key: %v", err)
	}
	t.Logf("Manager key loaded: keyId=%s userId=%s", mgrKey.KeyID, mgrKey.UserID)

	assertion, err := buildJWTAssertion(mgrKey.KeyID, mgrKey.UserID, issuer, mgrPriv)
	if err != nil {
		t.Fatalf("Failed to build manager assertion: %v", err)
	}

	managerJWT, err := fetchJWT(issuer, projectID, assertion)
	if err != nil {
		t.Fatalf("Failed to fetch manager JWT: %v", err)
	}
	t.Logf("Manager JWT obtained (%d chars)", len(managerJWT))

	// --- Step 2: Connect to SGX instance ---
	t.Logf("Connecting to SGX instance at %s:%d...", sgxHost, sgxPort)
	client, err := ratls.Connect(sgxHost, sgxPort, &ratls.Options{})
	if err != nil {
		t.Fatalf("RA-TLS connection failed: %v", err)
	}
	defer client.Close()
	t.Logf("TLS handshake complete: %s / %s", client.TLSVersion(), client.CipherSuite())

	// --- Step 3: Send SetAttestationServers with oidc_bootstrap ---
	bootstrap := map[string]interface{}{
		"issuer":             issuer,
		"service_account_id": serviceAccountID,
	}
	if projectID != "" {
		bootstrap["project_id"] = projectID
	}

	request := map[string]interface{}{
		"auth": managerJWT,
		"SetAttestationServers": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"url":            attestationURL,
					"oidc_bootstrap": bootstrap,
				},
			},
		},
	}

	reqJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	t.Logf("Sending SetAttestationServers with OIDC bootstrap (service_account=%s)...", serviceAccountID)

	resp, err := client.SendRaw(reqJSON)
	if err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}

	// --- Step 4: Verify response ---
	t.Logf("Response: %s", string(resp))

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(resp, &parsed); err != nil {
		// Try as a plain string (Error variant)
		var errStr string
		if err2 := json.Unmarshal(resp, &errStr); err2 == nil {
			t.Fatalf("Enclave returned error: %s", errStr)
		}
		t.Fatalf("Failed to parse response: %v — raw: %s", err, string(resp))
	}

	if errMsg, ok := parsed["Error"]; ok {
		t.Fatalf("Enclave returned Error: %s", string(errMsg))
	}

	asUpdated, ok := parsed["AttestationServersUpdated"]
	if !ok {
		t.Fatalf("Expected AttestationServersUpdated, got: %s", string(resp))
	}

	var result struct {
		ServerCount int    `json:"server_count"`
		Hash        string `json:"hash"`
	}
	if err := json.Unmarshal(asUpdated, &result); err != nil {
		t.Fatalf("Failed to parse AttestationServersUpdated: %v", err)
	}

	if result.ServerCount != 1 {
		t.Errorf("Expected server_count=1, got %d", result.ServerCount)
	}
	if result.Hash == "" {
		t.Error("Expected non-empty hash")
	}

	t.Log("=== OIDC BOOTSTRAP PASSED ===")
	t.Logf("Attestation servers configured: %d (hash: %s)", result.ServerCount, result.Hash)
}
