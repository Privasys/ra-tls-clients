// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

// High-level vault client with Shamir Secret Sharing.
//
// Distributes secret shares across multiple vault instances (SGX enclaves)
// via RA-TLS connections, and reconstructs secrets from any N-of-M shares.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"enclave-os-mini/clients/go/ratls"
)

// ---------------------------------------------------------------------------
//  Configuration
// ---------------------------------------------------------------------------

// VaultEndpoint is a single vault instance address.
type VaultEndpoint struct {
	Host string
	Port int
}

func (e VaultEndpoint) String() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

// VaultClientConfig configures the vault client.
type VaultClientConfig struct {
	// Endpoints are the vault instances (one share per endpoint).
	Endpoints []VaultEndpoint
	// Threshold is the minimum number of shares for reconstruction (>= 2).
	Threshold int
	// SigningKey is the secret owner's ES256 (P-256) private key for JWT signing.
	// Used to authenticate store/delete/update operations.
	SigningKey *ecdsa.PrivateKey
	// CACertPath is optional PEM CA cert for TLS verification.
	CACertPath string
	// VaultPolicy is optional RA-TLS verification policy for vault certs.
	VaultPolicy *ratls.VerificationPolicy
	// ClientCert is an optional TLS client certificate for mutual RA-TLS.
	// When set, GetSecret presents this certificate during the TLS handshake
	// so the vault can extract attestation evidence (SGX/TDX quote and OIDs)
	// from its X.509 extensions.
	ClientCert *tls.Certificate
	// GetClientCertificate is a callback for dynamic client certificate
	// generation during the TLS handshake.  When set, the callback
	// receives RATLSChallenge — the server's challenge nonce sent as
	// TLS extension 0xffbb in the CertificateRequest message — and
	// generates a fresh RA-TLS certificate binding that nonce into
	// report_data for bidirectional challenge-response attestation.
	//
	// Takes precedence over ClientCert when both are set.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// ---------------------------------------------------------------------------
//  Result types
// ---------------------------------------------------------------------------

// EndpointResult is the result of an operation against one vault endpoint.
type EndpointResult struct {
	Endpoint  string
	Success   bool
	Error     string
	ExpiresAt *uint64
}

// ReconstructedSecret is a successfully reconstructed secret.
type ReconstructedSecret struct {
	Secret    []byte
	ExpiresAt uint64
}

// ---------------------------------------------------------------------------
//  Wire types (mirrors of enclave-os-vault types.rs)
// ---------------------------------------------------------------------------

// VaultRequest is JSON-encoded inside Request.Data.
type VaultRequest struct {
	// Exactly one of these fields is non-nil when marshalled.
	StoreSecret        *vaultStoreSecret        `json:"StoreSecret,omitempty"`
	GetSecret          *vaultGetSecret          `json:"GetSecret,omitempty"`
	DeleteSecret       *vaultDeleteSecret       `json:"DeleteSecret,omitempty"`
	UpdateSecretPolicy *vaultUpdateSecretPolicy `json:"UpdateSecretPolicy,omitempty"`
}

type vaultStoreSecret struct {
	JWT []byte `json:"jwt"`
}

type vaultGetSecret struct {
	Name        string `json:"name"`
	BearerToken []byte `json:"bearer_token,omitempty"`
}

type vaultDeleteSecret struct {
	JWT []byte `json:"jwt"`
}

type vaultUpdateSecretPolicy struct {
	JWT []byte `json:"jwt"`
}

// VaultResponse is the vault's response, JSON-decoded from Response.Data.
type VaultResponse struct {
	SecretStored  *vaultSecretStored `json:"SecretStored,omitempty"`
	SecretValue   *vaultSecretValue  `json:"SecretValue,omitempty"`
	SecretDeleted *json.RawMessage   `json:"SecretDeleted,omitempty"`
	PolicyUpdated *json.RawMessage   `json:"PolicyUpdated,omitempty"`
	Error         *string            `json:"Error,omitempty"`
}

type vaultSecretStored struct {
	Name      string `json:"name"`
	ExpiresAt uint64 `json:"expires_at"`
}

type vaultSecretValue struct {
	Secret    []byte `json:"secret"`
	ExpiresAt uint64 `json:"expires_at"`
}

// OidClaim is an OID key-value pair from the caller's RA-TLS certificate.
type OidClaim struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

// OidRequirement is an OID requirement in a secret policy.
type OidRequirement struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

// SecretPolicy is the access policy for a vault secret.
type SecretPolicy struct {
	AllowedMREnclave []string `json:"allowed_mrenclave,omitempty"`
	AllowedMRTD      []string `json:"allowed_mrtd,omitempty"`
	// ManagerPubkey is the hex-encoded uncompressed P-256 public key
	// (65 bytes: 04 || x || y) of the manager authorised to issue bearer
	// tokens for this secret.  If non-nil, GetSecret requires a valid
	// ES256 JWT signed by this key.
	ManagerPubkey *string          `json:"manager_pubkey,omitempty"`
	RequiredOids  []OidRequirement `json:"required_oids,omitempty"`
	TTLSeconds    uint64           `json:"ttl_seconds,omitempty"`
}

// JWT claim types for store/delete/update.

type storeSecretClaims struct {
	Name   string        `json:"name"`
	Secret string        `json:"secret"` // base64url-encoded
	Policy *SecretPolicy `json:"policy"`
}

type deleteSecretClaims struct {
	Name string `json:"name"`
}

type updatePolicyClaims struct {
	Name   string        `json:"name"`
	Policy *SecretPolicy `json:"policy"`
}

// ---------------------------------------------------------------------------
//  VaultClient
// ---------------------------------------------------------------------------

// VaultClient distributes secrets across multiple vault instances using
// Shamir Secret Sharing over RA-TLS connections.
type VaultClient struct {
	endpoints            []VaultEndpoint
	threshold            int
	signingKey           *ecdsa.PrivateKey
	caCertPath           string
	policy               *ratls.VerificationPolicy
	clientCert           *tls.Certificate
	getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// NewVaultClient creates a new vault client.
func NewVaultClient(config VaultClientConfig) (*VaultClient, error) {
	if len(config.Endpoints) == 0 {
		return nil, errors.New("at least one vault endpoint required")
	}
	if config.Threshold < 2 {
		return nil, errors.New("threshold must be >= 2")
	}
	if config.Threshold > len(config.Endpoints) {
		return nil, errors.New("threshold must be <= number of endpoints")
	}
	if config.SigningKey == nil {
		return nil, errors.New("signing key required")
	}
	if config.SigningKey.Curve != elliptic.P256() {
		return nil, errors.New("signing key must be P-256 (ES256)")
	}

	return &VaultClient{
		endpoints:            config.Endpoints,
		threshold:            config.Threshold,
		signingKey:           config.SigningKey,
		caCertPath:           config.CACertPath,
		policy:               config.VaultPolicy,
		clientCert:           config.ClientCert,
		getClientCertificate: config.GetClientCertificate,
	}, nil
}

// StoreSecret splits a secret via Shamir SSS and stores one share per vault.
func (vc *VaultClient) StoreSecret(name string, secret []byte, policy *SecretPolicy) ([]EndpointResult, error) {
	shares, err := ShamirSplit(secret, vc.threshold, len(vc.endpoints))
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}

	results := make([]EndpointResult, len(vc.endpoints))
	okCount := 0

	for i, ep := range vc.endpoints {
		shareBytes := ShareToBytes(shares[i])
		shareB64 := base64.RawURLEncoding.EncodeToString(shareBytes)

		claims := storeSecretClaims{
			Name:   name,
			Secret: shareB64,
			Policy: policy,
		}

		jwt, err := vc.buildJWT(claims)
		if err != nil {
			results[i] = EndpointResult{Endpoint: ep.String(), Error: err.Error()}
			continue
		}

		req := VaultRequest{StoreSecret: &vaultStoreSecret{JWT: jwt}}
		resp, err := vc.sendVaultRequest(ep, &req)
		if err != nil {
			results[i] = EndpointResult{Endpoint: ep.String(), Error: err.Error()}
			continue
		}
		if resp.Error != nil {
			results[i] = EndpointResult{Endpoint: ep.String(), Error: *resp.Error}
			continue
		}
		if resp.SecretStored != nil {
			ea := resp.SecretStored.ExpiresAt
			results[i] = EndpointResult{Endpoint: ep.String(), Success: true, ExpiresAt: &ea}
			okCount++
		} else {
			results[i] = EndpointResult{Endpoint: ep.String(), Error: "unexpected response"}
		}
	}

	if okCount < vc.threshold {
		return results, fmt.Errorf("only %d/%d vaults stored (need >= %d)", okCount, len(vc.endpoints), vc.threshold)
	}
	return results, nil
}

// GetSecret retrieves shares from vault endpoints and reconstructs the secret.
//
// Attestation is provided via mutual RA-TLS: the client certificate
// configured in VaultClientConfig.ClientCert is presented during the
// TLS handshake.  The vault extracts the SGX/TDX quote and OID claims
// from that certificate.
func (vc *VaultClient) GetSecret(name string, bearerToken []byte) (*ReconstructedSecret, error) {
	var collected []*Share
	var minExpiry uint64 = ^uint64(0) // max u64
	var errs []string

	for _, ep := range vc.endpoints {
		if len(collected) >= vc.threshold {
			break
		}

		req := VaultRequest{GetSecret: &vaultGetSecret{
			Name:        name,
			BearerToken: bearerToken,
		}}

		resp, err := vc.sendVaultRequestMutual(ep, &req)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ep, err))
			continue
		}
		if resp.Error != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", ep, *resp.Error))
			continue
		}
		if resp.SecretValue == nil {
			errs = append(errs, fmt.Sprintf("%s: unexpected response", ep))
			continue
		}

		share, err := ShareFromBytes(resp.SecretValue.Secret)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: bad share: %v", ep, err))
			continue
		}

		if resp.SecretValue.ExpiresAt < minExpiry {
			minExpiry = resp.SecretValue.ExpiresAt
		}
		collected = append(collected, share)
	}

	if len(collected) < vc.threshold {
		return nil, fmt.Errorf("collected %d/%d shares (need %d); errors: %v",
			len(collected), len(vc.endpoints), vc.threshold, errs)
	}

	secret, err := ShamirReconstruct(collected)
	if err != nil {
		return nil, fmt.Errorf("reconstruct: %w", err)
	}

	return &ReconstructedSecret{Secret: secret, ExpiresAt: minExpiry}, nil
}

// DeleteSecret deletes a secret from all vault endpoints.
func (vc *VaultClient) DeleteSecret(name string) ([]EndpointResult, error) {
	jwt, err := vc.buildJWT(deleteSecretClaims{Name: name})
	if err != nil {
		return nil, err
	}
	req := VaultRequest{DeleteSecret: &vaultDeleteSecret{JWT: jwt}}
	return vc.broadcastRequest(&req), nil
}

// UpdatePolicy updates the access policy for a secret on all vault endpoints.
func (vc *VaultClient) UpdatePolicy(name string, policy *SecretPolicy) ([]EndpointResult, error) {
	jwt, err := vc.buildJWT(updatePolicyClaims{Name: name, Policy: policy})
	if err != nil {
		return nil, err
	}
	req := VaultRequest{UpdateSecretPolicy: &vaultUpdateSecretPolicy{JWT: jwt}}
	return vc.broadcastRequest(&req), nil
}

// ---------------------------------------------------------------------------
//  Internal helpers
// ---------------------------------------------------------------------------

func (vc *VaultClient) broadcastRequest(req *VaultRequest) []EndpointResult {
	results := make([]EndpointResult, len(vc.endpoints))
	for i, ep := range vc.endpoints {
		resp, err := vc.sendVaultRequest(ep, req)
		if err != nil {
			results[i] = EndpointResult{Endpoint: ep.String(), Error: err.Error()}
			continue
		}
		if resp.Error != nil {
			results[i] = EndpointResult{Endpoint: ep.String(), Error: *resp.Error}
			continue
		}
		results[i] = EndpointResult{Endpoint: ep.String(), Success: true}
	}
	return results
}

func (vc *VaultClient) sendVaultRequest(ep VaultEndpoint, req *VaultRequest) (*VaultResponse, error) {
	opts := &ratls.Options{CACertPath: vc.caCertPath}
	client, err := ratls.Connect(ep.Host, ep.Port, opts)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", ep, err)
	}
	defer client.Close()

	// Optional RA-TLS verification
	if vc.policy != nil {
		if _, err := client.VerifyCertificate(vc.policy); err != nil {
			return nil, fmt.Errorf("RA-TLS verify %s: %w", ep, err)
		}
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	respBytes, err := client.SendData(payload)
	if err != nil {
		return nil, fmt.Errorf("send to %s: %w", ep, err)
	}

	var resp VaultResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("parse response from %s: %w", ep, err)
	}
	return &resp, nil
}

// sendVaultRequestMutual connects with a client certificate (mutual RA-TLS),
// sends a VaultRequest, and decodes the VaultResponse.
//
// When GetClientCertificate is configured, dynamic cert generation is used
// (bidirectional challenge-response).  Otherwise falls back to the static
// ClientCert.
func (vc *VaultClient) sendVaultRequestMutual(ep VaultEndpoint, req *VaultRequest) (*VaultResponse, error) {
	if vc.getClientCertificate == nil && vc.clientCert == nil {
		return nil, fmt.Errorf("mutual RA-TLS required for GetSecret but no ClientCert or GetClientCertificate configured")
	}
	opts := &ratls.Options{
		CACertPath:           vc.caCertPath,
		GetClientCertificate: vc.getClientCertificate,
		ClientCert:           vc.clientCert,
	}
	client, err := ratls.Connect(ep.Host, ep.Port, opts)
	if err != nil {
		return nil, fmt.Errorf("mutual RA-TLS connect %s: %w", ep, err)
	}
	defer client.Close()

	// Optional RA-TLS verification
	if vc.policy != nil {
		if _, err := client.VerifyCertificate(vc.policy); err != nil {
			return nil, fmt.Errorf("RA-TLS verify %s: %w", ep, err)
		}
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	respBytes, err := client.SendData(payload)
	if err != nil {
		return nil, fmt.Errorf("send to %s: %w", ep, err)
	}

	var resp VaultResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, fmt.Errorf("parse response from %s: %w", ep, err)
	}
	return &resp, nil
}

// buildJWT creates a compact JWS (ES256) from claims.
// Format: base64url(header).base64url(payload).base64url(signature)
func (vc *VaultClient) buildJWT(claims interface{}) ([]byte, error) {
	header := `{"alg":"ES256","typ":"JWT"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal JWT claims: %w", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	// ES256: ECDSA-SHA256 with P-256
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, vc.signingKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ES256 sign: %w", err)
	}

	// JWS signature: r || s, each zero-padded to 32 bytes
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwt := signingInput + "." + sigB64

	return []byte(jwt), nil
}

// ---------------------------------------------------------------------------
//  Helpers for parsing PKCS#8 / PEM private keys
// ---------------------------------------------------------------------------

// ParseES256PrivateKeyPKCS8 parses a PKCS#8 DER-encoded P-256 private key.
func ParseES256PrivateKeyPKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return ecKey, nil
}

// ParseES256PrivateKeyRaw constructs a P-256 private key from a raw
// 32-byte scalar d and optionally the uncompressed public point (65 bytes).
// If pubBytes is nil, the public key is derived from d.
func ParseES256PrivateKeyRaw(d []byte, pubBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(d) != 32 {
		return nil, errors.New("private scalar must be 32 bytes")
	}
	curve := elliptic.P256()
	priv := new(ecdsa.PrivateKey)
	priv.D = new(big.Int).SetBytes(d)
	priv.PublicKey.Curve = curve

	if pubBytes != nil && len(pubBytes) == 65 && pubBytes[0] == 0x04 {
		priv.PublicKey.X = new(big.Int).SetBytes(pubBytes[1:33])
		priv.PublicKey.Y = new(big.Int).SetBytes(pubBytes[33:65])
	} else {
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d)
	}
	return priv, nil
}
