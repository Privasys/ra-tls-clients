// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Package spend implements the Privasys SPEND TOKEN: the way an app names
// the user who pays for what it calls, without a bearer that could leak
// and without any dependency on attestation pinning.
//
// # How it works
//
// A user allows an app to spend their platform credits once (in the wallet
// at sign-in, or on privasys.id/account), under a monthly cap. The app then:
//
//  1. Generates a P-256 key at boot (Signer) and publishes the public half at
//     WellKnownPath on its own origin.
//  2. Fetches a spend token per signed-in user from the identity provider
//     (Signer.Token): a JWT naming the user, the app, the consent session
//     and the cap, with the app's key bound in `cnf`. The request is
//     authenticated as the app with a private-key JWT signed by that key.
//  3. Attaches, on every outbound call, the token plus a PROOF signed with
//     the same key and scoped to that callee host and that minute
//     (Signer.Decorate). A leaked token is inert without the key; a leaked
//     proof is worth one call to one host for one minute.
//
// The callee's runtime (enclave-os) verifies both on ingress and asserts the
// paying user to the app in HeaderPayer / HeaderPayerApp, stripping the same
// headers from every request it did not verify. A non-enclave callee uses
// Verifier to do the same itself. Callee apps read one header (Payer).
package spend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// HeaderToken carries the spend token on an outbound call.
	HeaderToken = "X-Privasys-Spend"
	// HeaderProof carries the per-callee proof beside the token.
	HeaderProof = "X-Privasys-Spend-Proof"

	// HeaderPayer, HeaderPayerApp and HeaderPayerSID are what a callee's
	// runtime asserts to the app after verifying token and proof. They live
	// in the X-Privasys-Peer-* namespace the runtime already strips from
	// every unverified request, so an app can trust them today, on a
	// runtime that predates spend tokens as much as on one that verifies
	// them.
	HeaderPayer    = "X-Privasys-Peer-Payer"
	HeaderPayerApp = "X-Privasys-Peer-Payer-App"
	HeaderPayerSID = "X-Privasys-Peer-Payer-Sid"

	// WellKnownPath is where an app publishes its spend keys.
	WellKnownPath = "/.well-known/privasys-spend-keys.json"
	// TokenPath is the identity provider's token endpoint.
	TokenPath = "/spend/token"

	// TokenTyp and ProofTyp are the JOSE typ values.
	TokenTyp     = "spend+jwt"
	ProofTyp     = "spend-proof+jwt"
	AssertionTyp = "spend-client+jwt"

	// ProofWindow bounds a proof's age at the callee; ReplayWindow is how
	// long a callee remembers a proof's jti.
	ProofWindow  = 60 * time.Second
	ReplayWindow = 2 * ProofWindow
)

// ErrNoConsent is returned by Signer.Token when the identity provider
// refuses because the user has not allowed the app to spend (or revoked it).
var ErrNoConsent = errors.New("spend: the user has not allowed this app to spend their credits")

// JWK is the public half of a P-256 key as it travels in a JWKS and in a
// token's cnf.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// PublicKey decodes the JWK.
func (k JWK) PublicKey() (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("spend: unsupported key %s/%s", k.Kty, k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("spend: jwk x: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("spend: jwk y: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("spend: jwk point not on P-256")
	}
	return pub, nil
}

// JWKOf renders a P-256 public key as a JWK with its RFC 7638 thumbprint
// as kid.
func JWKOf(pub *ecdsa.PublicKey) JWK {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	k := JWK{Kty: "EC", Crv: "P-256", Use: "sig", Alg: "ES256",
		X: base64.RawURLEncoding.EncodeToString(x), Y: base64.RawURLEncoding.EncodeToString(y)}
	k.Kid = Thumbprint(k)
	return k
}

// Thumbprint is the RFC 7638 thumbprint of a P-256 JWK.
func Thumbprint(k JWK) string {
	canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, k.X, k.Y)
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- Signer (caller side) -----------------------------------------------------

// Signer is an app's spend key plus its per-user token cache.
type Signer struct {
	appID  string
	issuer string
	key    *ecdsa.PrivateKey
	jwk    JWK
	http   *http.Client
	now    func() time.Time

	mu     sync.Mutex
	tokens map[string]*cachedToken
}

type cachedToken struct {
	token string
	exp   time.Time
	cap   int64
	sid   string
}

// Option configures a Signer.
type Option func(*Signer)

// WithHTTPClient sets the client used to reach the identity provider.
func WithHTTPClient(c *http.Client) Option { return func(s *Signer) { s.http = c } }

// WithKey uses an existing P-256 key instead of generating one (tests, or
// an app that keeps its key in a sealed store across restarts).
func WithKey(k *ecdsa.PrivateKey) Option { return func(s *Signer) { s.key = k } }

// NewSigner creates a spend signer for appID (undashed hex app id, or an
// OIDC client id for a non-enclave app) against issuerURL (the identity
// provider, e.g. https://privasys.id). A fresh P-256 key is generated in
// memory; publish it with ServeJWKS at WellKnownPath.
func NewSigner(appID, issuerURL string, opts ...Option) (*Signer, error) {
	appID = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(appID), "-", ""))
	if appID == "" {
		return nil, errors.New("spend: app id required")
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if !strings.HasPrefix(issuerURL, "https://") {
		return nil, errors.New("spend: issuer must be an https URL")
	}
	s := &Signer{appID: appID, issuer: issuerURL, now: time.Now, tokens: map[string]*cachedToken{}}
	for _, o := range opts {
		o(s)
	}
	if s.key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("spend: generate key: %w", err)
		}
		s.key = k
	}
	if s.http == nil {
		s.http = &http.Client{Timeout: 15 * time.Second}
	}
	s.jwk = JWKOf(&s.key.PublicKey)
	return s, nil
}

// AppID returns the app id the signer acts as.
func (s *Signer) AppID() string { return s.appID }

// Kid returns the current key's thumbprint.
func (s *Signer) Kid() string { return s.jwk.Kid }

// JWKS returns the JSON key set to publish at WellKnownPath.
func (s *Signer) JWKS() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []JWK{s.jwk}})
	return b
}

// ServeJWKS is an http.Handler for WellKnownPath.
func (s *Signer) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.JWKS())
}

// Token returns a spend token for sub, fetching or refreshing it from the
// identity provider as needed. ErrNoConsent when the user never allowed
// this app to spend (or revoked it); other errors are transport failures.
func (s *Signer) Token(ctx context.Context, sub string) (string, error) {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return "", errors.New("spend: subject required")
	}
	now := s.now()
	s.mu.Lock()
	c := s.tokens[sub]
	s.mu.Unlock()
	if c != nil && now.Add(5*time.Minute).Before(c.exp) {
		return c.token, nil
	}
	tok, err := s.fetch(ctx, sub)
	if err != nil {
		if c != nil && now.Before(c.exp) {
			return c.token, nil // keep serving the live token through an outage
		}
		return "", err
	}
	s.mu.Lock()
	s.tokens[sub] = tok
	s.mu.Unlock()
	return tok.token, nil
}

// Forget drops the cached token for sub (after a callee reported it
// revoked, or on sign-out).
func (s *Signer) Forget(sub string) {
	s.mu.Lock()
	delete(s.tokens, sub)
	s.mu.Unlock()
}

// Cap returns the monthly cap the cached token for sub carries (0 = none,
// or no token cached).
func (s *Signer) Cap(sub string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.tokens[sub]; c != nil {
		return c.cap
	}
	return 0
}

func (s *Signer) fetch(ctx context.Context, sub string) (*cachedToken, error) {
	assertion, err := s.assertion()
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"sub": sub, "client_assertion": assertion})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.issuer+TokenPath, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("spend: token request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrNoConsent
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spend: token request: status %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	var out struct {
		SpendToken string `json:"spend_token"`
		ExpiresIn  int64  `json:"expires_in"`
		Cap        int64  `json:"cap"`
		SID        string `json:"sid"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.SpendToken == "" {
		return nil, errors.New("spend: token request: malformed response")
	}
	return &cachedToken{
		token: out.SpendToken,
		exp:   s.now().Add(time.Duration(out.ExpiresIn) * time.Second),
		cap:   out.Cap,
		sid:   out.SID,
	}, nil
}

// assertion signs the private-key JWT that authenticates the app to the
// token endpoint.
func (s *Signer) assertion() (string, error) {
	now := s.now()
	claims := map[string]any{
		"iss": s.appID, "sub": s.appID, "aud": s.issuer + TokenPath,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": randomID(),
	}
	return SignJWT(s.key, s.jwk.Kid, AssertionTyp, claims)
}

// Proof signs a per-callee proof for aud (the callee host, lowercase,
// without port).
func (s *Signer) Proof(aud string) (string, error) {
	aud = NormaliseHost(aud)
	if aud == "" {
		return "", errors.New("spend: proof audience required")
	}
	now := s.now()
	claims := map[string]any{"aud": aud, "iat": now.Unix(), "jti": randomID()}
	return SignJWT(s.key, s.jwk.Kid, ProofTyp, claims)
}

// Decorate attaches the spend token for sub and a proof for the request's
// host to req. Any caller-supplied spend headers are replaced. An empty sub
// leaves the request untouched (the app then pays as itself).
func (s *Signer) Decorate(ctx context.Context, req *http.Request, sub string) error {
	req.Header.Del(HeaderToken)
	req.Header.Del(HeaderProof)
	if strings.TrimSpace(sub) == "" {
		return nil
	}
	tok, err := s.Token(ctx, sub)
	if err != nil {
		return err
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	proof, err := s.Proof(host)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderToken, tok)
	req.Header.Set(HeaderProof, proof)
	return nil
}

// NormaliseHost lowercases a host and drops a port, so caller and callee
// name the audience the same way.
func NormaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
}

// --- Verifier (callee side) ----------------------------------------------------

// Payer is the verified paying user behind a request.
type Payer struct {
	Sub   string
	AppID string
	SID   string
	Cap   int64
	// TokenExp is when the token expires; a callee may cache the verified
	// claims by token hash until then.
	TokenExp time.Time
}

// TokenClaims are the parsed claims of a spend token.
type TokenClaims struct {
	Issuer string
	Sub    string
	AppID  string
	SID    string
	Cap    int64
	Iat    time.Time
	Exp    time.Time
	JTI    string
	Cnf    JWK
}

// KeyFunc resolves the identity provider's signing key by kid.
type KeyFunc func(kid string) (*ecdsa.PublicKey, error)

// ParseToken verifies a spend token's signature (ES256 against keyFn),
// issuer, typ and expiry, and returns its claims.
func ParseToken(token, issuer string, keyFn KeyFunc, now time.Time) (*TokenClaims, error) {
	_, body, err := verifyJWS(token, func(kid, typ string) (*ecdsa.PublicKey, error) {
		if typ != TokenTyp {
			return nil, fmt.Errorf("spend: token typ %q", typ)
		}
		return keyFn(kid)
	})
	if err != nil {
		return nil, err
	}
	var c struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Azp string `json:"azp"`
		SID string `json:"sid"`
		Cap int64  `json:"cap"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		JTI string `json:"jti"`
		Cnf struct {
			JWK JWK `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("spend: token claims: %w", err)
	}
	if issuer != "" && c.Iss != issuer {
		return nil, fmt.Errorf("spend: token issuer %q", c.Iss)
	}
	if c.Sub == "" || c.Azp == "" || c.SID == "" {
		return nil, errors.New("spend: token lacks sub, azp or sid")
	}
	if c.Exp == 0 || now.After(time.Unix(c.Exp, 0)) {
		return nil, errors.New("spend: token expired")
	}
	if c.Cnf.JWK.X == "" || c.Cnf.JWK.Y == "" {
		return nil, errors.New("spend: token has no cnf key")
	}
	if c.Cnf.JWK.Kid == "" {
		c.Cnf.JWK.Kid = Thumbprint(c.Cnf.JWK)
	}
	return &TokenClaims{
		Issuer: c.Iss, Sub: c.Sub, AppID: c.Azp, SID: c.SID, Cap: c.Cap,
		Iat: time.Unix(c.Iat, 0), Exp: time.Unix(c.Exp, 0), JTI: c.JTI, Cnf: c.Cnf.JWK,
	}, nil
}

// VerifyProof checks a proof against the token's cnf key: signature,
// audience (the callee host), freshness. Returns the proof's jti for
// replay tracking.
func VerifyProof(proof string, cnf JWK, host string, now time.Time) (string, error) {
	pub, err := cnf.PublicKey()
	if err != nil {
		return "", err
	}
	_, body, err := verifyJWS(proof, func(kid, typ string) (*ecdsa.PublicKey, error) {
		if typ != ProofTyp {
			return nil, fmt.Errorf("spend: proof typ %q", typ)
		}
		if kid != "" && cnf.Kid != "" && kid != cnf.Kid {
			return nil, errors.New("spend: proof kid is not the token's cnf key")
		}
		return pub, nil
	})
	if err != nil {
		return "", err
	}
	var c struct {
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return "", fmt.Errorf("spend: proof claims: %w", err)
	}
	if NormaliseHost(c.Aud) != NormaliseHost(host) {
		return "", fmt.Errorf("spend: proof audience %q is not this host", c.Aud)
	}
	age := now.Sub(time.Unix(c.Iat, 0))
	if age > ProofWindow || age < -ProofWindow {
		return "", errors.New("spend: proof is not fresh")
	}
	if c.JTI == "" {
		return "", errors.New("spend: proof has no jti")
	}
	return c.JTI, nil
}

// ReplayCache remembers proof ids for ReplayWindow.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewReplayCache returns an empty cache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: map[string]time.Time{}, now: time.Now}
}

// Seen records jti and reports whether it was already present. Expired
// entries are swept opportunistically.
func (c *ReplayCache) Seen(jti string) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) > 4096 {
		for k, t := range c.seen {
			if now.Sub(t) > ReplayWindow {
				delete(c.seen, k)
			}
		}
	}
	if t, ok := c.seen[jti]; ok && now.Sub(t) <= ReplayWindow {
		return true
	}
	c.seen[jti] = now
	return false
}

// Verifier verifies token + proof for a callee that is not behind an
// enclave-os runtime (a plain HTTPS service). Enclave apps do not need it:
// their runtime verifies and asserts HeaderPayer.
type Verifier struct {
	issuer  string
	keys    *jwksCache
	replay  *ReplayCache
	tokens  sync.Map // token hash → *TokenClaims (verified claims cached to exp)
	Revoked func(sid string) bool
	now     func() time.Time
}

// NewVerifier creates a verifier for tokens issued by issuerURL, fetching
// its keys from <issuer>/jwks.
func NewVerifier(issuerURL string, client *http.Client) *Verifier {
	issuerURL = strings.TrimRight(issuerURL, "/")
	return &Verifier{
		issuer: issuerURL,
		keys:   newJWKSCache(issuerURL+"/jwks", client),
		replay: NewReplayCache(),
		now:    time.Now,
	}
}

// Verify checks the spend headers on r for host (the callee's own host;
// empty uses r.Host). It returns (nil, nil) when the request carries no
// spend token, a Payer on success, and an error the callee should turn
// into 403 otherwise.
func (v *Verifier) Verify(r *http.Request, host string) (*Payer, error) {
	tok := strings.TrimSpace(r.Header.Get(HeaderToken))
	proof := strings.TrimSpace(r.Header.Get(HeaderProof))
	if tok == "" && proof == "" {
		return nil, nil
	}
	if host == "" {
		host = r.Host
	}
	return v.verify(tok, proof, host)
}

func (v *Verifier) verify(tok, proof, host string) (*Payer, error) {
	if tok == "" || proof == "" {
		return nil, errors.New("spend: token and proof must travel together")
	}
	now := v.now()
	h := sha256.Sum256([]byte(tok))
	key := base64.RawURLEncoding.EncodeToString(h[:])
	var claims *TokenClaims
	if cached, ok := v.tokens.Load(key); ok {
		c := cached.(*TokenClaims)
		if now.Before(c.Exp) {
			claims = c
		}
	}
	if claims == nil {
		c, err := ParseToken(tok, v.issuer, v.keys.Key, now)
		if err != nil {
			return nil, err
		}
		v.tokens.Store(key, c)
		claims = c
	}
	if v.Revoked != nil && v.Revoked(claims.SID) {
		return nil, errors.New("spend: consent revoked")
	}
	jti, err := VerifyProof(proof, claims.Cnf, host, now)
	if err != nil {
		return nil, err
	}
	if v.replay.Seen(jti) {
		return nil, errors.New("spend: proof replayed")
	}
	return &Payer{Sub: claims.Sub, AppID: claims.AppID, SID: claims.SID, Cap: claims.Cap, TokenExp: claims.Exp}, nil
}

// PayerFromRequest reads the runtime-asserted payer headers (an app behind
// enclave-os). nil when the request carries none.
func PayerFromRequest(r *http.Request) *Payer {
	sub := strings.TrimSpace(r.Header.Get(HeaderPayer))
	if sub == "" {
		return nil
	}
	return &Payer{
		Sub:   sub,
		AppID: strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderPayerApp))),
		SID:   strings.TrimSpace(r.Header.Get(HeaderPayerSID)),
	}
}

// StripPayerHeaders removes the runtime-asserted payer headers from an
// inbound request (a non-enclave callee must do this before honouring
// what its own Verifier asserts).
func StripPayerHeaders(r *http.Request) {
	r.Header.Del(HeaderPayer)
	r.Header.Del(HeaderPayerApp)
	r.Header.Del(HeaderPayerSID)
}

// --- JWKS cache ----------------------------------------------------------------

type jwksCache struct {
	url     string
	http    *http.Client
	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

func newJWKSCache(jwksURL string, client *http.Client) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksCache{url: jwksURL, http: client, keys: map[string]*ecdsa.PublicKey{}}
}

// Key resolves kid, refetching the JWKS when it is stale or the kid is
// unknown (at most every 30 s).
func (c *jwksCache) Key(kid string) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok && time.Since(c.fetched) < 10*time.Minute {
		return k, nil
	}
	if time.Since(c.fetched) > 30*time.Second {
		if err := c.refresh(); err != nil {
			if k, ok := c.keys[kid]; ok {
				return k, nil
			}
			return nil, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("spend: issuer publishes no key %q", kid)
}

func (c *jwksCache) refresh() error {
	resp, err := c.http.Get(c.url)
	if err != nil {
		return fmt.Errorf("spend: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("spend: fetch jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&doc); err != nil {
		return fmt.Errorf("spend: parse jwks: %w", err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range doc.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = Thumbprint(k)
		}
		keys[kid] = pub
	}
	c.keys = keys
	c.fetched = time.Now()
	return nil
}

// --- compact JWS (ES256) --------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SignJWT signs a compact ES256 JWS with the given header typ and kid.
// Exported for issuers and tests; apps use Signer.
func SignJWT(key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": typ, "kid": kid})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", fmt.Errorf("spend: sign: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64(sig), nil
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// verifyJWS checks an ES256 compact JWS with the key keyFn returns for its
// header and returns the header and the raw payload.
func verifyJWS(token string, keyFn func(kid, typ string) (*ecdsa.PublicKey, error)) (*header, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("spend: malformed jws")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, errors.New("spend: malformed jws header")
	}
	var h header
	if err := json.Unmarshal(hdrJSON, &h); err != nil {
		return nil, nil, errors.New("spend: malformed jws header")
	}
	if h.Alg != "ES256" {
		return nil, nil, fmt.Errorf("spend: alg %q", h.Alg)
	}
	pub, err := keyFn(h.Kid, h.Typ)
	if err != nil {
		return nil, nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, nil, errors.New("spend: malformed jws signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, nil, errors.New("spend: bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, errors.New("spend: malformed jws payload")
	}
	return &h, body, nil
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("spend: rand: " + err.Error())
	}
	return b64(b)
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// IssuerFromEnv returns the identity provider an app should use:
// PRIVASYS_ISSUER when set (the runtime injects it), else the production
// issuer.
func IssuerFromEnv(get func(string) string) string {
	if v := strings.TrimSpace(get("PRIVASYS_ISSUER")); v != "" {
		if u, err := url.Parse(v); err == nil && u.Scheme == "https" {
			return strings.TrimRight(v, "/")
		}
	}
	return "https://privasys.id"
}
