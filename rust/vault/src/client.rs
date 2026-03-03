// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! High-level vault client with Shamir Secret Sharing.
//!
//! Distributes secret shares across multiple vault instances (SGX enclaves)
//! via RA-TLS connections, and reconstructs secrets from any `threshold`
//! shares.
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────────┐       RA-TLS         ┌─────────────┐
//!  │              │──── share 1 ────────►│  Vault #1   │
//!  │  VaultClient │──── share 2 ────────►│  Vault #2   │
//!  │  (Shamir)    │──── share 3 ────────►│  Vault #3   │
//!  │              │       ...            │    ...      │
//!  │              │──── share M ────────►│  Vault #M   │
//!  └──────────────┘                      └─────────────┘
//!
//!  Reconstruction: any N-of-M shares → original secret
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use vault_client::client::{VaultClient, VaultClientConfig, VaultEndpoint};
//!
//! let config = VaultClientConfig {
//!     endpoints: vec![
//!         VaultEndpoint { host: "vault1.example.com".into(), port: 443 },
//!         VaultEndpoint { host: "vault2.example.com".into(), port: 443 },
//!         VaultEndpoint { host: "vault3.example.com".into(), port: 443 },
//!     ],
//!     threshold: 2,
//!     signing_key_pkcs8: std::fs::read("owner-key.p8").unwrap(),
//!     ca_cert_pem: Some("vault-ca.pem".into()),
//!     vault_policy: None,
//! };
//!
//! let client = VaultClient::new(config).unwrap();
//!
//! // Store — Shamir splits the secret into 3 shares (threshold 2)
//! let results = client.store_secret("my-dek", secret_bytes, &policy).unwrap();
//!
//! // Retrieve — fetches 2 shares and reconstructs
//! let secret = client.get_secret("my-dek", None, &my_quote, &[]).unwrap();
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};

use crate::shamir;
use ratls_client::RaTlsClient;
use ratls_client::VerificationPolicy;

// ---------------------------------------------------------------------------
//  Configuration
// ---------------------------------------------------------------------------

/// A single vault endpoint address.
#[derive(Debug, Clone)]
pub struct VaultEndpoint {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for VaultEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Configuration for the vault client.
pub struct VaultClientConfig {
    /// Vault endpoint addresses (one share per endpoint).
    pub endpoints: Vec<VaultEndpoint>,
    /// Shamir threshold: minimum shares needed to reconstruct.
    /// Must be `>= 2` and `<= endpoints.len()`.
    pub threshold: usize,
    /// PKCS#8 DER-encoded ES256 (P-256) private key for JWT signing.
    /// This is the secret owner's key, used to authenticate
    /// store/delete/update operations.
    pub signing_key_pkcs8: Vec<u8>,
    /// Optional PEM CA certificate path for TLS chain verification.
    /// If `None`, certificate verification is disabled (dev mode).
    pub ca_cert_pem: Option<String>,
    /// Optional RA-TLS verification policy for the vault's certificate.
    /// Use this to verify the vault's MRENCLAVE/MRSIGNER before sending shares.
    pub vault_policy: Option<VerificationPolicy>,
    /// Optional client certificate for mutual RA-TLS (used by `get_secret`).
    ///
    /// This is the querying enclave's RA-TLS certificate chain (DER, leaf
    /// first) containing the SGX/TDX quote in X.509 extensions. When set,
    /// `get_secret` presents this certificate during the TLS handshake so
    /// the vault can verify the caller's attestation.
    pub client_cert_der: Option<Vec<Vec<u8>>>,
    /// PKCS#8-encoded private key for `client_cert_der`.
    pub client_key_pkcs8: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
//  Result types
// ---------------------------------------------------------------------------

/// Result of an operation against a single vault endpoint.
#[derive(Debug, Clone)]
pub struct EndpointResult {
    /// Endpoint address (host:port).
    pub endpoint: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Expiry timestamp (for store operations).
    pub expires_at: Option<u64>,
}

/// Successfully reconstructed secret.
#[derive(Debug, Clone)]
pub struct ReconstructedSecret {
    /// The original secret bytes.
    pub secret: Vec<u8>,
    /// Earliest expiry across the shares that were used.
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
//  Wire types (mirrors of enclave-os-vault/src/types.rs)
// ---------------------------------------------------------------------------

/// Vault-specific request, JSON-encoded inside `Request::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    StoreSecret { jwt: Vec<u8> },
    GetSecret {
        name: String,
        #[serde(default)]
        bearer_token: Option<Vec<u8>>,
    },
    DeleteSecret { jwt: Vec<u8> },
    UpdateSecretPolicy { jwt: Vec<u8> },
}

/// Vault-specific response, JSON-encoded inside `Response::Data`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultResponse {
    SecretStored { name: String, expires_at: u64 },
    SecretValue { secret: Vec<u8>, expires_at: u64 },
    SecretDeleted,
    PolicyUpdated,
    Error(String),
}

/// OID claim from the caller's RA-TLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidClaim {
    pub oid: String,
    pub value: String,
}

/// OID requirement in a secret policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidRequirement {
    pub oid: String,
    pub value: String,
}

/// Access policy for a vault secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    #[serde(default)]
    pub allowed_mrenclave: Vec<String>,
    #[serde(default)]
    pub allowed_mrtd: Vec<String>,
    /// Hex-encoded uncompressed P-256 public key (65 bytes: `04 || x || y`)
    /// of the manager authorised to issue bearer tokens for this secret.
    /// If present, `GetSecret` requires a valid JWT signed by this key.
    #[serde(default)]
    pub manager_pubkey: Option<String>,
    #[serde(default)]
    pub required_oids: Vec<OidRequirement>,
    #[serde(default)]
    pub ttl_seconds: u64,
}

// JWT claim types (must match vault expectations)

#[derive(Serialize)]
struct StoreSecretClaims<'a> {
    name: &'a str,
    secret: String, // base64url-encoded
    policy: &'a SecretPolicy,
}

#[derive(Serialize)]
struct DeleteSecretClaims<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct UpdateSecretPolicyClaims<'a> {
    name: &'a str,
    policy: &'a SecretPolicy,
}

// ---------------------------------------------------------------------------
//  VaultClient
// ---------------------------------------------------------------------------

/// High-level vault client that distributes secrets across multiple SGX vault
/// instances using Shamir Secret Sharing.
///
/// - **Store/Delete/UpdatePolicy**: authenticated via ES256 JWT (secret owner)
/// - **GetSecret**: authenticated via mutual RA-TLS (client cert with quote)
pub struct VaultClient {
    endpoints: Vec<VaultEndpoint>,
    threshold: usize,
    signing_key: EcdsaKeyPair,
    ca_cert_pem: Option<String>,
    vault_policy: Option<VerificationPolicy>,
    /// Client certificate chain (DER, leaf first) for mutual RA-TLS.
    client_cert_der: Option<Vec<Vec<u8>>>,
    /// PKCS#8-encoded private key for the client certificate.
    client_key_pkcs8: Option<Vec<u8>>,
    rng: SystemRandom,
}

impl VaultClient {
    /// Create a new vault client.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing key is invalid or configuration
    /// constraints are violated.
    pub fn new(config: VaultClientConfig) -> Result<Self, String> {
        if config.endpoints.is_empty() {
            return Err("at least one vault endpoint required".into());
        }
        if config.threshold < 2 {
            return Err("threshold must be >= 2".into());
        }
        if config.threshold > config.endpoints.len() {
            return Err("threshold must be <= number of endpoints".into());
        }

        let rng = SystemRandom::new();
        let signing_key = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &config.signing_key_pkcs8,
            &rng,
        )
        .map_err(|e| format!("invalid PKCS#8 signing key: {e}"))?;

        Ok(Self {
            endpoints: config.endpoints,
            threshold: config.threshold,
            signing_key,
            ca_cert_pem: config.ca_cert_pem,
            vault_policy: config.vault_policy,
            client_cert_der: config.client_cert_der,
            client_key_pkcs8: config.client_key_pkcs8,
            rng,
        })
    }

    /// Store a secret using Shamir Secret Sharing across all vault endpoints.
    ///
    /// The secret is split into `M` shares (one per endpoint) with the
    /// configured threshold `N`.  Each vault stores one share under the
    /// same `name`.  The share index is embedded as the first byte.
    ///
    /// Returns one [`EndpointResult`] per endpoint.
    pub fn store_secret(
        &self,
        name: &str,
        secret: &[u8],
        policy: &SecretPolicy,
    ) -> Result<Vec<EndpointResult>, String> {
        let num_shares = self.endpoints.len();
        let shares = shamir::split(secret, self.threshold, num_shares)?;

        let mut results = Vec::with_capacity(num_shares);

        for (i, endpoint) in self.endpoints.iter().enumerate() {
            let share_bytes = shares[i].to_bytes();
            let share_b64 = URL_SAFE_NO_PAD.encode(&share_bytes);

            let claims = StoreSecretClaims {
                name,
                secret: share_b64,
                policy,
            };

            let jwt = self.build_jwt(&claims)?;
            let vault_req = VaultRequest::StoreSecret { jwt };

            match self.send_vault_request(endpoint, &vault_req) {
                Ok(VaultResponse::SecretStored { expires_at, .. }) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: true,
                        error: None,
                        expires_at: Some(expires_at),
                    });
                }
                Ok(VaultResponse::Error(e)) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: false,
                        error: Some(e),
                        expires_at: None,
                    });
                }
                Ok(other) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: false,
                        error: Some(format!("unexpected response: {:?}", other)),
                        expires_at: None,
                    });
                }
                Err(e) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: false,
                        error: Some(e),
                        expires_at: None,
                    });
                }
            }
        }

        // Warn if fewer than threshold succeeded
        let ok_count = results.iter().filter(|r| r.success).count();
        if ok_count < self.threshold {
            return Err(format!(
                "only {ok_count}/{num_shares} vaults stored successfully \
                 (need >= {} for reconstruction)",
                self.threshold
            ));
        }

        Ok(results)
    }

    /// Retrieve and reconstruct a secret from vault endpoints.
    ///
    /// Contacts endpoints in order until `threshold` shares are collected,
    /// then reconstructs the original secret via Shamir interpolation.
    ///
    /// Attestation is provided via mutual RA-TLS: the client certificate
    /// configured in [`VaultClientConfig::client_cert_der`] is presented
    /// during the TLS handshake.  The vault extracts the SGX/TDX quote
    /// and OID claims from that certificate.
    ///
    /// A `bearer_token` may still be required depending on the secret's
    /// policy (when `manager_pubkey` is set).
    pub fn get_secret(
        &self,
        name: &str,
        bearer_token: Option<&[u8]>,
    ) -> Result<ReconstructedSecret, String> {
        let mut collected_shares: Vec<shamir::Share> = Vec::new();
        let mut min_expiry = u64::MAX;
        let mut errors: Vec<String> = Vec::new();

        for endpoint in &self.endpoints {
            if collected_shares.len() >= self.threshold {
                break;
            }

            let vault_req = VaultRequest::GetSecret {
                name: name.to_string(),
                bearer_token: bearer_token.map(|t| t.to_vec()),
            };

            match self.send_vault_request_mutual(endpoint, &vault_req) {
                Ok(VaultResponse::SecretValue { secret, expires_at }) => {
                    match shamir::Share::from_bytes(&secret) {
                        Ok(share) => {
                            if expires_at < min_expiry {
                                min_expiry = expires_at;
                            }
                            collected_shares.push(share);
                        }
                        Err(e) => {
                            errors.push(format!("{endpoint}: bad share: {e}"));
                        }
                    }
                }
                Ok(VaultResponse::Error(e)) => {
                    errors.push(format!("{endpoint}: {e}"));
                }
                Ok(other) => {
                    errors.push(format!("{endpoint}: unexpected: {:?}", other));
                }
                Err(e) => {
                    errors.push(format!("{endpoint}: {e}"));
                }
            }
        }

        if collected_shares.len() < self.threshold {
            return Err(format!(
                "collected only {}/{} shares (need {}). Errors: {}",
                collected_shares.len(),
                self.endpoints.len(),
                self.threshold,
                errors.join("; ")
            ));
        }

        let secret = shamir::reconstruct(&collected_shares)?;

        Ok(ReconstructedSecret {
            secret,
            expires_at: min_expiry,
        })
    }

    /// Delete a secret from all vault endpoints.
    ///
    /// Returns one [`EndpointResult`] per endpoint.  Partial failures are
    /// reported but do not prevent other endpoints from being contacted.
    pub fn delete_secret(&self, name: &str) -> Result<Vec<EndpointResult>, String> {
        let claims = DeleteSecretClaims { name };
        let jwt = self.build_jwt(&claims)?;
        let vault_req = VaultRequest::DeleteSecret { jwt };
        Ok(self.broadcast_request(&vault_req))
    }

    /// Update the access policy for a secret on all vault endpoints.
    ///
    /// Returns one [`EndpointResult`] per endpoint.
    pub fn update_policy(
        &self,
        name: &str,
        policy: &SecretPolicy,
    ) -> Result<Vec<EndpointResult>, String> {
        let claims = UpdateSecretPolicyClaims { name, policy };
        let jwt = self.build_jwt(&claims)?;
        let vault_req = VaultRequest::UpdateSecretPolicy { jwt };
        Ok(self.broadcast_request(&vault_req))
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// Send a vault request to all endpoints, collecting results.
    fn broadcast_request(&self, vault_req: &VaultRequest) -> Vec<EndpointResult> {
        let mut results = Vec::with_capacity(self.endpoints.len());
        for endpoint in &self.endpoints {
            match self.send_vault_request(endpoint, vault_req) {
                Ok(VaultResponse::SecretDeleted) | Ok(VaultResponse::PolicyUpdated) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: true,
                        error: None,
                        expires_at: None,
                    });
                }
                Ok(VaultResponse::Error(e)) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: false,
                        error: Some(e),
                        expires_at: None,
                    });
                }
                Ok(other) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: false,
                        error: Some(format!("unexpected response: {:?}", other)),
                        expires_at: None,
                    });
                }
                Err(e) => {
                    results.push(EndpointResult {
                        endpoint: endpoint.to_string(),
                        success: false,
                        error: Some(e),
                        expires_at: None,
                    });
                }
            }
        }
        results
    }

    /// Connect to a vault endpoint via RA-TLS, send a VaultRequest, and
    /// decode the VaultResponse.
    fn send_vault_request(
        &self,
        endpoint: &VaultEndpoint,
        vault_req: &VaultRequest,
    ) -> Result<VaultResponse, String> {
        let ca = self.ca_cert_pem.as_deref();
        let mut client = RaTlsClient::connect(&endpoint.host, endpoint.port, ca)
            .map_err(|e| format!("connect to {endpoint}: {e}"))?;

        // Optionally verify the vault's RA-TLS certificate
        if let Some(ref policy) = self.vault_policy {
            client
                .verify_certificate(policy)
                .map_err(|e| format!("RA-TLS verify {endpoint}: {e}"))?;
        }

        let payload = serde_json::to_vec(vault_req)
            .map_err(|e| format!("serialise request: {e}"))?;

        let resp_bytes = client
            .send_data(&payload)
            .map_err(|e| format!("send to {endpoint}: {e}"))?;

        let vault_resp: VaultResponse = serde_json::from_slice(&resp_bytes)
            .map_err(|e| format!("parse response from {endpoint}: {e}"))?;

        Ok(vault_resp)
    }

    /// Connect to a vault endpoint via mutual RA-TLS (presenting a client
    /// certificate), send a VaultRequest, and decode the VaultResponse.
    ///
    /// Used for `GetSecret` where the vault requires the caller's RA-TLS
    /// certificate to extract attestation evidence.
    fn send_vault_request_mutual(
        &self,
        endpoint: &VaultEndpoint,
        vault_req: &VaultRequest,
    ) -> Result<VaultResponse, String> {
        let ca = self.ca_cert_pem.as_deref();

        let mut client = match (&self.client_cert_der, &self.client_key_pkcs8) {
            (Some(cert_chain), Some(key)) => {
                RaTlsClient::connect_mutual(
                    &endpoint.host,
                    endpoint.port,
                    ca,
                    cert_chain.clone(),
                    key.clone(),
                )
                .map_err(|e| format!("mutual RA-TLS connect to {endpoint}: {e}"))?
            }
            _ => {
                return Err(format!(
                    "mutual RA-TLS required for GetSecret but no client_cert_der/client_key_pkcs8 configured"
                ))
            }
        };

        // Optionally verify the vault's RA-TLS certificate
        if let Some(ref policy) = self.vault_policy {
            client
                .verify_certificate(policy)
                .map_err(|e| format!("RA-TLS verify {endpoint}: {e}"))?;
        }

        let payload = serde_json::to_vec(vault_req)
            .map_err(|e| format!("serialise request: {e}"))?;

        let resp_bytes = client
            .send_data(&payload)
            .map_err(|e| format!("send to {endpoint}: {e}"))?;

        let vault_resp: VaultResponse = serde_json::from_slice(&resp_bytes)
            .map_err(|e| format!("parse response from {endpoint}: {e}"))?;

        Ok(vault_resp)
    }

    /// Build a compact JWS (ES256) from claims.
    ///
    /// Format: `base64url(header).base64url(payload).base64url(signature)`
    /// where signature is the raw `r || s` (64 bytes) from P-256.
    fn build_jwt(&self, claims: &impl Serialize) -> Result<Vec<u8>, String> {
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

        let claims_json =
            serde_json::to_vec(claims).map_err(|e| format!("serialise JWT claims: {e}"))?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        let signing_input = format!("{header_b64}.{claims_b64}");

        let sig = self
            .signing_key
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|_| "ES256 signing failed".to_string())?;

        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        let jwt = format!("{signing_input}.{sig_b64}");

        Ok(jwt.into_bytes())
    }
}

// ---------------------------------------------------------------------------
//  Convenience: create a SecretPolicy builder
// ---------------------------------------------------------------------------

impl SecretPolicy {
    /// Create a new empty policy (denies all access — add measurements).
    pub fn new() -> Self {
        Self {
            allowed_mrenclave: Vec::new(),
            allowed_mrtd: Vec::new(),
            manager_pubkey: None,
            required_oids: Vec::new(),
            ttl_seconds: 0, // will default to 30 days
        }
    }

    /// Add an allowed SGX MRENCLAVE (hex-encoded, 64 chars).
    pub fn allow_mrenclave(mut self, mrenclave: &str) -> Self {
        self.allowed_mrenclave.push(mrenclave.to_lowercase());
        self
    }

    /// Add an allowed TDX MRTD (hex-encoded, 96 chars).
    pub fn allow_mrtd(mut self, mrtd: &str) -> Self {
        self.allowed_mrtd.push(mrtd.to_lowercase());
        self
    }

    /// Set the manager's public key (hex-encoded uncompressed P-256, 65 bytes).
    ///
    /// When set, `GetSecret` requires a bearer token that is a valid ES256
    /// JWT signed by the manager's corresponding private key.  The JWT
    /// payload must contain `{ "name": "<secret-name>" }` matching the
    /// requested secret.
    pub fn manager_pubkey(mut self, pubkey_hex: &str) -> Self {
        self.manager_pubkey = Some(pubkey_hex.to_lowercase());
        self
    }

    /// Require an OID value from the caller's RA-TLS certificate.
    pub fn require_oid(mut self, oid: &str, value: &str) -> Self {
        self.required_oids.push(OidRequirement {
            oid: oid.to_string(),
            value: value.to_lowercase(),
        });
        self
    }

    /// Set the TTL in seconds (capped at 90 days by the vault).
    pub fn ttl(mut self, seconds: u64) -> Self {
        self.ttl_seconds = seconds;
        self
    }
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self::new()
    }
}
