// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Vault client with Shamir Secret Sharing for enclave-os-mini.
//!
//! This crate provides:
//! - Shamir Secret Sharing over GF(2^8) ([`shamir`] module)
//! - High-level vault client that distributes secret shares across
//!   multiple vault instances via RA-TLS ([`client`] module)
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
//!     signing_key_pkcs8: std::fs::read("manager-key.p8").unwrap(),
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

pub mod client;
pub mod shamir;
