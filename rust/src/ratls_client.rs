// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS client connector for enclave-os-mini.
//!
//! Provides:
//! - TLS connection with optional CA certificate verification
//! - RA-TLS certificate inspection (SGX / TDX quote extraction)
//! - Minimal HTTP/1.1 protocol over RA-TLS (curl-compatible)
//! - Typed request/response helpers matching the server REST API
//!
//! # Dependencies
//! ```toml
//! [dependencies]
//! rustls = "0.23"
//! webpki-roots = "0.26"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! x509-parser = "0.16"
//! ```

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer;

// ---------------------------------------------------------------------------
//  RA-TLS OIDs
// ---------------------------------------------------------------------------

/// Intel SGX Quote  (enclave-os-mini)
pub const OID_SGX_QUOTE: &str = "1.2.840.113741.1.13.1.0";
/// Intel TDX Quote  (ra-tls-caddy / TDX VMs)
pub const OID_TDX_QUOTE: &str = "1.2.840.113741.1.5.5.1.6";

// Privasys configuration OIDs
/// Config Merkle root — proves all config inputs.
pub const OID_CONFIG_MERKLE_ROOT: &str = "1.3.6.1.4.1.65230.1.1";
/// Egress CA bundle hash — proves the outbound trust anchors.
pub const OID_EGRESS_CA_HASH: &str = "1.3.6.1.4.1.65230.2.1";
/// Runtime version hash — SHA-256 of the runtime version (Wasmtime / containerd).
pub const OID_RUNTIME_VERSION_HASH: &str = "1.3.6.1.4.1.65230.2.4";
/// Combined workloads hash — proves the application code (WASM apps / container images).
pub const OID_COMBINED_WORKLOADS_HASH: &str = "1.3.6.1.4.1.65230.2.5";
/// Data Encryption Key origin — "byok:<fingerprint>" or "generated".
pub const OID_DEK_ORIGIN: &str = "1.3.6.1.4.1.65230.2.6";
/// Attestation servers hash — SHA-256 of the sorted attestation server URL list.
pub const OID_ATTESTATION_SERVERS_HASH: &str = "1.3.6.1.4.1.65230.2.7";
/// Per-workload config Merkle root.
pub const OID_WORKLOAD_CONFIG_MERKLE_ROOT: &str = "1.3.6.1.4.1.65230.3.1";
/// Per-workload code/image hash.
pub const OID_WORKLOAD_CODE_HASH: &str = "1.3.6.1.4.1.65230.3.2";
/// Per-workload image ref (Virtual only).
pub const OID_WORKLOAD_IMAGE_REF: &str = "1.3.6.1.4.1.65230.3.3";
/// Per-workload key source / volume encryption.
pub const OID_WORKLOAD_KEY_SOURCE: &str = "1.3.6.1.4.1.65230.3.4";

// Backward-compatible aliases
/// Alias for `OID_COMBINED_WORKLOADS_HASH` (legacy name).
pub const OID_WASM_APPS_HASH: &str = OID_COMBINED_WORKLOADS_HASH;

/// All known Privasys configuration OIDs.
const PRIVASYS_OIDS: &[&str] = &[
    OID_CONFIG_MERKLE_ROOT,
    OID_EGRESS_CA_HASH,
    OID_RUNTIME_VERSION_HASH,
    OID_COMBINED_WORKLOADS_HASH,
    OID_DEK_ORIGIN,
    OID_ATTESTATION_SERVERS_HASH,
    OID_WORKLOAD_CONFIG_MERKLE_ROOT,
    OID_WORKLOAD_CODE_HASH,
    OID_WORKLOAD_IMAGE_REF,
    OID_WORKLOAD_KEY_SOURCE,
];

/// Map OID dotted-string → human label.
pub fn oid_label(oid: &str) -> &'static str {
    match oid {
        OID_SGX_QUOTE => "SGX Quote",
        OID_TDX_QUOTE => "TDX Quote",
        OID_CONFIG_MERKLE_ROOT => "Config Merkle Root",
        OID_EGRESS_CA_HASH => "Egress CA Hash",
        OID_RUNTIME_VERSION_HASH => "Runtime Version Hash",
        OID_COMBINED_WORKLOADS_HASH => "Combined Workloads Hash",
        OID_DEK_ORIGIN => "DEK Origin",
        OID_ATTESTATION_SERVERS_HASH => "Attestation Servers Hash",
        OID_WORKLOAD_CONFIG_MERKLE_ROOT => "Workload Config Merkle Root",
        OID_WORKLOAD_CODE_HASH => "Workload Code Hash",
        OID_WORKLOAD_IMAGE_REF => "Workload Image Ref",
        OID_WORKLOAD_KEY_SOURCE => "Workload Key Source",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
//  Quote byte-offset constants
// ---------------------------------------------------------------------------

/// SGX DCAP Quote v3 layout: QuoteHeader(48) + ReportBody(384).
pub mod sgx_quote {
    pub const MIN_SIZE: usize = 432;
    pub const MRENCLAVE: std::ops::Range<usize> = 112..144;
    pub const MRSIGNER: std::ops::Range<usize> = 176..208;
    pub const REPORT_DATA: std::ops::Range<usize> = 368..432;
}

/// SGX raw Report structure (as returned by `sgx_create_report`).
///
/// Layout: `ReportBody(384) + KeyId(32) + MAC(16)` = 432 bytes.
/// The offsets differ from a DCAP Quote v3 because there is no
/// 48-byte QuoteHeader prefix.
pub mod sgx_report {
    pub const SIZE: usize = 432;
    pub const MRENCLAVE: std::ops::Range<usize> = 64..96;
    pub const MRSIGNER: std::ops::Range<usize> = 128..160;
    pub const REPORT_DATA: std::ops::Range<usize> = 320..384;
}

/// TDX DCAP Quote v4 layout: Quote4Header(48) + Report2Body(584).
pub mod tdx_quote {
    pub const MIN_SIZE: usize = 632;
    pub const MRTD: std::ops::Range<usize> = 184..232;
    pub const REPORT_DATA: std::ops::Range<usize> = 568..632;
}

// ---------------------------------------------------------------------------
//  SGX format detection
// ---------------------------------------------------------------------------

/// Detected format of the SGX attestation blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgxQuoteFormat {
    /// Full DCAP Quote v3 (48-byte header + report body + sig).
    DcapV3,
    /// Raw SGX Report from `sgx_create_report` (no header).
    RawReport,
}

/// Detect whether an SGX attestation blob is a DCAP Quote v3 or a raw Report.
///
/// DCAP Quote v3 starts with a 2-byte LE version field equal to 3.
/// Raw SGX Reports start with `CPUSVN[16]`, which never decodes to
/// version 3 in practice.
pub fn detect_sgx_format(raw: &[u8]) -> SgxQuoteFormat {
    if raw.len() >= 4 {
        let version = u16::from_le_bytes([raw[0], raw[1]]);
        if version == 3 {
            return SgxQuoteFormat::DcapV3;
        }
    }
    SgxQuoteFormat::RawReport
}

/// Return the offsets for the detected SGX format.
fn sgx_offsets(format: SgxQuoteFormat) -> (std::ops::Range<usize>, std::ops::Range<usize>, std::ops::Range<usize>, usize) {
    match format {
        SgxQuoteFormat::DcapV3 => (
            sgx_quote::MRENCLAVE,
            sgx_quote::MRSIGNER,
            sgx_quote::REPORT_DATA,
            sgx_quote::MIN_SIZE,
        ),
        SgxQuoteFormat::RawReport => (
            sgx_report::MRENCLAVE,
            sgx_report::MRSIGNER,
            sgx_report::REPORT_DATA,
            sgx_report::SIZE,
        ),
    }
}

// ---------------------------------------------------------------------------
//  RA-TLS verification types
// ---------------------------------------------------------------------------

/// Target TEE type for RA-TLS verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeType {
    Sgx,
    Tdx,
}

/// How the verifier reproduces the quote's 64-byte `ReportData`.
///
/// Both modes compute `SHA-512( SHA-256(pubkey) || binding )`.
///
/// | TEE | Pubkey | Deterministic binding | Challenge binding |
/// |-----|--------|-----------------------|-------------------|
/// | SGX | Raw EC point (65 B) | *skipped* | Client nonce |
/// | TDX | Full SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` | Client nonce |
#[derive(Debug, Clone)]
pub enum ReportDataMode {
    /// Do not verify ReportData (inspection only).
    Skip,
    /// Deterministic — reproduced from the certificate alone.
    Deterministic,
    /// Challenge-response — binding is a client-supplied nonce.
    ChallengeResponse { nonce: Vec<u8> },
}

/// An expected X.509 extension OID and its value.
#[derive(Debug, Clone)]
pub struct ExpectedOid {
    pub oid: String,
    pub expected_value: Vec<u8>,
}

// ---------------------------------------------------------------------------
//  Quote verification types
// ---------------------------------------------------------------------------

/// TCB status returned by a quote verification service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteVerificationStatus {
    Ok,
    TcbOutOfDate,
    ConfigurationNeeded,
    SwHardeningNeeded,
    ConfigurationAndSwHardeningNeeded,
    TcbRevoked,
    TcbExpired,
    Unrecognized(String),
}

impl std::fmt::Display for QuoteVerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::TcbOutOfDate => write!(f, "TCB_OUT_OF_DATE"),
            Self::ConfigurationNeeded => write!(f, "CONFIGURATION_NEEDED"),
            Self::SwHardeningNeeded => write!(f, "SW_HARDENING_NEEDED"),
            Self::ConfigurationAndSwHardeningNeeded => {
                write!(f, "CONFIGURATION_AND_SW_HARDENING_NEEDED")
            }
            Self::TcbRevoked => write!(f, "TCB_REVOKED"),
            Self::TcbExpired => write!(f, "TCB_EXPIRED"),
            Self::Unrecognized(s) => write!(f, "{}", s),
        }
    }
}

impl QuoteVerificationStatus {
    fn from_str(s: &str) -> Self {
        match s {
            "OK" => Self::Ok,
            "TCB_OUT_OF_DATE" => Self::TcbOutOfDate,
            "CONFIGURATION_NEEDED" => Self::ConfigurationNeeded,
            "SW_HARDENING_NEEDED" => Self::SwHardeningNeeded,
            "CONFIGURATION_AND_SW_HARDENING_NEEDED" => Self::ConfigurationAndSwHardeningNeeded,
            "TCB_REVOKED" => Self::TcbRevoked,
            "TCB_EXPIRED" => Self::TcbExpired,
            other => Self::Unrecognized(other.to_string()),
        }
    }
}

/// Configuration for remote quote verification via an HTTP service.
///
/// Point `endpoint` at a quote verification service (e.g. an attestation server).
#[derive(Debug, Clone)]
pub struct QuoteVerificationConfig {
    /// URL of the quote verification endpoint (POST).
    pub endpoint: String,
    /// Optional Bearer token for the verification service.
    pub token: Option<String>,
    /// TCB statuses accepted in addition to `Ok`.
    pub accepted_statuses: Vec<QuoteVerificationStatus>,
    /// HTTP request timeout in seconds (default: 10).
    pub timeout_secs: u64,
}

/// Result of remote quote verification.
#[derive(Debug, Clone)]
pub struct QuoteVerificationResult {
    /// TCB status returned by the verification service.
    pub status: QuoteVerificationStatus,
    /// TCB date from the collateral (if provided).
    pub tcb_date: Option<String>,
    /// Intel Security Advisory IDs (if any).
    pub advisory_ids: Vec<String>,
}

/// RA-TLS verification policy.
///
/// Pass to [`verify_ratls_cert`] to verify an RA-TLS certificate.
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Which TEE type to expect.
    pub tee: TeeType,
    /// Expected MRENCLAVE (SGX, 32 bytes). `None` = skip.
    pub mr_enclave: Option<[u8; 32]>,
    /// Expected MRSIGNER (SGX, 32 bytes). `None` = skip.
    pub mr_signer: Option<[u8; 32]>,
    /// Expected MRTD (TDX, 48 bytes). `None` = skip.
    pub mr_td: Option<[u8; 48]>,
    /// How to verify the quote's ReportData field.
    pub report_data: ReportDataMode,
    /// Expected custom OID values to verify.
    pub expected_oids: Vec<ExpectedOid>,
    /// Optional remote quote verification configuration.
    pub quote_verification: Option<QuoteVerificationConfig>,
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

/// Parsed attestation quote from the certificate.
#[derive(Debug, Clone)]
pub struct QuoteInfo {
    pub oid: String,
    pub label: String,
    pub critical: bool,
    pub raw: Vec<u8>,
    pub is_mock: bool,
    pub version: Option<u16>,
    pub report_data: Option<Vec<u8>>,
}

/// A custom X.509 extension (e.g. Privasys configuration OID).
#[derive(Debug, Clone)]
pub struct OidExtension {
    pub oid: String,
    pub label: String,
    pub value: Vec<u8>,
}

/// Summary of the server certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sig_algo: String,
    pub quote: Option<QuoteInfo>,
    /// Privasys configuration OIDs found in the certificate.
    pub custom_oids: Vec<OidExtension>,
    /// Result of remote quote verification (populated during verify).
    pub quote_verification: Option<QuoteVerificationResult>,
}

/// Inspect a DER-encoded certificate for RA-TLS extensions.
pub fn inspect_der_certificate(der: &[u8]) -> CertInfo {
    use x509_parser::prelude::*;

    let mut info = CertInfo {
        subject: String::new(),
        issuer: String::new(),
        serial: String::new(),
        not_before: String::new(),
        not_after: String::new(),
        sig_algo: String::new(),
        quote: None,
        custom_oids: Vec::new(),
        quote_verification: None,
    };

    let (_, cert) = match X509Certificate::from_der(der) {
        Ok(r) => r,
        Err(_) => return info,
    };

    info.subject = cert.subject().to_string();
    info.issuer = cert.issuer().to_string();
    info.serial = cert.raw_serial_as_string();
    info.not_before = cert.validity().not_before.to_rfc2822().unwrap_or_default();
    info.not_after = cert.validity().not_after.to_rfc2822().unwrap_or_default();
    info.sig_algo = cert.signature_algorithm.algorithm.to_id_string();

    // Walk extensions for RA-TLS OIDs
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == OID_SGX_QUOTE || oid_str == OID_TDX_QUOTE {
            let raw = ext.value.to_vec();
            info.quote = Some(parse_quote(&oid_str, ext.critical, &raw));
        } else if PRIVASYS_OIDS.contains(&oid_str.as_str()) {
            info.custom_oids.push(OidExtension {
                oid: oid_str.clone(),
                label: oid_label(&oid_str).to_string(),
                value: ext.value.to_vec(),
            });
        }
    }

    info
}

fn parse_quote(oid: &str, critical: bool, raw: &[u8]) -> QuoteInfo {
    let label = oid_label(oid).to_string();
    let mut q = QuoteInfo {
        oid: oid.to_string(),
        label,
        critical,
        raw: raw.to_vec(),
        is_mock: false,
        version: None,
        report_data: None,
    };

    if raw.starts_with(b"MOCK_QUOTE:") {
        q.is_mock = true;
        let rd_end = raw.len().min(75);
        q.report_data = Some(raw[11..rd_end].to_vec());
    } else if oid == OID_SGX_QUOTE && raw.len() >= 4 {
        q.version = Some(u16::from_le_bytes([raw[0], raw[1]]));
        let format = detect_sgx_format(raw);
        let (_, _, rd_range, min_sz) = sgx_offsets(format);
        if raw.len() >= min_sz {
            q.report_data = Some(raw[rd_range].to_vec());
        }
    } else if oid == OID_TDX_QUOTE && raw.len() >= 4 {
        q.version = Some(u16::from_le_bytes([raw[0], raw[1]]));
        if raw.len() >= tdx_quote::MIN_SIZE {
            q.report_data = Some(raw[tdx_quote::REPORT_DATA].to_vec());
        }
    }

    q
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

/// Verify an RA-TLS certificate against a [`VerificationPolicy`].
///
/// Returns `Ok(CertInfo)` with parsed certificate data on success, or
/// `Err(description)` if any policy check fails.
pub fn verify_ratls_cert(der: &[u8], policy: &VerificationPolicy) -> Result<CertInfo, String> {
    let info = inspect_der_certificate(der);

    // 1. Quote must be present
    let quote = info.quote.clone().ok_or("no RA-TLS attestation quote in certificate")?;
    if quote.is_mock {
        return Err("certificate contains a MOCK quote".into());
    }

    // 2. Correct TEE type
    match policy.tee {
        TeeType::Sgx => {
            if quote.oid != OID_SGX_QUOTE {
                return Err(format!(
                    "expected SGX quote ({}), found {}",
                    OID_SGX_QUOTE, quote.oid
                ));
            }
        }
        TeeType::Tdx => {
            if quote.oid != OID_TDX_QUOTE {
                return Err(format!(
                    "expected TDX quote ({}), found {}",
                    OID_TDX_QUOTE, quote.oid
                ));
            }
        }
    }

    // 3. Measurement registers
    verify_measurements(&quote.raw, policy)?;

    // 4. ReportData
    verify_report_data(der, &quote.raw, policy)?;

    // 5. Custom OID values
    verify_expected_oids(&info.custom_oids, &policy.expected_oids)?;

    // 6. Remote quote verification
    let mut info = info;
    if let Some(ref config) = policy.quote_verification {
        info.quote_verification = Some(verify_quote(&quote.raw, config)?);
    }

    Ok(info)
}

/// Verify SGX or TDX measurement registers.
fn verify_measurements(raw: &[u8], policy: &VerificationPolicy) -> Result<(), String> {
    match policy.tee {
        TeeType::Sgx => {
            let format = detect_sgx_format(raw);
            let (mr_enclave_range, mr_signer_range, _, min_sz) = sgx_offsets(format);
            if raw.len() < min_sz {
                return Err(format!(
                    "SGX attestation blob too small: {} < {}",
                    raw.len(), min_sz
                ));
            }
            if let Some(expected) = &policy.mr_enclave {
                let actual = &raw[mr_enclave_range];
                if actual != expected.as_slice() {
                    return Err(format!(
                        "MRENCLAVE mismatch: got {}, expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ));
                }
            }
            if let Some(expected) = &policy.mr_signer {
                let actual = &raw[mr_signer_range];
                if actual != expected.as_slice() {
                    return Err(format!(
                        "MRSIGNER mismatch: got {}, expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ));
                }
            }
        }
        TeeType::Tdx => {
            if raw.len() < tdx_quote::MIN_SIZE {
                return Err(format!(
                    "TDX quote too small: {} < {}",
                    raw.len(),
                    tdx_quote::MIN_SIZE
                ));
            }
            if let Some(expected) = &policy.mr_td {
                let actual = &raw[tdx_quote::MRTD];
                if actual != expected.as_slice() {
                    return Err(format!(
                        "MRTD mismatch: got {}, expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Verify the quote ReportData field.
fn verify_report_data(der: &[u8], raw: &[u8], policy: &VerificationPolicy) -> Result<(), String> {
    let binding = match &policy.report_data {
        ReportDataMode::Skip => return Ok(()),
        ReportDataMode::Deterministic => {
            if policy.tee == TeeType::Sgx {
                // Deterministic mode is not applicable for SGX (no creation_time).
                return Ok(());
            }
            // TDX: binding is NotBefore formatted as "YYYY-MM-DDTHH:MMZ"
            let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der)
                .map_err(|e| format!("parse cert: {e}"))?;
            let nb = cert.validity().not_before;
            // x509-parser's ASN1Time::to_rfc2822 gives us RFC 2822; we need ISO.
            // Use the raw datetime.
            let ts = nb.to_datetime();
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}Z",
                ts.year(),
                ts.month(),
                ts.day(),
                ts.hour(),
                ts.minute()
            )
            .into_bytes()
        }
        ReportDataMode::ChallengeResponse { nonce } => nonce.clone(),
    };

    // Extract the public key
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der)
        .map_err(|e| format!("parse cert: {e}"))?;
    let pubkey_bytes = cert.public_key().subject_public_key.data.to_vec();

    // Build the same input the enclave used: SHA-512( SHA-256(pubkey) || binding )
    let pubkey_input = match policy.tee {
        TeeType::Sgx => {
            // SGX: raw EC point (65 bytes) is used directly
            pubkey_bytes
        }
        TeeType::Tdx => {
            // TDX: full SPKI DER (AlgorithmIdentifier + BitString wrapping the EC point)
            build_p256_spki_der(&pubkey_bytes)
        }
    };

    let expected = compute_report_data_hash(&pubkey_input, &binding);

    // Get actual ReportData from quote
    let actual_range = match policy.tee {
        TeeType::Sgx => {
            let format = detect_sgx_format(raw);
            let (_, _, rd_range, _) = sgx_offsets(format);
            rd_range
        }
        TeeType::Tdx => tdx_quote::REPORT_DATA,
    };
    if raw.len() < actual_range.end {
        return Err("quote too small to contain ReportData".into());
    }
    let actual = &raw[actual_range];

    if actual != expected.as_slice() {
        return Err(format!(
            "ReportData mismatch:\n  got:      {}\n  expected: {}",
            hex::encode(actual),
            hex::encode(&expected)
        ));
    }
    Ok(())
}

/// Verify that each expected custom OID matches a certificate extension.
fn verify_expected_oids(
    actual: &[OidExtension],
    expected: &[ExpectedOid],
) -> Result<(), String> {
    for exp in expected {
        let found = actual.iter().find(|e| e.oid == exp.oid);
        match found {
            None => {
                return Err(format!(
                    "expected OID {} ({}) not found in certificate",
                    exp.oid,
                    oid_label(&exp.oid)
                ));
            }
            Some(ext) => {
                if ext.value != exp.expected_value {
                    return Err(format!(
                        "{} ({}) mismatch: got {}, expected {}",
                        oid_label(&exp.oid),
                        exp.oid,
                        hex::encode(&ext.value),
                        hex::encode(&exp.expected_value)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Build a DER-encoded SubjectPublicKeyInfo for an uncompressed P-256 EC
/// point so we match the Go `x509.MarshalPKIXPublicKey` output used by
/// ra-tls-caddy.
///
/// The result is 91 bytes:
///   SEQUENCE {
///     SEQUENCE { OID ecPublicKey, OID prime256v1 }
///     BIT STRING { 0x04 || x(32) || y(32) }
///   }
fn build_p256_spki_der(ec_point: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier for id-ecPublicKey + prime256v1
    const ALGO_ID: [u8; 21] = [
        0x30, 0x13, // SEQUENCE (19 bytes)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
    ];

    let bit_string_len = 1 + ec_point.len(); // 0x00 pad + point
    let mut spki = Vec::with_capacity(2 + ALGO_ID.len() + 2 + bit_string_len);
    // Outer SEQUENCE
    let inner_len = ALGO_ID.len() + 2 + bit_string_len;
    spki.push(0x30);
    spki.push(inner_len as u8);
    spki.extend_from_slice(&ALGO_ID);
    // BIT STRING: tag, length, unused-bits(0), EC point
    spki.push(0x03);
    spki.push(bit_string_len as u8);
    spki.push(0x00);
    spki.extend_from_slice(ec_point);
    spki
}

/// Compute the 64-byte ReportData hash: `SHA-512( SHA-256(pubkey) || binding )`.
fn compute_report_data_hash(pubkey_input: &[u8], binding: &[u8]) -> Vec<u8> {
    let pk_hash = digest::digest(&digest::SHA256, pubkey_input);
    let mut buf = Vec::with_capacity(32 + binding.len());
    buf.extend_from_slice(pk_hash.as_ref());
    buf.extend_from_slice(binding);
    digest::digest(&digest::SHA512, &buf).as_ref().to_vec()
}

/// Verify the raw quote against a remote quote verification service.
fn verify_quote(
    quote_raw: &[u8],
    config: &QuoteVerificationConfig,
) -> Result<QuoteVerificationResult, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let body = serde_json::json!({
        "quote": STANDARD.encode(quote_raw),
    });

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build();

    let mut request = agent.post(&config.endpoint);
    if let Some(ref key) = config.token {
        request = request.set("Authorization", &format!("Bearer {}", key));
    }

    let resp = request.send_json(body).map_err(|e| {
        match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                format!(
                    "quote verification failed: HTTP {} — {}",
                    code,
                    if body.is_empty() { "(empty body)".to_string() } else { body }
                )
            }
            other => format!("quote verification request failed: {}", other),
        }
    })?;

    let resp_body: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("failed to parse quote verification response: {}", e))?;

    let status_str = resp_body["status"]
        .as_str()
        .ok_or("quote verification response missing 'status' field")?;
    let status = QuoteVerificationStatus::from_str(status_str);

    let tcb_date = resp_body["tcbDate"].as_str().map(String::from);
    let advisory_ids = resp_body["advisoryIds"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let result = QuoteVerificationResult {
        status,
        tcb_date,
        advisory_ids,
    };

    if result.status != QuoteVerificationStatus::Ok
        && !config.accepted_statuses.contains(&result.status)
    {
        return Err(format!(
            "quote verification failed: status={}, advisories={:?}",
            result.status, result.advisory_ids
        ));
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
//  HTTP response parsing helpers
// ---------------------------------------------------------------------------

/// Find the `\r\n\r\n` header/body separator in a byte buffer.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

// ---------------------------------------------------------------------------
//  Danger: accept any certificate (for self-signed / dev)
// ---------------------------------------------------------------------------

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertVerifier;

    impl ServerCertVerifier for NoCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

/// RA-TLS client for enclave-os-mini.
pub struct RaTlsClient {
    stream: StreamOwned<ClientConnection, TcpStream>,
    peer_certs: Vec<Vec<u8>>,
}

impl RaTlsClient {
    /// Connect to the server.
    ///
    /// - `host`: server hostname or IP
    /// - `port`: server port
    /// - `ca_cert_pem`: optional PEM CA cert for chain verification.
    ///   If `None`, certificate verification is disabled.
    pub fn connect(host: &str, port: u16, ca_cert_pem: Option<&str>) -> io::Result<Self> {
        let config = if let Some(pem_path) = ca_cert_pem {
            let pem_data = std::fs::read(pem_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            let certs = rustls_pemfile::certs(&mut &pem_data[..])
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            for cert in certs {
                root_store.add(cert).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))
                })?;
            }
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertVerifier))
                .with_no_client_auth()
        };

        Self::finish_connect(host, port, config)
    }

    /// Connect to the server with a client certificate (mutual RA-TLS).
    ///
    /// - `host`: server hostname or IP
    /// - `port`: server port
    /// - `ca_cert_pem`: optional PEM CA cert for server chain verification.
    ///   If `None`, server certificate verification is disabled.
    /// - `client_cert_der`: DER-encoded X.509 client certificate chain
    ///   (leaf first). This is the querying enclave's RA-TLS certificate.
    /// - `client_key_pkcs8`: PKCS#8-encoded private key for the client cert.
    pub fn connect_mutual(
        host: &str,
        port: u16,
        ca_cert_pem: Option<&str>,
        client_cert_der: Vec<Vec<u8>>,
        client_key_pkcs8: Vec<u8>,
    ) -> io::Result<Self> {
        let certs: Vec<CertificateDer<'static>> = client_cert_der
            .into_iter()
            .map(|der| CertificateDer::from(der).into_owned())
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key_pkcs8));

        let config = if let Some(pem_path) = ca_cert_pem {
            let pem_data = std::fs::read(pem_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            let root_certs = rustls_pemfile::certs(&mut &pem_data[..])
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            for cert in root_certs {
                root_store.add(cert).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))
                })?;
            }
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertVerifier))
                .with_client_auth_cert(certs, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        };

        Self::finish_connect(host, port, config)
    }

    /// Connect with an RA-TLS challenge nonce (one-way attestation).
    ///
    /// Sends `nonce` in the ClientHello via TLS extension `0xFFBB`.
    /// The server is expected to bind this nonce into its RA-TLS
    /// certificate's `ReportData` field.
    ///
    /// Use [`ReportDataMode::ChallengeResponse`] when verifying the
    /// server certificate to prove freshness.
    pub fn connect_challenged(
        host: &str,
        port: u16,
        ca_cert_pem: Option<&str>,
        nonce: Vec<u8>,
    ) -> io::Result<Self> {
        let mut config = if let Some(pem_path) = ca_cert_pem {
            let pem_data = std::fs::read(pem_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            let certs = rustls_pemfile::certs(&mut &pem_data[..])
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            for cert in certs {
                root_store.add(cert).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))
                })?;
            }
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertVerifier))
                .with_no_client_auth()
        };
        config.ratls_challenge = Some(nonce);

        Self::finish_connect(host, port, config)
    }

    /// Connect with mutual RA-TLS and challenge nonces in both directions.
    ///
    /// - Sends `client_nonce` in the ClientHello (`0xFFBB`) so the
    ///   server binds it in its certificate.
    /// - Provides `client_cert_der` + `client_key_pkcs8` as the client
    ///   certificate for mutual authentication.
    ///
    /// The server may also send a challenge nonce in the CertificateRequest
    /// (`0xFFBB`). If you need to react to that nonce at runtime (e.g. to
    /// generate a fresh attestation certificate), use a custom
    /// `ResolvesClientCert` implementation instead.
    pub fn connect_mutual_challenged(
        host: &str,
        port: u16,
        ca_cert_pem: Option<&str>,
        client_cert_der: Vec<Vec<u8>>,
        client_key_pkcs8: Vec<u8>,
        client_nonce: Vec<u8>,
    ) -> io::Result<Self> {
        let certs: Vec<CertificateDer<'static>> = client_cert_der
            .into_iter()
            .map(|der| CertificateDer::from(der).into_owned())
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key_pkcs8));

        let mut config = if let Some(pem_path) = ca_cert_pem {
            let pem_data = std::fs::read(pem_path)?;
            let mut root_store = rustls::RootCertStore::empty();
            let root_certs = rustls_pemfile::certs(&mut &pem_data[..])
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            for cert in root_certs {
                root_store.add(cert).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{}", e))
                })?;
            }
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        } else {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertVerifier))
                .with_client_auth_cert(certs, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
        };
        config.ratls_challenge = Some(client_nonce);

        Self::finish_connect(host, port, config)
    }

    /// Shared TCP + TLS connection logic.
    fn finish_connect(host: &str, port: u16, config: ClientConfig) -> io::Result<Self> {
        let server_name: ServerName<'static> = host
            .to_string()
            .try_into()
            .unwrap_or_else(|_| {
                let addr: std::net::IpAddr = host.parse().expect("invalid host");
                ServerName::IpAddress(addr.into())
            });

        let conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let tcp = TcpStream::connect(format!("{}:{}", host, port))?;
        let mut tls = StreamOwned::new(conn, tcp);

        // Force handshake
        tls.flush()?;

        // Save peer certs
        let peer_certs: Vec<Vec<u8>> = tls
            .conn
            .peer_certificates()
            .unwrap_or(&[])
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect();

        Ok(Self {
            stream: tls,
            peer_certs,
        })
    }

    /// Inspect the server's leaf certificate.
    pub fn inspect_certificate(&self) -> CertInfo {
        if let Some(der) = self.peer_certs.first() {
            inspect_der_certificate(der)
        } else {
            CertInfo {
                subject: String::new(),
                issuer: String::new(),
                serial: String::new(),
                not_before: String::new(),
                not_after: String::new(),
                sig_algo: String::new(),
                quote: None,
                custom_oids: Vec::new(),
                quote_verification: None,
            }
        }
    }

    /// Verify the server's leaf certificate against a policy.
    pub fn verify_certificate(&self, policy: &VerificationPolicy) -> Result<CertInfo, String> {
        let der = self
            .peer_certs
            .first()
            .ok_or("no peer certificate")?;
        verify_ratls_cert(der, policy)
    }

    // -- HTTP/1.1 protocol ---------------------------------------------------

    fn send_http_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        auth_token: Option<&str>,
        connection_close: bool,
    ) -> io::Result<()> {
        let mut header = format!("{} {} HTTP/1.1\r\nHost: enclave\r\n", method, path);
        if let Some(b) = body {
            if !b.is_empty() {
                header.push_str(&format!(
                    "Content-Length: {}\r\nContent-Type: application/json\r\n",
                    b.len()
                ));
            }
        }
        if let Some(token) = auth_token {
            header.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }
        if connection_close {
            header.push_str("Connection: close\r\n");
        }
        header.push_str("\r\n");
        self.stream.write_all(header.as_bytes())?;
        if let Some(b) = body {
            if !b.is_empty() {
                self.stream.write_all(b)?;
            }
        }
        self.stream.flush()
    }

    fn recv_http_response(&mut self) -> io::Result<(u16, Vec<u8>)> {
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];

        // Read until \r\n\r\n
        let header_end;
        loop {
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection closed before HTTP headers",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_header_end(&buf) {
                header_end = pos;
                break;
            }
        }

        let header_section =
            std::str::from_utf8(&buf[..header_end]).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, e)
            })?;

        // Parse status
        let status_line = header_section
            .lines()
            .next()
            .unwrap_or("");
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Parse Content-Length
        let mut content_length: usize = 0;
        for line in header_section.lines().skip(1) {
            if let Some(rest) = line.strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
            {
                content_length = rest.trim().parse().unwrap_or(0);
            }
        }

        // Collect body
        let body_start = header_end + 4;
        let mut body = if body_start < buf.len() {
            buf[body_start..].to_vec()
        } else {
            Vec::new()
        };

        while body.len() < content_length {
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(content_length);

        Ok((status_code, body))
    }

    /// GET /healthz — liveness probe (no auth).
    pub fn healthz(&mut self) -> io::Result<serde_json::Value> {
        self.send_http_request("GET", "/healthz", None, None, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("healthz failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// GET /readyz — readiness probe (monitoring+ role).
    pub fn readyz(&mut self, auth_token: Option<&str>) -> io::Result<serde_json::Value> {
        self.send_http_request("GET", "/readyz", None, auth_token, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("readyz failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// GET /status — enclave status (monitoring+ role).
    pub fn status(&mut self, auth_token: Option<&str>) -> io::Result<serde_json::Value> {
        self.send_http_request("GET", "/status", None, auth_token, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("status failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// GET /metrics — Prometheus metrics (monitoring+ role).
    pub fn metrics(&mut self, auth_token: Option<&str>) -> io::Result<String> {
        self.send_http_request("GET", "/metrics", None, auth_token, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("metrics failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        String::from_utf8(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// POST /data — send module command, return response body.
    pub fn send_data(&mut self, data: &[u8], auth_token: Option<&str>) -> io::Result<Vec<u8>> {
        self.send_http_request("POST", "/data", Some(data), auth_token, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("send_data failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        Ok(body)
    }

    /// PUT /attestation-servers — set attestation server list.
    pub fn set_attestation_servers(
        &mut self,
        servers: &[&str],
        auth_token: Option<&str>,
    ) -> io::Result<serde_json::Value> {
        let payload = serde_json::json!({ "servers": servers });
        let body = serde_json::to_vec(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.send_http_request("PUT", "/attestation-servers", Some(&body), auth_token, false)?;
        let (status, resp) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "set_attestation_servers failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&resp)
                ),
            ));
        }
        serde_json::from_slice(&resp)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// POST /shutdown — request graceful shutdown.
    pub fn shutdown(&mut self, auth_token: Option<&str>) -> io::Result<()> {
        self.send_http_request("POST", "/shutdown", None, auth_token, true)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("shutdown failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
//  Pretty-print
// ---------------------------------------------------------------------------

pub fn print_cert_info(info: &CertInfo) {
    println!("  Subject      : {}", info.subject);
    println!("  Issuer       : {}", info.issuer);
    println!("  Serial       : {}", info.serial);
    println!("  Not Before   : {}", info.not_before);
    println!("  Not After    : {}", info.not_after);
    println!("  Sig Algo     : {}", info.sig_algo);

    if let Some(ref q) = info.quote {
        println!();
        println!("  ** RA-TLS Extension found! **");
        println!("    OID       : {}  ({})", q.oid, q.label);
        println!("    Critical  : {}", q.critical);
        println!("    Size      : {} bytes", q.raw.len());
        if q.is_mock {
            println!("    ** MOCK QUOTE **");
        }
        if let Some(v) = q.version {
            println!("    Version   : {}", v);
        }
        if let Some(ref rd) = q.report_data {
            println!("    ReportData: {}", hex::encode(rd));
        }

        // Display measurement registers from raw quote
        if q.oid == OID_SGX_QUOTE {
            let format = detect_sgx_format(&q.raw);
            let (mr_enclave_range, mr_signer_range, _, min_sz) = sgx_offsets(format);
            if q.raw.len() >= min_sz {
                println!("    Format    : {:?}", format);
                println!("    MRENCLAVE : {}", hex::encode(&q.raw[mr_enclave_range]));
                println!("    MRSIGNER  : {}", hex::encode(&q.raw[mr_signer_range]));
            }
        } else if q.oid == OID_TDX_QUOTE && q.raw.len() >= tdx_quote::MIN_SIZE {
            println!("    MRTD      : {}", hex::encode(&q.raw[tdx_quote::MRTD]));
        }

        let preview_len = q.raw.len().min(32);
        println!("    Preview   : {}...", hex::encode(&q.raw[..preview_len]));
    } else {
        println!();
        println!("  No RA-TLS extension found.");
    }

    if !info.custom_oids.is_empty() {
        println!();
        println!("  ** Privasys Configuration OIDs **");
        for ext in &info.custom_oids {
            println!("    {} ({}): {}", ext.label, ext.oid, hex::encode(&ext.value));
        }
    }

    if let Some(ref qv) = info.quote_verification {
        println!();
        println!("  ** Quote Verification **");
        println!("    Status    : {}", qv.status);
        if let Some(ref d) = qv.tcb_date {
            println!("    TCB Date  : {}", d);
        }
        if !qv.advisory_ids.is_empty() {
            println!("    Advisories: {}", qv.advisory_ids.join(", "));
        }
    }
}
