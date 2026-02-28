// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS client connector for enclave-os-mini.
//!
//! Provides:
//! - TLS connection with optional CA certificate verification
//! - RA-TLS certificate inspection (SGX / TDX quote extraction)
//! - Length-delimited framing (4-byte big-endian prefix)
//! - Typed request/response helpers matching the Rust protocol
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
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};

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
/// WASM apps combined hash — proves the application code.
pub const OID_WASM_APPS_HASH: &str = "1.3.6.1.4.1.65230.2.3";

/// All known Privasys configuration OIDs.
const PRIVASYS_OIDS: &[&str] = &[
    OID_CONFIG_MERKLE_ROOT,
    OID_EGRESS_CA_HASH,
    OID_WASM_APPS_HASH,
];

/// Map OID dotted-string → human label.
pub fn oid_label(oid: &str) -> &'static str {
    match oid {
        OID_SGX_QUOTE => "SGX Quote",
        OID_TDX_QUOTE => "TDX Quote",
        OID_CONFIG_MERKLE_ROOT => "Config Merkle Root",
        OID_EGRESS_CA_HASH => "Egress CA Hash",
        OID_WASM_APPS_HASH => "WASM Apps Hash",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
//  DCAP quote byte-offset constants
// ---------------------------------------------------------------------------

/// SGX DCAP Quote v3 layout: QuoteHeader(48) + ReportBody(384).
pub mod sgx_quote {
    pub const MIN_SIZE: usize = 432;
    pub const MRENCLAVE: std::ops::Range<usize> = 112..144;
    pub const MRSIGNER: std::ops::Range<usize> = 176..208;
    pub const REPORT_DATA: std::ops::Range<usize> = 368..432;
}

/// TDX DCAP Quote v4 layout: Quote4Header(48) + Report2Body(584).
pub mod tdx_quote {
    pub const MIN_SIZE: usize = 632;
    pub const MRTD: std::ops::Range<usize> = 184..232;
    pub const REPORT_DATA: std::ops::Range<usize> = 568..632;
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
//  DCAP / QVL quote verification types
// ---------------------------------------------------------------------------

/// TCB status returned by a DCAP / QVL Quote Verification Service.
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

/// Configuration for DCAP / QVL quote verification via an HTTP service.
///
/// For SGX enclaves, point `endpoint` at a DCAP Quote Verification Service
/// (QVS / PCCS). For TDX VMs, use a service wrapping the Intel Quote
/// Verification Library (QVL).
#[derive(Debug, Clone)]
pub struct QuoteVerificationConfig {
    /// URL of the quote verification endpoint (POST).
    pub endpoint: String,
    /// Optional Bearer token (JWT) for the verification service.
    pub api_key: Option<String>,
    /// TCB statuses accepted in addition to `Ok`.
    pub accepted_statuses: Vec<QuoteVerificationStatus>,
    /// HTTP request timeout in seconds (default: 10).
    pub timeout_secs: u64,
}

/// Result of DCAP / QVL quote verification.
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
    /// Optional DCAP / QVL quote verification configuration.
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
    /// Result of DCAP / QVL quote verification (populated during verify).
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
    info.not_before = cert.validity().not_before.to_rfc2822();
    info.not_after = cert.validity().not_after.to_rfc2822();
    info.sig_algo = cert.signature_algorithm.algorithm.to_id_string();

    // Walk extensions for RA-TLS OIDs
    if let Ok(Some(extensions)) = cert.extensions_map() {
        // Fallback: iterate parsed extensions
    }

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
        if raw.len() >= 432 {
            q.report_data = Some(raw[368..432].to_vec());
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
    let quote = info.quote.as_ref().ok_or("no RA-TLS attestation quote in certificate")?;
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

    // 6. DCAP / QVL quote verification
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
            if raw.len() < sgx_quote::MIN_SIZE {
                return Err(format!(
                    "SGX quote too small: {} < {}",
                    raw.len(),
                    sgx_quote::MIN_SIZE
                ));
            }
            if let Some(expected) = &policy.mr_enclave {
                let actual = &raw[sgx_quote::MRENCLAVE];
                if actual != expected.as_slice() {
                    return Err(format!(
                        "MRENCLAVE mismatch: got {}, expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ));
                }
            }
            if let Some(expected) = &policy.mr_signer {
                let actual = &raw[sgx_quote::MRSIGNER];
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
            let ts = nb
                .to_datetime()
                .ok_or("cannot convert NotBefore to datetime")?;
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
        TeeType::Sgx => sgx_quote::REPORT_DATA,
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
    const ALGO_ID: [u8; 19] = [
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

/// Verify the raw quote against a DCAP / QVL verification service.
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
    if let Some(ref key) = config.api_key {
        request = request.set("Authorization", &format!("Bearer {}", key));
    }

    let resp = request
        .send_json(body)
        .map_err(|e| format!("DCAP verification request failed: {}", e))?;

    let resp_body: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("failed to parse DCAP verification response: {}", e))?;

    let status_str = resp_body["status"]
        .as_str()
        .ok_or("DCAP response missing 'status' field")?;
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
            "DCAP quote verification failed: status={}, advisories={:?}",
            result.status, result.advisory_ids
        ));
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
//  Framing
// ---------------------------------------------------------------------------

pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(payload);
    frame
}

pub fn decode_frame(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + length {
        return None;
    }
    Some((buf[4..4 + length].to_vec(), 4 + length))
}

// ---------------------------------------------------------------------------
//  Protocol types  (matching enclave_os_common::protocol)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Data(Vec<u8>),
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Data(Vec<u8>),
    Ok,
    Error(Vec<u8>),
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

        let server_name: ServerName<'static> = host
            .to_string()
            .try_into()
            .unwrap_or_else(|_| ServerName::IpAddress(host.parse().expect("invalid host")));

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

    /// Send a Ping request and expect Pong.
    pub fn ping(&mut self) -> io::Result<bool> {
        let payload = serde_json::to_vec(&"Ping").unwrap();
        self.send_frame(&payload)?;
        let resp_raw = self.recv_frame()?;
        let resp: serde_json::Value = serde_json::from_slice(&resp_raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(resp == "Pong")
    }

    /// Send Data(payload) and return the response bytes.
    pub fn send_data(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let req = Request::Data(data.to_vec());
        let payload = serde_json::to_vec(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.send_frame(&payload)?;

        let resp_raw = self.recv_frame()?;
        let resp: Response = serde_json::from_slice(&resp_raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        match resp {
            Response::Data(d) => Ok(d),
            Response::Error(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                String::from_utf8_lossy(&e).to_string(),
            )),
            other => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unexpected response: {:?}", other),
            )),
        }
    }

    fn send_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = encode_frame(payload);
        self.stream.write_all(&frame)?;
        self.stream.flush()
    }

    fn recv_frame(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let mut data = Vec::new();
        loop {
            let n = self.stream.read(&mut buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection closed",
                ));
            }
            data.extend_from_slice(&buf[..n]);
            if let Some((payload, _consumed)) = decode_frame(&data) {
                return Ok(payload);
            }
        }
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
        if q.oid == OID_SGX_QUOTE && q.raw.len() >= sgx_quote::MIN_SIZE {
            println!("    MRENCLAVE : {}", hex::encode(&q.raw[sgx_quote::MRENCLAVE]));
            println!("    MRSIGNER  : {}", hex::encode(&q.raw[sgx_quote::MRSIGNER]));
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
        println!("  ** DCAP Quote Verification **");
        println!("    Status    : {}", qv.status);
        if let Some(ref d) = qv.tcb_date {
            println!("    TCB Date  : {}", d);
        }
        if !qv.advisory_ids.is_empty() {
            println!("    Advisories: {}", qv.advisory_ids.join(", "));
        }
    }
}
