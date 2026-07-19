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

/// ALPN protocol identifier advertised by every RA-TLS-capable client.
/// The Privasys gateway inspects the ClientHello: connections that
/// advertise this token are spliced (pure L4, the enclave terminates
/// RA-TLS); all others are terminated by the gateway with its public
/// Let's Encrypt cert and forwarded over an internal RA-TLS leg.
pub const RATLS_ALPN_PROTO: &[u8] = b"privasys-ratls/1";

/// Intel SGX Quote  (enclave-os-mini)
pub const OID_SGX_QUOTE: &str = "1.2.840.113741.1.13.1.0";
/// Intel TDX Quote  (enclave-os-virtual / TDX VMs)
pub const OID_TDX_QUOTE: &str = "1.2.840.113741.1.5.5.1.6";
/// AMD SEV-SNP Attestation Report
pub const OID_SEV_SNP_REPORT: &str = "1.3.6.1.4.1.65230.4.1";
/// NVIDIA GPU Attestation Evidence
pub const OID_NVIDIA_GPU_EVIDENCE: &str = "1.3.6.1.4.1.65230.5.1";

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
/// Image build profile — "production" or "dev", from the dm-verity
/// measured marker /etc/privasys/image-profile.
pub const OID_IMAGE_PROFILE: &str = "1.3.6.1.4.1.65230.2.8";
/// Per-workload config Merkle root.
pub const OID_WORKLOAD_CONFIG_MERKLE_ROOT: &str = "1.3.6.1.4.1.65230.3.1";
/// Per-workload code/image hash.
pub const OID_WORKLOAD_CODE_HASH: &str = "1.3.6.1.4.1.65230.3.2";
/// Per-workload image ref (Virtual only).
pub const OID_WORKLOAD_IMAGE_REF: &str = "1.3.6.1.4.1.65230.3.3";
/// Per-workload key source / volume encryption.
pub const OID_WORKLOAD_KEY_SOURCE: &str = "1.3.6.1.4.1.65230.3.4";
/// Per-workload management app-id — the stable identifier a caller resolves to
/// a published app + publisher. Matches the enclave-side APP_ID / MR_APP
/// extension. A dependent uses it to select which dependency entry applies.
pub const OID_WORKLOAD_APP_ID: &str = "1.3.6.1.4.1.65230.3.6";
/// Carries a workload's set of DIRECT attested cross-enclave dependencies (the
/// identities it is pinned to and will only complete an RA-TLS handshake with).
/// Written by the trusted runtime, never by the app. The value is the canonical
/// encoding produced by `dependencies::encode_dependency_set`.
pub const OID_ATTESTED_DEPENDENCY_SET: &str = "1.3.6.1.4.1.65230.6.1";

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
    OID_IMAGE_PROFILE,
    OID_WORKLOAD_CONFIG_MERKLE_ROOT,
    OID_WORKLOAD_CODE_HASH,
    OID_WORKLOAD_IMAGE_REF,
    OID_WORKLOAD_KEY_SOURCE,
    OID_WORKLOAD_APP_ID,
    OID_ATTESTED_DEPENDENCY_SET,
];

/// Map OID dotted-string → human label.
pub fn oid_label(oid: &str) -> &'static str {
    match oid {
        OID_SGX_QUOTE => "SGX Quote",
        OID_TDX_QUOTE => "TDX Quote",
        OID_SEV_SNP_REPORT => "SEV-SNP Report",
        OID_NVIDIA_GPU_EVIDENCE => "NVIDIA GPU Evidence",
        OID_CONFIG_MERKLE_ROOT => "Config Merkle Root",
        OID_EGRESS_CA_HASH => "Egress CA Hash",
        OID_RUNTIME_VERSION_HASH => "Runtime Version Hash",
        OID_COMBINED_WORKLOADS_HASH => "Combined Workloads Hash",
        OID_DEK_ORIGIN => "DEK Origin",
        OID_ATTESTATION_SERVERS_HASH => "Attestation Servers Hash",
        OID_IMAGE_PROFILE => "Image Profile",
        OID_WORKLOAD_CONFIG_MERKLE_ROOT => "Workload Config Merkle Root",
        OID_WORKLOAD_CODE_HASH => "Workload Code Hash",
        OID_WORKLOAD_IMAGE_REF => "Workload Image Ref",
        OID_WORKLOAD_KEY_SOURCE => "Workload Key Source",
        OID_WORKLOAD_APP_ID => "Workload App ID",
        OID_ATTESTED_DEPENDENCY_SET => "Attested Dependency Set",
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

/// AMD SEV-SNP Attestation Report layout.
/// Report size: 0x4A0 = 1184 bytes.
pub mod sev_snp_report {
    pub const MIN_SIZE: usize = 0x4A0;
    pub const REPORT_DATA: std::ops::Range<usize> = 0x050..0x090;
    pub const MEASUREMENT: std::ops::Range<usize> = 0x090..0x0C0;
    pub const HOST_DATA: std::ops::Range<usize> = 0x0C0..0x0E0;
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
    SevSnp,
    NvidiaGpu,
}

/// How the verifier reproduces the quote's 64-byte `ReportData`.
///
/// Both modes compute `SHA-512( SHA-256(pubkey) || binding )`.
///
/// | TEE | Pubkey | Deterministic binding | Challenge binding |
/// |-----|--------|-----------------------|-------------------|
/// | SGX | Full SPKI DER (91 B) | *skipped* (creation_time not in cert) | Client nonce |
/// | TDX | Full SPKI DER (91 B) | `NotBefore` as `"YYYY-MM-DDTHH:MMZ"` | Client nonce |
/// | SEV-SNP | Full SPKI DER (91 B) | — | Client nonce |
/// | NVIDIA GPU | — | — | — |
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
    /// Expected MEASUREMENT (SEV-SNP, 48 bytes). `None` = skip.
    pub measurement: Option<[u8; 48]>,
    /// Expected HOST_DATA (SEV-SNP, 32 bytes). `None` = skip.
    pub host_data: Option<[u8; 32]>,
    /// How to verify the quote's ReportData field.
    pub report_data: ReportDataMode,
    /// Expected custom OID values to verify.
    pub expected_oids: Vec<ExpectedOid>,
    /// Optional remote quote verification configuration.
    pub quote_verification: Option<QuoteVerificationConfig>,
    /// Accept certificates whose Image Profile extension (OID
    /// 1.3.6.1.4.1.65230.2.8) is not "production" (e.g. "dev" images
    /// built with SSH and debug tools). Must stay `false` in
    /// production. The check fails closed: any unknown profile value is
    /// rejected. Certificates without the extension (images predating
    /// the marker) are accepted.
    pub allow_debug_images: bool,
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

/// Decide whether a newly-seen attestation extension should become the
/// certificate's `quote`, given whatever quote was already selected.
///
/// A confidential-GPU enclave presents BOTH a platform TEE quote
/// (SGX/TDX/SEV-SNP, which carries the measurements) and opaque NVIDIA GPU
/// evidence. Only the TEE quote has an mrenclave/mrtd/report_data layout, so
/// it must win regardless of the order the extensions appear in the cert.
/// GPU evidence never displaces a TEE quote; a TEE quote replaces a previously
/// selected GPU-only placeholder.
fn quote_candidate_wins(current: Option<&QuoteInfo>, candidate_oid: &str) -> bool {
    let candidate_is_gpu = candidate_oid == OID_NVIDIA_GPU_EVIDENCE;
    let have_tee_quote = current.map_or(false, |q| q.oid != OID_NVIDIA_GPU_EVIDENCE);
    !(candidate_is_gpu && have_tee_quote)
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

    // Walk extensions for RA-TLS OIDs.
    //
    // A single certificate can carry MORE than one attestation extension: a
    // confidential-GPU enclave (e.g. confidential-ai on a TDX+H100 host)
    // presents BOTH a platform TEE quote (SGX/TDX/SEV-SNP — the extension
    // that actually carries mrenclave/mrtd) AND opaque NVIDIA GPU evidence.
    // The measurement-bearing TEE quote must win regardless of the order the
    // extensions appear in. GPU evidence has no mr* layout, so letting it
    // overwrite the TEE quote strips the measurements — the caller then sees
    // an attested cert with no mrtd, which the wallet's session-relay gate
    // reports as "did not present an attested certificate". Keep the TEE
    // quote; never let GPU evidence displace it, but do let a TEE quote
    // replace a GPU-only placeholder if the GPU extension came first.
    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == OID_SGX_QUOTE || oid_str == OID_TDX_QUOTE || oid_str == OID_SEV_SNP_REPORT || oid_str == OID_NVIDIA_GPU_EVIDENCE {
            if !quote_candidate_wins(info.quote.as_ref(), &oid_str) {
                continue;
            }
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
    } else if oid == OID_SEV_SNP_REPORT && raw.len() >= 4 {
        q.version = Some(u16::from_le_bytes([raw[0], raw[1]]));
        if raw.len() >= sev_snp_report::MIN_SIZE {
            q.report_data = Some(raw[sev_snp_report::REPORT_DATA].to_vec());
        }
    } else if oid == OID_NVIDIA_GPU_EVIDENCE {
        // NVIDIA GPU evidence is opaque; no standard binary layout.
    }

    q
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

/// Category of an RA-TLS verification failure, so a caller can tell a definite
/// bad verdict (show the problem, allow an explicit override) from an
/// inconclusive one (attestation service unreachable — offer to continue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyErrorKind {
    /// Bad caller input (policy/JSON/arguments). A programming error, not
    /// something the user should be asked to override.
    Config,
    /// Could not connect to, or complete the TLS handshake with, the enclave.
    /// There is nothing to proceed to — retry, don't override.
    Connection,
    /// A quote was present but failed a local check: missing/mock quote, wrong
    /// TEE family, measurement mismatch, `report_data`/channel-binder mismatch,
    /// a disallowed image profile, or an expected-OID mismatch. A definite
    /// negative verdict.
    QuoteInvalid,
    /// The attestation service was unreachable, timed out, or returned a
    /// response we could not interpret — no clear verdict either way.
    AsUnreachable,
    /// The attestation service returned a clear negative verdict (an HTTP error
    /// status, or a non-accepted quote status). A definite negative verdict.
    AsRejected,
}

impl VerifyErrorKind {
    /// Stable lowercase token surfaced across the FFI boundary.
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyErrorKind::Config => "config",
            VerifyErrorKind::Connection => "connection",
            VerifyErrorKind::QuoteInvalid => "quote_invalid",
            VerifyErrorKind::AsUnreachable => "as_unreachable",
            VerifyErrorKind::AsRejected => "as_rejected",
        }
    }
}

/// An RA-TLS verification failure carrying its [`VerifyErrorKind`] category.
#[derive(Debug, Clone)]
pub struct VerifyError {
    pub kind: VerifyErrorKind,
    pub message: String,
}

impl VerifyError {
    pub fn new(kind: VerifyErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Verify an RA-TLS certificate against a [`VerificationPolicy`].
///
/// Returns `Ok(CertInfo)` with parsed certificate data on success, or
/// `Err(description)` if any policy check fails.
pub fn verify_ratls_cert(der: &[u8], policy: &VerificationPolicy) -> Result<CertInfo, String> {
    verify_ratls_cert_bound(der, policy, None)
}

/// Like [`verify_ratls_cert`], but also verifies RA-TLS channel binding.
///
/// In challenge mode the enclave folds the TLS session `channel_binder` (a
/// 32-byte value derived from the shared handshake key schedule, obtained from
/// [`RaTlsClient`] after the handshake) into the quote's `report_data`. Pass it
/// here so a relayed or co-located quote — one that cannot commit to this TLS
/// session — fails closed. Deterministic mode ignores the binder; challenge
/// mode requires it.
pub fn verify_ratls_cert_bound(
    der: &[u8],
    policy: &VerificationPolicy,
    channel_binder: Option<&[u8]>,
) -> Result<CertInfo, String> {
    verify_ratls_cert_bound_typed(der, policy, channel_binder).map_err(|e| e.message)
}

/// Like [`verify_ratls_cert_bound`], but returns a categorised [`VerifyError`]
/// so the caller can distinguish a definite bad verdict (invalid quote, or the
/// attestation service rejecting it) from an inconclusive one (the attestation
/// service being unreachable). Every local check maps to
/// [`VerifyErrorKind::QuoteInvalid`]; the remote attestation-service call
/// carries its own [`VerifyErrorKind::AsUnreachable`]/[`VerifyErrorKind::AsRejected`].
pub fn verify_ratls_cert_bound_typed(
    der: &[u8],
    policy: &VerificationPolicy,
    channel_binder: Option<&[u8]>,
) -> Result<CertInfo, VerifyError> {
    let bad = |m: String| VerifyError::new(VerifyErrorKind::QuoteInvalid, m);
    let info = inspect_der_certificate(der);

    // 1. Quote must be present
    let quote = info.quote.clone()
        .ok_or_else(|| bad("no RA-TLS attestation quote in certificate".into()))?;
    if quote.is_mock {
        return Err(bad("certificate contains a MOCK quote".into()));
    }

    // 2. Correct TEE type
    match policy.tee {
        TeeType::Sgx => {
            if quote.oid != OID_SGX_QUOTE {
                return Err(bad(format!(
                    "expected SGX quote ({}), found {}",
                    OID_SGX_QUOTE, quote.oid
                )));
            }
        }
        TeeType::Tdx => {
            if quote.oid != OID_TDX_QUOTE {
                return Err(bad(format!(
                    "expected TDX quote ({}), found {}",
                    OID_TDX_QUOTE, quote.oid
                )));
            }
        }
        TeeType::SevSnp => {
            if quote.oid != OID_SEV_SNP_REPORT {
                return Err(bad(format!(
                    "expected SEV-SNP report ({}), found {}",
                    OID_SEV_SNP_REPORT, quote.oid
                )));
            }
        }
        TeeType::NvidiaGpu => {
            if quote.oid != OID_NVIDIA_GPU_EVIDENCE {
                return Err(bad(format!(
                    "expected NVIDIA GPU evidence ({}), found {}",
                    OID_NVIDIA_GPU_EVIDENCE, quote.oid
                )));
            }
        }
    }

    // 3. Measurement registers
    verify_measurements(&quote.raw, policy).map_err(bad)?;

    // 4. ReportData
    verify_report_data(der, &quote.raw, policy, channel_binder).map_err(bad)?;

    // 5. Image profile (reject dev/debug images unless opted in)
    verify_image_profile(&info.custom_oids, policy).map_err(bad)?;

    // 6. Custom OID values
    verify_expected_oids(&info.custom_oids, &policy.expected_oids).map_err(bad)?;

    // 7. Remote quote verification. Its error already carries the right kind
    // (unreachable vs rejected), so it propagates unchanged.
    let mut info = info;
    if let Some(ref config) = policy.quote_verification {
        info.quote_verification = Some(verify_quote(&quote.raw, config)?);
    }

    Ok(info)
}

/// Reject non-production image profiles unless explicitly allowed.
///
/// The Image Profile extension (OID 1.3.6.1.4.1.65230.2.8) carries the
/// VM image build flavor, read from a marker inside the dm-verity
/// measured rootfs: "production" (no SSH, no debug tools) or "dev"
/// (openssh + debug tools). Fail-closed: any value other than
/// "production" counts as a debug image. Certificates without the
/// extension (images predating the marker) are accepted.
fn verify_image_profile(
    actual: &[OidExtension],
    policy: &VerificationPolicy,
) -> Result<(), String> {
    for ext in actual {
        if ext.oid != OID_IMAGE_PROFILE {
            continue;
        }
        let profile = String::from_utf8_lossy(&ext.value);
        let profile = profile.trim();
        if profile != "production" && !policy.allow_debug_images {
            return Err(format!(
                "server runs a {:?} image (OID {}): debug/dev images are \
                 rejected unless VerificationPolicy.allow_debug_images is set",
                profile, OID_IMAGE_PROFILE
            ));
        }
        return Ok(());
    }
    Ok(())
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
        TeeType::SevSnp => {
            if raw.len() < sev_snp_report::MIN_SIZE {
                return Err(format!(
                    "SEV-SNP report too small: {} < {}",
                    raw.len(),
                    sev_snp_report::MIN_SIZE
                ));
            }
            if let Some(expected) = &policy.measurement {
                let actual = &raw[sev_snp_report::MEASUREMENT];
                if actual != expected.as_slice() {
                    return Err(format!(
                        "MEASUREMENT mismatch: got {}, expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ));
                }
            }
            if let Some(expected) = &policy.host_data {
                let actual = &raw[sev_snp_report::HOST_DATA];
                if actual != expected.as_slice() {
                    return Err(format!(
                        "HOST_DATA mismatch: got {}, expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ));
                }
            }
        }
        TeeType::NvidiaGpu => {
            // NVIDIA GPU evidence is verified remotely; no local measurement check.
        }
    }
    Ok(())
}

/// Verify the quote ReportData field.
fn verify_report_data(
    der: &[u8],
    raw: &[u8],
    policy: &VerificationPolicy,
    channel_binder: Option<&[u8]>,
) -> Result<(), String> {
    let binding = match &policy.report_data {
        ReportDataMode::Skip => return Ok(()),
        ReportDataMode::Deterministic => {
            // NVIDIA GPU evidence carries no ReportData bound to the TLS key
            // (the GPU quote is not bound to the CPU-side certificate), so there
            // is nothing to reconstruct. This is an explicit, unverified gap —
            // a GPU deterministic pass is NOT a key-to-quote binding, and callers
            // must not treat it as one.
            if policy.tee == TeeType::NvidiaGpu {
                return Ok(());
            }
            // SGX and TDX: binding is NotBefore formatted as "YYYY-MM-DDTHH:MMZ".
            // Both issuers set NotBefore to the minute-truncated creation time.
            let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der)
                .map_err(|e| format!("parse cert: {e}"))?;
            let ts = cert.validity().not_before.to_datetime();
            // ts.month() is `time::Month` whose Display prints "May"; cast to u8.
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}Z",
                ts.year(),
                ts.month() as u8,
                ts.day(),
                ts.hour(),
                ts.minute()
            )
            .into_bytes()
        }
        ReportDataMode::ChallengeResponse { nonce } => {
            // Channel binding is mandatory in challenge mode: the enclave folds
            // the 32-byte TLS session binder (derived from the shared handshake
            // key schedule) into report_data alongside the nonce. Recompute WITH
            // the binder so a relayed or co-located quote — which cannot commit
            // to this TLS session — fails closed. The binder is only available
            // after the handshake, so this must run post-handshake.
            let binder = channel_binder.ok_or_else(|| {
                "challenge mode requires the TLS channel binder (fail closed)".to_string()
            })?;
            let mut b = nonce.clone();
            b.extend_from_slice(binder);
            b
        }
    };

    // Extract the public key
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der)
        .map_err(|e| format!("parse cert: {e}"))?;
    let pubkey_bytes = cert.public_key().subject_public_key.data.to_vec();

    // Build the same input the enclave used: SHA-512( SHA-256(SPKI_DER) || binding ).
    // SPKI is the full 91-byte SubjectPublicKeyInfo (Go's x509.MarshalPKIXPublicKey,
    // matching standard X.509 viewers' "Public Key SHA-256" fingerprint).
    let pubkey_input = match policy.tee {
        TeeType::Sgx | TeeType::Tdx | TeeType::SevSnp => {
            build_p256_spki_der(&pubkey_bytes)
        }
        TeeType::NvidiaGpu => {
            return Ok(());
        }
    };

    // NVIDIA GPU CC evidence fold: when the certificate carries GPU evidence
    // (OID 5.1), the enclave binds ReportData as
    //   SHA-512( SHA-256(pubkey) || binding || SHA-256(evidence) )
    // to prove CPU<->GPU co-location. A verifier that omits the fold rejects a
    // correctly-bound GPU enclave on a ReportData mismatch. Gated on the
    // extension, so non-GPU certificates are byte-for-byte unchanged.
    let mut binding = binding;
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == OID_NVIDIA_GPU_EVIDENCE {
            let ev_hash = digest::digest(&digest::SHA256, ext.value);
            binding.extend_from_slice(ev_hash.as_ref());
            break;
        }
    }

    let expected = compute_report_data_hash(&pubkey_input, &binding);

    // Get actual ReportData from quote
    let actual_range = match policy.tee {
        TeeType::Sgx => {
            let format = detect_sgx_format(raw);
            let (_, _, rd_range, _) = sgx_offsets(format);
            rd_range
        }
        TeeType::Tdx => tdx_quote::REPORT_DATA,
        TeeType::SevSnp => sev_snp_report::REPORT_DATA,
        TeeType::NvidiaGpu => return Ok(()),
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
/// enclave-os-virtual.
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
) -> Result<QuoteVerificationResult, VerifyError> {
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
            // The service answered, but with an error status — a clear verdict.
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                VerifyError::new(VerifyErrorKind::AsRejected, format!(
                    "quote verification failed: HTTP {} — {}",
                    code,
                    if body.is_empty() { "(empty body)".to_string() } else { body }
                ))
            }
            // Transport failure (DNS, connect, timeout, TLS) — no verdict.
            other => VerifyError::new(VerifyErrorKind::AsUnreachable,
                format!("quote verification request failed: {}", other)),
        }
    })?;

    // A response we cannot interpret is not a verdict — treat as unreachable so
    // the caller offers a continue/bypass rather than a hard rejection.
    let resp_body: serde_json::Value = resp
        .into_json()
        .map_err(|e| VerifyError::new(VerifyErrorKind::AsUnreachable,
            format!("failed to parse quote verification response: {}", e)))?;

    let status_str = resp_body["status"]
        .as_str()
        .ok_or_else(|| VerifyError::new(VerifyErrorKind::AsUnreachable,
            "quote verification response missing 'status' field".to_string()))?;
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
        // The service gave a clear negative verdict on the quote's TCB status.
        return Err(VerifyError::new(VerifyErrorKind::AsRejected, format!(
            "quote verification failed: status={}, advisories={:?}",
            result.status, result.advisory_ids
        )));
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
    host: String,
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
    fn finish_connect(host: &str, port: u16, mut config: ClientConfig) -> io::Result<Self> {
        // Advertise the Privasys RA-TLS marker first so gateways that
        // front enclave hosts know to *splice* the connection (pure L4
        // forwarding) instead of terminating with their public LE cert.
        // Then advertise `http/1.1` so the actual TLS server on the
        // spliced upstream — typically Caddy in enclave-os-virtual,
        // whose default NextProtos is `["h2", "http/1.1"]` — can
        // negotiate a real HTTP version. Without `http/1.1`, TLS 1.3
        // strict ALPN sends `no_application_protocol` because the
        // marker is not in the server's list.
        //
        // We deliberately do NOT advertise `h2`: this client uses
        // `ureq` which is HTTP/1.1 only. If we offered `h2` first
        // Caddy would pick it (its own preference is `h2` ahead of
        // `http/1.1`), then ureq would speak HTTP/1.1 over the
        // h2-negotiated connection and Caddy would close mid-request
        // (observed as "connection closed before HTTP headers" on
        // /__privasys/session-bootstrap with wallet 1.2.16).
        //
        // ALPN-aware clients (this library, its FFI consumers — wallet,
        // mobile RA-TLS clients, the management service) all do this;
        // browsers and other plain TLS clients don't advertise the
        // marker and get the terminate path so they see a public cert.
        let wants = [RATLS_ALPN_PROTO, b"http/1.1".as_slice()];
        for (i, proto) in wants.iter().enumerate() {
            if !config
                .alpn_protocols
                .iter()
                .any(|p| p.as_slice() == *proto)
            {
                // Preserve relative order of newly inserted protocols
                // (marker first, then http/1.1) while leaving any
                // caller-supplied entries intact.
                let insert_at = i.min(config.alpn_protocols.len());
                config.alpn_protocols.insert(insert_at, proto.to_vec());
            }
        }

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
            host: host.to_string(),
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
    ///
    /// In challenge mode the quote's `report_data` commits to this TLS session
    /// via the channel binder derived from our own handshake key schedule, so
    /// the check is done here (post-handshake), where the binder is available.
    pub fn verify_certificate(&self, policy: &VerificationPolicy) -> Result<CertInfo, String> {
        self.verify_certificate_typed(policy).map_err(|e| e.message)
    }

    /// Typed variant of [`verify_certificate`]: returns a categorised
    /// [`VerifyError`] so a caller can tell a definite bad verdict from an
    /// unreachable attestation service and offer the right recovery.
    pub fn verify_certificate_typed(
        &self,
        policy: &VerificationPolicy,
    ) -> Result<CertInfo, VerifyError> {
        let der = self
            .peer_certs
            .first()
            .ok_or_else(|| VerifyError::new(VerifyErrorKind::Connection, "no peer certificate"))?;
        let binder = self.stream.conn.ratls_channel_binder();
        verify_ratls_cert_bound_typed(der, policy, binder.as_ref().map(|b| b.as_slice()))
    }

    /// Cheap, network-free check that the peer's leaf certificate carries a
    /// genuine quote whose `report_data` binds this certificate's public key in
    /// DETERMINISTIC mode. Used on the data plane (every request/post) so the
    /// transport is never blind to an unbound or swapped certificate. The TEE
    /// family is inferred from the quote's OID. There is no attestation-service
    /// call and no measurement pinning here — those belong to the verification
    /// gate; this is only the key-to-quote binding.
    pub fn check_report_data_deterministic(&self) -> Result<(), VerifyError> {
        let der = self
            .peer_certs
            .first()
            .ok_or_else(|| VerifyError::new(VerifyErrorKind::Connection, "no peer certificate"))?;
        let info = inspect_der_certificate(der);
        // A certificate with no RA-TLS quote is a non-enclave backend — the
        // portal / IdP behind a public CA cert, or a plain FIDO2 relying party
        // like github.com. There is nothing to bind, and rejecting it here would
        // break every non-enclave data-plane call. Whether a non-enclave peer is
        // acceptable is the caller's decision (the sign-in flow explicitly
        // supports non-enclave RPs); we only enforce the binding when a quote is
        // actually present, so a genuine enclave cert can't be silently swapped.
        let quote = match info.quote.as_ref() {
            Some(q) => q,
            None => return Ok(()),
        };
        if quote.is_mock {
            return Err(VerifyError::new(
                VerifyErrorKind::QuoteInvalid,
                "certificate contains a MOCK quote",
            ));
        }
        let tee = match quote.oid.as_str() {
            OID_SGX_QUOTE => TeeType::Sgx,
            OID_TDX_QUOTE => TeeType::Tdx,
            OID_SEV_SNP_REPORT => TeeType::SevSnp,
            OID_NVIDIA_GPU_EVIDENCE => TeeType::NvidiaGpu,
            other => {
                return Err(VerifyError::new(
                    VerifyErrorKind::QuoteInvalid,
                    format!("unknown quote OID: {other}"),
                ))
            }
        };
        let policy = VerificationPolicy {
            tee,
            mr_enclave: None,
            mr_signer: None,
            mr_td: None,
            measurement: None,
            host_data: None,
            report_data: ReportDataMode::Deterministic,
            expected_oids: Vec::new(),
            quote_verification: None,
            allow_debug_images: true,
        };
        verify_report_data(der, &quote.raw, &policy, None)
            .map_err(|m| VerifyError::new(VerifyErrorKind::QuoteInvalid, m))
    }

    // -- HTTP/1.1 protocol ---------------------------------------------------

    fn send_http_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        auth_token: Option<&str>,
        extra_headers: Option<&[(String, String)]>,
        connection_close: bool,
    ) -> io::Result<()> {
        let mut header = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", method, path, self.host);
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
        // Caller-supplied headers (e.g. X-Privasys-Voucher). Names and values are
        // sanitised to a single header line each so a value can never inject
        // additional CRLF-separated headers or a body.
        if let Some(headers) = extra_headers {
            for (name, value) in headers {
                let clean_name: String =
                    name.chars().filter(|c| *c != '\r' && *c != '\n' && *c != ':').collect();
                let clean_value: String =
                    value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
                if !clean_name.is_empty() {
                    header.push_str(&format!("{}: {}\r\n", clean_name, clean_value));
                }
            }
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
        self.send_http_request("GET", "/healthz", None, None, None, false)?;
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
        self.send_http_request("GET", "/readyz", None, auth_token, None, false)?;
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
        self.send_http_request("GET", "/status", None, auth_token, None, false)?;
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
        self.send_http_request("GET", "/metrics", None, auth_token, None, false)?;
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
        self.send_http_request("POST", "/data", Some(data), auth_token, None, false)?;
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
        self.send_http_request("PUT", "/attestation-servers", Some(&body), auth_token, None, false)?;
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
        self.send_http_request("POST", "/shutdown", None, auth_token, None, true)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("shutdown failed ({}): {}", status, String::from_utf8_lossy(&body)),
            ));
        }
        Ok(())
    }

    /// Generic HTTP request with an arbitrary method (GET, POST, PUT,
    /// DELETE, …) to an arbitrary path over the RA-TLS connection. A
    /// `None` body sends no body (correct for GET/DELETE); a `Some`
    /// body is sent with `Content-Type: application/json`. Returns
    /// (status_code, response_body).
    pub fn http_request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        auth_token: Option<&str>,
        extra_headers: Option<&[(String, String)]>,
    ) -> io::Result<(u16, Vec<u8>)> {
        self.send_http_request(method, path, body, auth_token, extra_headers, true)?;
        self.recv_http_response()
    }

    /// Generic HTTP POST to an arbitrary path over the RA-TLS connection.
    /// Returns (status_code, response_body). Thin wrapper over
    /// `http_request` kept for existing callers.
    pub fn http_post(
        &mut self,
        path: &str,
        body: &[u8],
        auth_token: Option<&str>,
        extra_headers: Option<&[(String, String)]>,
    ) -> io::Result<(u16, Vec<u8>)> {
        self.http_request("POST", path, Some(body), auth_token, extra_headers)
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

// ---------------------------------------------------------------------------
//  Attested cross-enclave dependencies
// ---------------------------------------------------------------------------
//
// A workload that depends on other enclaves (for example a service that calls a
// confidential-inference enclave) is pinned to a fixed set of dependency
// identities. The runtime carries that set in the certificate extension
// `OID_ATTESTED_DEPENDENCY_SET` (65230.6.1) and refuses, fail-closed, to complete
// an RA-TLS handshake with a peer that does not match the pinned identity for the
// dependency being dialled. The extension is written by the trusted runtime, so
// the advertised set and the enforced set are one object.
//
// A dependency identity is the SAME tuple used to verify any app — measurement
// registers plus required OID values. Verification therefore reuses the ordinary
// certificate matcher (`super::verify_measurements` / `super::verify_expected_oids`),
// not a parallel one.
//
// Depth soundness comes from the identity fold: a dependency entry commits to the
// dependency's OWN dependency set via `folded_identity`, so a change deep in the
// tree changes the identity a dependent is pinned to. Enforcement stays a single
// direct-edge check at every hop; the recursion lives in the pinned identity, not
// in the verifier. See [`fold_identity`].
//
// This is a byte-for-byte cross-language wire contract: the canonical encoding and
// the fold preimage are reproduced identically in the Go/Python/TypeScript/C#
// SDKs, so an OID value or a folded identity produced by one SDK verifies in any
// other.
pub mod dependencies {
    use super::{
        digest, CertInfo, ExpectedOid, ReportDataMode, TeeType, VerificationPolicy,
        OID_WORKLOAD_APP_ID,
    };

    /// Separates the fold preimage from any other SHA-256 use.
    const DOMAIN_FOLD_IDENTITY: &str = "privasys-app-identity-v1";

    /// A TDX measurement triple (all lowercase hex).
    #[derive(Debug, Clone)]
    pub struct DepTdxMeasurement {
        pub mrtd: String,
        pub rtmr1: String,
        pub rtmr2: String,
    }

    /// One allowed measurement for a dependency, mirroring the vault's
    /// `Measurement` enum. Exactly one of SGX / TDX applies.
    #[derive(Debug, Clone)]
    pub enum DepMeasurement {
        /// A lowercase-hex MRENCLAVE (SGX enclaves).
        Sgx(String),
        /// An MRTD+RTMR triple (TDX VMs).
        Tdx(DepTdxMeasurement),
    }

    impl DepMeasurement {
        /// Stable string form used for sorting and for the fold preimage.
        /// Identical across SDKs.
        pub fn canonical(&self) -> String {
            match self {
                DepMeasurement::Tdx(t) => format!(
                    "tdx:{}:{}:{}",
                    t.mrtd.to_lowercase(),
                    t.rtmr1.to_lowercase(),
                    t.rtmr2.to_lowercase()
                ),
                DepMeasurement::Sgx(s) => format!("sgx:{}", s.to_lowercase()),
            }
        }
    }

    /// Pins one DIRECT dependency: the identity a dependent enclave is allowed to
    /// talk to for that dependency app.
    #[derive(Debug, Clone)]
    pub struct DependencyEntry {
        /// Management app-id of the dependency (matches the peer's
        /// `OID_WORKLOAD_APP_ID` value). Selects which entry applies to the peer
        /// being dialled, and the key the wallet caches an approval under.
        pub app_id: String,
        /// Any-of set of allowed measurement registers. A peer matches when it
        /// satisfies at least one.
        pub measurements: Vec<DepMeasurement>,
        /// OID values the peer's certificate must carry verbatim (typically code
        /// hash 65230.3.2 and app-id 65230.3.6).
        pub required_oids: Vec<ExpectedOid>,
        /// Lowercase-hex commitment to THIS dependency's own transitive
        /// dependency subtree (its [`fold_identity`] output). Empty for a leaf
        /// dependency. Because a parent folds this value in, a change anywhere in
        /// the subtree changes the parent's pinned identity.
        pub folded_identity: String,
    }

    /// A workload's ordered set of direct attested dependencies.
    #[derive(Debug, Clone, Default)]
    pub struct DependencySet {
        pub entries: Vec<DependencyEntry>,
    }

    // -- canonical, length-prefixed byte grammar (big-endian u32 lengths) -------

    fn w_u32(buf: &mut Vec<u8>, n: usize) {
        buf.extend_from_slice(&(n as u32).to_be_bytes());
    }

    fn w_bytes(buf: &mut Vec<u8>, b: &[u8]) {
        w_u32(buf, b.len());
        buf.extend_from_slice(b);
    }

    fn w_str(buf: &mut Vec<u8>, s: &str) {
        w_bytes(buf, s.as_bytes());
    }

    /// Append the normalised canonical bytes of `set` to `buf`. Normalisation
    /// sorts entries by app-id, each entry's measurements by canonical form, and
    /// required OIDs by (oid, value), so the output is independent of declaration
    /// order.
    fn write_canonical(set: &DependencySet, buf: &mut Vec<u8>) {
        let mut entries = set.entries.clone();
        for e in entries.iter_mut() {
            e.measurements
                .sort_by(|a, b| a.canonical().cmp(&b.canonical()));
            e.required_oids.sort_by(|a, b| {
                a.oid
                    .cmp(&b.oid)
                    .then_with(|| a.expected_value.cmp(&b.expected_value))
            });
        }
        entries.sort_by(|a, b| a.app_id.cmp(&b.app_id));

        w_u32(buf, entries.len());
        for e in &entries {
            w_str(buf, &e.app_id);
            w_u32(buf, e.measurements.len());
            for m in &e.measurements {
                w_str(buf, &m.canonical());
            }
            w_u32(buf, e.required_oids.len());
            for o in &e.required_oids {
                w_str(buf, &o.oid);
                w_bytes(buf, &o.expected_value);
            }
            w_str(buf, &e.folded_identity.to_lowercase());
        }
    }

    /// The canonical byte encoding placed in the `OID_ATTESTED_DEPENDENCY_SET`
    /// certificate extension. Deterministic: the same logical set always encodes
    /// to the same bytes regardless of declaration order.
    pub fn encode_dependency_set(set: &DependencySet) -> Vec<u8> {
        let mut buf = Vec::new();
        write_canonical(set, &mut buf);
        buf
    }

    fn r_u32(b: &[u8], off: &mut usize) -> Result<u32, String> {
        if *off + 4 > b.len() {
            return Err("dependency-set encoding truncated".to_string());
        }
        let v = u32::from_be_bytes([b[*off], b[*off + 1], b[*off + 2], b[*off + 3]]);
        *off += 4;
        Ok(v)
    }

    fn r_bytes(b: &[u8], off: &mut usize) -> Result<Vec<u8>, String> {
        let n = r_u32(b, off)? as usize;
        if *off + n > b.len() {
            return Err("dependency-set encoding truncated".to_string());
        }
        let out = b[*off..*off + n].to_vec();
        *off += n;
        Ok(out)
    }

    fn r_str(b: &[u8], off: &mut usize) -> Result<String, String> {
        let bytes = r_bytes(b, off)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Parse the canonical encoding. Measurement and OID-value details collapse to
    /// their canonical string forms; intended for inspection and round-trip checks,
    /// not for reconstructing typed measurements (verification uses the encoded
    /// bytes and the live certificate).
    pub fn decode_dependency_set(b: &[u8]) -> Result<DependencySet, String> {
        let mut off = 0usize;
        let n = r_u32(b, &mut off)?;
        let mut set = DependencySet {
            entries: Vec::with_capacity(n as usize),
        };
        for _ in 0..n {
            let app_id = r_str(b, &mut off)?;
            let mc = r_u32(b, &mut off)?;
            let mut measurements = Vec::with_capacity(mc as usize);
            for _ in 0..mc {
                let s = r_str(b, &mut off)?;
                measurements.push(decode_canonical_measurement(&s));
            }
            let oc = r_u32(b, &mut off)?;
            let mut required_oids = Vec::with_capacity(oc as usize);
            for _ in 0..oc {
                let oid = r_str(b, &mut off)?;
                let value = r_bytes(b, &mut off)?;
                required_oids.push(ExpectedOid {
                    oid,
                    expected_value: value,
                });
            }
            let folded_identity = r_str(b, &mut off)?;
            set.entries.push(DependencyEntry {
                app_id,
                measurements,
                required_oids,
                folded_identity,
            });
        }
        if off != b.len() {
            return Err("trailing bytes in dependency-set encoding".to_string());
        }
        Ok(set)
    }

    fn decode_canonical_measurement(s: &str) -> DepMeasurement {
        if let Some(rest) = s.strip_prefix("tdx:") {
            let parts: Vec<&str> = rest.split(':').collect();
            DepMeasurement::Tdx(DepTdxMeasurement {
                mrtd: parts.first().copied().unwrap_or("").to_string(),
                rtmr1: parts.get(1).copied().unwrap_or("").to_string(),
                rtmr2: parts.get(2).copied().unwrap_or("").to_string(),
            })
        } else {
            DepMeasurement::Sgx(s.strip_prefix("sgx:").unwrap_or(s).to_string())
        }
    }

    /// Compute a workload's folded identity:
    ///
    /// ```text
    /// identity(X) = SHA-256( domain || measurements(X) || requiredOids(X) || encode(deps(X)) )
    /// ```
    ///
    /// Because `deps(X)` carries each direct dependency's own `folded_identity`,
    /// the result transitively commits to the entire dependency subtree while every
    /// hop verifies only its direct edges. A dependent pins X by this value, so any
    /// change beneath X changes what the dependent accepts and forces re-approval.
    ///
    /// `own_measurements` are the workload's own measurement registers (canonical
    /// form, e.g. [`DepMeasurement::canonical`]); `own_required_oids` are its own
    /// pinned OID values.
    pub fn fold_identity(
        own_measurements: &[String],
        own_required_oids: &[ExpectedOid],
        deps: &DependencySet,
    ) -> [u8; 32] {
        let mut buf = Vec::new();
        w_str(&mut buf, DOMAIN_FOLD_IDENTITY);

        let mut ms: Vec<String> = own_measurements.iter().map(|m| m.to_lowercase()).collect();
        ms.sort();
        w_u32(&mut buf, ms.len());
        for m in &ms {
            w_str(&mut buf, m);
        }

        let mut os: Vec<ExpectedOid> = own_required_oids.to_vec();
        os.sort_by(|a, b| {
            a.oid
                .cmp(&b.oid)
                .then_with(|| a.expected_value.cmp(&b.expected_value))
        });
        w_u32(&mut buf, os.len());
        for o in &os {
            w_str(&mut buf, &o.oid);
            w_bytes(&mut buf, &o.expected_value);
        }

        write_canonical(deps, &mut buf);

        let d = digest::digest(&digest::SHA256, &buf);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }

    /// [`fold_identity`] as lowercase hex, the form stored in
    /// [`DependencyEntry::folded_identity`].
    pub fn fold_identity_hex(
        own_measurements: &[String],
        own_required_oids: &[ExpectedOid],
        deps: &DependencySet,
    ) -> String {
        hex::encode(fold_identity(own_measurements, own_required_oids, deps))
    }

    /// Build a single-measurement [`VerificationPolicy`] so [`match_dependency`]
    /// can reuse [`super::verify_measurements`] for each allowed measurement.
    fn measurement_policy(tee: TeeType, m: &DepMeasurement) -> Result<VerificationPolicy, String> {
        let mut pol = VerificationPolicy {
            tee,
            mr_enclave: None,
            mr_signer: None,
            mr_td: None,
            measurement: None,
            host_data: None,
            report_data: ReportDataMode::Skip,
            expected_oids: Vec::new(),
            quote_verification: None,
            allow_debug_images: false,
        };
        match tee {
            TeeType::Sgx => {
                let sgx = match m {
                    DepMeasurement::Sgx(s) => s.as_str(),
                    // TEE says SGX but the measurement is TDX: no MRENCLAVE to pin.
                    DepMeasurement::Tdx(_) => "",
                };
                let b = hex::decode(sgx)
                    .map_err(|_| format!("invalid SGX MRENCLAVE {:?}", sgx))?;
                if b.len() != 32 {
                    return Err(format!("invalid SGX MRENCLAVE {:?}", sgx));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                pol.mr_enclave = Some(arr);
            }
            TeeType::Tdx => {
                let t = match m {
                    DepMeasurement::Tdx(t) => t,
                    DepMeasurement::Sgx(_) => {
                        return Err("TDX measurement missing MRTD triple".to_string())
                    }
                };
                let b = hex::decode(&t.mrtd)
                    .map_err(|_| format!("invalid TDX MRTD {:?}", t.mrtd))?;
                if b.len() != 48 {
                    return Err(format!("invalid TDX MRTD {:?}", t.mrtd));
                }
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&b);
                pol.mr_td = Some(arr);
            }
            _ => return Err("unsupported TEE type for dependency measurement".to_string()),
        }
        Ok(pol)
    }

    /// Whether a peer certificate satisfies a single dependency entry: its
    /// measurement registers match at least one allowed measurement AND every
    /// required OID is present verbatim. Returns `Ok(())` on a match and a
    /// descriptive error otherwise. Fail-closed — this is the check the dialling
    /// runtime runs before sending any application data to a dependency.
    ///
    /// Reuses the ordinary certificate matcher rather than a parallel verifier, so
    /// a dependency is verified exactly as any app.
    pub fn match_dependency(
        peer: &CertInfo,
        tee: TeeType,
        entry: &DependencyEntry,
    ) -> Result<(), String> {
        let quote = match &peer.quote {
            Some(q) if !q.raw.is_empty() => q,
            _ => {
                return Err(format!(
                    "dependency {}: peer certificate carries no quote (fail closed)",
                    entry.app_id
                ))
            }
        };
        if entry.measurements.is_empty() {
            return Err(format!(
                "dependency {}: entry pins no measurement (fail closed)",
                entry.app_id
            ));
        }

        let mut matched = false;
        let mut last_err = String::new();
        for m in &entry.measurements {
            match measurement_policy(tee, m) {
                Err(e) => {
                    last_err = e;
                    continue;
                }
                Ok(pol) => match super::verify_measurements(&quote.raw, &pol) {
                    Ok(()) => {
                        matched = true;
                        break;
                    }
                    Err(e) => last_err = e,
                },
            }
        }
        if !matched {
            return Err(format!(
                "dependency {}: peer matches no pinned measurement (fail closed): {}",
                entry.app_id, last_err
            ));
        }

        super::verify_expected_oids(&peer.custom_oids, &entry.required_oids)
            .map_err(|e| format!("dependency {}: {}", entry.app_id, e))?;
        Ok(())
    }

    /// The peer's management app-id (`OID_WORKLOAD_APP_ID`) or "" when absent. A
    /// dependent uses it to select which dependency entry applies to a peer.
    pub fn app_id_from_cert(peer: &CertInfo) -> String {
        for o in &peer.custom_oids {
            if o.oid == OID_WORKLOAD_APP_ID {
                return String::from_utf8_lossy(&o.value).into_owned();
            }
        }
        String::new()
    }

    /// Enforce the whole set: select the entry whose `app_id` matches the peer's
    /// app-id (`OID_WORKLOAD_APP_ID`) and require the peer to match it. A peer whose
    /// app-id is not a declared dependency is rejected — a dependent talks only to
    /// enclaves it has pinned. This is the top-level fail-closed gate.
    pub fn verify_peer_is_dependency(
        peer: &CertInfo,
        tee: TeeType,
        set: &DependencySet,
    ) -> Result<(), String> {
        let app_id = app_id_from_cert(peer);
        if app_id.is_empty() {
            return Err(format!(
                "peer certificate carries no app-id (OID {}); cannot match a declared dependency (fail closed)",
                OID_WORKLOAD_APP_ID
            ));
        }
        for e in &set.entries {
            if e.app_id == app_id {
                return match_dependency(peer, tee, e);
            }
        }
        Err(format!(
            "peer app-id {} is not a declared dependency (fail closed)",
            app_id
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            quote_candidate_wins, sgx_report, OidExtension, QuoteInfo, OID_NVIDIA_GPU_EVIDENCE,
            OID_SGX_QUOTE, OID_TDX_QUOTE, OID_WORKLOAD_CODE_HASH,
        };

        /// Build a `CertInfo` whose quote is a raw SGX report carrying `mrenclave`,
        /// plus the given custom OID extensions. Mirrors a real dependency peer.
        fn sgx_peer(mrenclave: &[u8], oids: Vec<OidExtension>) -> CertInfo {
            let mut raw = vec![0u8; sgx_report::SIZE];
            raw[sgx_report::MRENCLAVE].copy_from_slice(mrenclave);
            CertInfo {
                subject: String::new(),
                issuer: String::new(),
                serial: String::new(),
                not_before: String::new(),
                not_after: String::new(),
                sig_algo: String::new(),
                quote: Some(QuoteInfo {
                    oid: OID_SGX_QUOTE.to_string(),
                    label: String::new(),
                    critical: false,
                    raw,
                    is_mock: false,
                    version: None,
                    report_data: None,
                }),
                custom_oids: oids,
                quote_verification: None,
            }
        }

        fn mre(b: u8) -> Vec<u8> {
            vec![b; 32]
        }

        fn oid(o: &str, v: &[u8]) -> ExpectedOid {
            ExpectedOid {
                oid: o.to_string(),
                expected_value: v.to_vec(),
            }
        }

        fn ext(o: &str, v: &[u8]) -> OidExtension {
            OidExtension {
                oid: o.to_string(),
                label: String::new(),
                value: v.to_vec(),
            }
        }

        fn tee_quote(oid: &str) -> QuoteInfo {
            QuoteInfo {
                oid: oid.to_string(),
                label: String::new(),
                critical: false,
                raw: Vec::new(),
                is_mock: false,
                version: None,
                report_data: None,
            }
        }

        #[test]
        fn tee_quote_beats_gpu_evidence_regardless_of_order() {
            // A confidential-GPU enclave (e.g. confidential-ai on TDX+H100)
            // carries BOTH a TDX quote and NVIDIA GPU evidence. Only the TDX
            // quote holds mrtd, so it must be the selected quote whichever
            // order the extensions appear in — otherwise the wallet's
            // session-relay gate sees no measurements ("did not present an
            // attested certificate").

            // GPU evidence must NOT displace an already-selected TEE quote
            // (the real cert order: TDX first, GPU second).
            let tdx = tee_quote(OID_TDX_QUOTE);
            assert!(
                !quote_candidate_wins(Some(&tdx), OID_NVIDIA_GPU_EVIDENCE),
                "GPU evidence wrongly displaced the TDX quote"
            );

            // A TEE quote MUST replace a GPU-only placeholder (GPU first).
            let gpu = tee_quote(OID_NVIDIA_GPU_EVIDENCE);
            assert!(
                quote_candidate_wins(Some(&gpu), OID_TDX_QUOTE),
                "TDX quote failed to replace GPU-only placeholder"
            );

            // First quote of any kind always wins when none is selected yet.
            assert!(quote_candidate_wins(None, OID_TDX_QUOTE));
            assert!(quote_candidate_wins(None, OID_NVIDIA_GPU_EVIDENCE));
        }

        #[test]
        fn encode_dependency_set_deterministic() {
            // Same logical content, different declaration order (entries,
            // measurements, and required OIDs all shuffled) must encode equal.
            let a = DependencySet {
                entries: vec![
                    DependencyEntry {
                        app_id: "bbb".into(),
                        measurements: vec![
                            DepMeasurement::Sgx("22".into()),
                            DepMeasurement::Sgx("11".into()),
                        ],
                        required_oids: vec![
                            oid(OID_WORKLOAD_APP_ID, b"bbb"),
                            oid(OID_WORKLOAD_CODE_HASH, b"hashB"),
                        ],
                        folded_identity: String::new(),
                    },
                    DependencyEntry {
                        app_id: "aaa".into(),
                        measurements: vec![DepMeasurement::Sgx("33".into())],
                        required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, b"hashA")],
                        folded_identity: String::new(),
                    },
                ],
            };
            let b = DependencySet {
                entries: vec![
                    DependencyEntry {
                        app_id: "aaa".into(),
                        measurements: vec![DepMeasurement::Sgx("33".into())],
                        required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, b"hashA")],
                        folded_identity: String::new(),
                    },
                    DependencyEntry {
                        app_id: "bbb".into(),
                        measurements: vec![
                            DepMeasurement::Sgx("11".into()),
                            DepMeasurement::Sgx("22".into()),
                        ],
                        required_oids: vec![
                            oid(OID_WORKLOAD_CODE_HASH, b"hashB"),
                            oid(OID_WORKLOAD_APP_ID, b"bbb"),
                        ],
                        folded_identity: String::new(),
                    },
                ],
            };
            assert_eq!(
                encode_dependency_set(&a),
                encode_dependency_set(&b),
                "encoding is not order-independent"
            );
        }

        #[test]
        fn dependency_set_round_trip() {
            let set = DependencySet {
                entries: vec![DependencyEntry {
                    app_id: "confidential-ai".into(),
                    measurements: vec![
                        DepMeasurement::Sgx("abcd".into()),
                        DepMeasurement::Tdx(DepTdxMeasurement {
                            mrtd: "aa".into(),
                            rtmr1: "bb".into(),
                            rtmr2: "cc".into(),
                        }),
                    ],
                    required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, &[0xde, 0xad])],
                    folded_identity: "00ff".into(),
                }],
            };
            let dec = decode_dependency_set(&encode_dependency_set(&set)).expect("decode");
            assert_eq!(
                encode_dependency_set(&dec),
                encode_dependency_set(&set),
                "round-trip changed the canonical encoding"
            );
        }

        #[test]
        fn decode_rejects_truncated() {
            let enc = encode_dependency_set(&DependencySet {
                entries: vec![DependencyEntry {
                    app_id: "x".into(),
                    measurements: vec![DepMeasurement::Sgx("11".into())],
                    required_oids: vec![],
                    folded_identity: String::new(),
                }],
            });
            assert!(
                decode_dependency_set(&enc[..enc.len() - 1]).is_err(),
                "expected error on truncated encoding"
            );
        }

        #[test]
        fn fold_identity_ripples_on_nested_change() {
            // A depends on B. B's own subtree changes (its folded_identity moves).
            // A's folded identity MUST change even though A's own code/measurement
            // did not — the depth-soundness property.
            let own = vec![format!("sgx:{}", hex::encode(mre(0xA1)))];
            let own_oids = vec![oid(OID_WORKLOAD_CODE_HASH, b"A-code")];

            let dep_b = |folded: &str| DependencySet {
                entries: vec![DependencyEntry {
                    app_id: "B".into(),
                    measurements: vec![DepMeasurement::Sgx(hex::encode(mre(0xB2)))],
                    required_oids: vec![oid(OID_WORKLOAD_APP_ID, b"B")],
                    folded_identity: folded.to_string(),
                }],
            };

            let id1 = fold_identity_hex(&own, &own_oids, &dep_b("1111"));
            let id2 = fold_identity_hex(&own, &own_oids, &dep_b("2222"));
            assert_ne!(
                id1, id2,
                "folded identity did not ripple when a nested dependency changed"
            );

            assert_eq!(
                fold_identity_hex(&own, &own_oids, &dep_b("1111")),
                id1,
                "folded identity is not stable for identical inputs"
            );
        }

        #[test]
        fn match_dependency_accepts_pinned_peer() {
            let mre_b = mre(0xB2);
            let peer = sgx_peer(
                &mre_b,
                vec![
                    ext(OID_WORKLOAD_APP_ID, b"B"),
                    ext(OID_WORKLOAD_CODE_HASH, b"B-code"),
                ],
            );
            let entry = DependencyEntry {
                app_id: "B".into(),
                measurements: vec![DepMeasurement::Sgx(hex::encode(&mre_b))],
                required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, b"B-code")],
                folded_identity: String::new(),
            };
            match_dependency(&peer, TeeType::Sgx, &entry).expect("expected match");
        }

        #[test]
        fn match_dependency_fails_closed_on_measurement_mismatch() {
            // Rogue measurement.
            let peer = sgx_peer(&mre(0xEE), vec![ext(OID_WORKLOAD_CODE_HASH, b"B-code")]);
            let entry = DependencyEntry {
                app_id: "B".into(),
                measurements: vec![DepMeasurement::Sgx(hex::encode(mre(0xB2)))],
                required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, b"B-code")],
                folded_identity: String::new(),
            };
            assert!(
                match_dependency(&peer, TeeType::Sgx, &entry).is_err(),
                "expected fail-closed on measurement mismatch"
            );
        }

        #[test]
        fn match_dependency_fails_closed_on_missing_oid() {
            let mre_b = mre(0xB2);
            // Code hash absent.
            let peer = sgx_peer(&mre_b, vec![ext(OID_WORKLOAD_APP_ID, b"B")]);
            let entry = DependencyEntry {
                app_id: "B".into(),
                measurements: vec![DepMeasurement::Sgx(hex::encode(&mre_b))],
                required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, b"B-code")],
                folded_identity: String::new(),
            };
            assert!(
                match_dependency(&peer, TeeType::Sgx, &entry).is_err(),
                "expected fail-closed on missing required OID"
            );
        }

        #[test]
        fn match_dependency_fails_closed_without_quote() {
            let peer = CertInfo {
                subject: String::new(),
                issuer: String::new(),
                serial: String::new(),
                not_before: String::new(),
                not_after: String::new(),
                sig_algo: String::new(),
                quote: None,
                custom_oids: vec![ext(OID_WORKLOAD_CODE_HASH, b"B-code")],
                quote_verification: None,
            };
            let entry = DependencyEntry {
                app_id: "B".into(),
                measurements: vec![DepMeasurement::Sgx(hex::encode(mre(0xB2)))],
                required_oids: vec![],
                folded_identity: String::new(),
            };
            assert!(
                match_dependency(&peer, TeeType::Sgx, &entry).is_err(),
                "expected fail-closed when peer carries no quote"
            );
        }

        #[test]
        fn verify_peer_is_dependency_accepts_and_rejects() {
            let mre_b = mre(0xB2);
            let set = DependencySet {
                entries: vec![DependencyEntry {
                    app_id: "B".into(),
                    measurements: vec![DepMeasurement::Sgx(hex::encode(&mre_b))],
                    required_oids: vec![oid(OID_WORKLOAD_CODE_HASH, b"B-code")],
                    folded_identity: String::new(),
                }],
            };

            let good = sgx_peer(
                &mre_b,
                vec![
                    ext(OID_WORKLOAD_APP_ID, b"B"),
                    ext(OID_WORKLOAD_CODE_HASH, b"B-code"),
                ],
            );
            verify_peer_is_dependency(&good, TeeType::Sgx, &set)
                .expect("expected declared dependency to verify");

            // A genuine enclave with a valid quote but an app-id we never pinned.
            let rogue = sgx_peer(&mre(0xCC), vec![ext(OID_WORKLOAD_APP_ID, b"C")]);
            assert!(
                verify_peer_is_dependency(&rogue, TeeType::Sgx, &set).is_err(),
                "expected fail-closed for an undeclared dependency app-id"
            );

            // No app-id at all.
            let anon = sgx_peer(&mre_b, vec![]);
            assert!(
                verify_peer_is_dependency(&anon, TeeType::Sgx, &set).is_err(),
                "expected fail-closed when peer has no app-id"
            );
        }
    }
}
