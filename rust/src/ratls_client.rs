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

mod oids_gen;
pub use oids_gen::*;

pub mod attest;
pub use attest::{
    check_quote_time, client_report_data, expected_report_data, parse_quote_time,
    quote_report_data, tee_type_of, AttestationMode, ClientEvidence, ClientEvidenceRequest,
    ClientEvidenceSource, Evidence, Framing, ATTEST_PATH, CONTEXT_LEN, EXPORTER_LABEL_CLIENT,
    EXPORTER_LABEL_SERVER, HCTX_LEN, MAX_FRAME, PROTOCOL_VERSION, QUOTE_TIME_LEN,
};

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
    // The TDREPORT td_info places MRCONFIGID / MROWNER / MROWNERCONFIG
    // (3 × 48 B) after MRTD, then RTMR0..3 (4 × 48 B), then REPORT_DATA.
    // The platform-runtime measurements the session-relay enc_pub is pinned
    // to (management-service ensureSessionRelayKey hashes MRTD|RTMR1|RTMR2)
    // live in RTMR1/RTMR2: RTMR1 = 424..472, RTMR2 = 472..520, and
    // 520 + 48 = 568 = REPORT_DATA, which anchors the offsets.
    pub const RTMR1: std::ops::Range<usize> = 424..472;
    pub const RTMR2: std::ops::Range<usize> = 472..520;
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
fn sgx_offsets(
    format: SgxQuoteFormat,
) -> (
    std::ops::Range<usize>,
    std::ops::Range<usize>,
    std::ops::Range<usize>,
    usize,
) {
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
    /// Opt-in client-side enforcement of the server's Intel `tcbStatus` against the
    /// secure floor (UpToDate, SWHardeningNeeded) + `acceptable_tcb_statuses`. Default
    /// false so rebuilding against a server that newly reports tcbStatus does not
    /// silently start rejecting previously-accepted platforms. The status is always
    /// parsed into the result; only rejection is gated.
    pub enforce_tcb_status: bool,
    /// Intel TCB statuses accepted in addition to the secure floor (e.g.
    /// "ConfigurationAndSWHardeningNeeded"). Only consulted when `enforce_tcb_status`.
    /// "Revoked" is never accepted, even if listed.
    pub acceptable_tcb_statuses: Vec<String>,
    /// HTTP request timeout in seconds (default: 10).
    pub timeout_secs: u64,
}

/// Returns true if `status` is in the secure TCB floor (accepted without relaxation).
fn tcb_in_secure_floor(status: &str) -> bool {
    matches!(status, "UpToDate" | "SWHardeningNeeded")
}

/// Checks a reported Intel TCB status against the secure floor + caller relaxations.
/// Empty (server didn't report) is Ok; Revoked is never Ok; floor statuses are Ok;
/// anything else must appear in `acceptable`.
fn tcb_status_acceptable(status: &str, acceptable: &[String]) -> Result<(), String> {
    if status.is_empty() {
        return Ok(());
    }
    if status == "Revoked" {
        return Err("TCB status Revoked is never acceptable".to_string());
    }
    if tcb_in_secure_floor(status) {
        return Ok(());
    }
    if acceptable.iter().any(|s| s == status) {
        return Ok(());
    }
    Err(format!(
        "TCB status {:?} not accepted: not in the secure floor and not in the configured acceptable set",
        status
    ))
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
    /// Intel platform TCB status (the server's `tcbStatus`), when reported.
    pub tcb_status: Option<String>,
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
    /// Expected custom OID values to verify.
    pub expected_oids: Vec<ExpectedOid>,
    /// Optional remote quote verification configuration.
    pub quote_verification: Option<QuoteVerificationConfig>,
    /// Accept certificates whose Image Profile extension (OID
    /// 1.3.6.1.4.1.65230.1.2) is not "production" (e.g. "dev" images
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
    /// A v1 certificate: attestation evidence carried as a certificate
    /// extension. A v2 verifier fails closed on it.
    pub v1_leaf: bool,
    /// The evidence body verified for the connection (RA-TLS v2: from the
    /// attest response, never from the certificate). `None` until
    /// verification ran with evidence; on a `v1_leaf` the unverified
    /// extension, for display only.
    pub quote: Option<QuoteInfo>,
    /// NVIDIA GPU CC evidence of the attest response, when present.
    pub gpu_evidence: Option<Vec<u8>>,
    /// The mode the evidence was obtained in; `None` when the connection
    /// carries no evidence.
    pub attestation: AttestationMode,
    /// The full evidence record after verification succeeded.
    pub evidence: Option<Evidence>,
    /// Privasys configuration OIDs found in the certificate.
    pub custom_oids: Vec<OidExtension>,
    /// Result of remote quote verification (populated during verify).
    pub quote_verification: Option<QuoteVerificationResult>,
}

impl CertInfo {
    /// An empty summary (no certificate).
    pub fn empty() -> Self {
        CertInfo {
            subject: String::new(),
            issuer: String::new(),
            serial: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            sig_algo: String::new(),
            v1_leaf: false,
            quote: None,
            gpu_evidence: None,
            attestation: AttestationMode::None,
            evidence: None,
            custom_oids: Vec::new(),
            quote_verification: None,
        }
    }
}

/// Inspect a DER-encoded certificate for RA-TLS extensions.
///
/// A v2 leaf carries Privasys OIDs and no evidence. A leaf that carries an
/// Intel-arc quote extension is a v1 leaf: it is flagged (`v1_leaf`) and its
/// quote is parsed for display only; a v2 verifier rejects it.
pub fn inspect_der_certificate(der: &[u8]) -> CertInfo {
    use x509_parser::prelude::*;

    let mut info = CertInfo::empty();

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

    for ext in cert.extensions() {
        let oid_str = ext.oid.to_id_string();
        if oid_str == OID_SGX_QUOTE || oid_str == OID_TDX_QUOTE {
            info.v1_leaf = true;
            info.quote = Some(parse_quote(&oid_str, ext.critical, ext.value));
        } else if oid_str.starts_with(OID_PRIVASYS_ARC_PREFIX) {
            // Everything under the Privasys arc, including the open-ended
            // app-defined 5.4.* extensions (an exact-match allowlist silently
            // dropped those, found 2026-08-01).
            info.custom_oids.push(OidExtension {
                oid: oid_str.clone(),
                label: oid_label(&oid_str),
                value: ext.value.to_vec(),
            });
        }
    }

    info
}

fn parse_quote(oid: &str, critical: bool, raw: &[u8]) -> QuoteInfo {
    let mut q = QuoteInfo {
        oid: oid.to_string(),
        label: oid_label(oid),
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

/// The [`QuoteInfo`] of an attest-response quote.
fn quote_info_of(ev: &Evidence) -> QuoteInfo {
    let oid = match ev.tee.as_str() {
        "tdx" | "tdx-gpu" => OID_EVIDENCE_TDX_QUOTE,
        "sev-snp" => OID_EVIDENCE_SEV_SNP_REPORT,
        _ => OID_EVIDENCE_SGX_QUOTE,
    };
    QuoteInfo {
        oid: oid.to_string(),
        label: oid_label(oid),
        critical: false,
        raw: ev.quote.clone(),
        is_mock: ev.quote.starts_with(b"MOCK_QUOTE:"),
        version: if ev.quote.len() >= 2 {
            Some(u16::from_le_bytes([ev.quote[0], ev.quote[1]]))
        } else {
            None
        },
        report_data: quote_report_data(&ev.tee, &ev.quote)
            .ok()
            .map(|r| r.to_vec()),
    }
}

/// The DER `SubjectPublicKeyInfo` of a certificate (91 bytes for P-256), the
/// input of every `report_data` recipe.
pub fn spki_der_of(der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der)
        .map_err(|e| format!("parse cert: {e}"))?;
    Ok(build_p256_spki_der(
        &cert.public_key().subject_public_key.data,
    ))
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
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Verify a v2 leaf against the certificate part of a policy only: v2 shape
/// (no evidence in the certificate), image profile and expected OIDs. It
/// proves nothing about the TEE; callers that need evidence use
/// [`verify_evidence`] or [`RaTlsClient::verify_certificate`].
pub fn verify_certificate_extensions(
    der: &[u8],
    policy: &VerificationPolicy,
) -> Result<CertInfo, VerifyError> {
    let bad = |m: String| VerifyError::new(VerifyErrorKind::QuoteInvalid, m);
    let info = inspect_der_certificate(der);
    if info.v1_leaf {
        return Err(bad(
            "v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier".into(),
        ));
    }
    verify_image_profile(&info.custom_oids, policy).map_err(bad)?;
    verify_expected_oids(&info.custom_oids, &policy.expected_oids).map_err(bad)?;
    Ok(info)
}

/// Verify the evidence obtained for the connection whose leaf is `der`
/// against `policy`. See [`verify_evidence_typed`].
pub fn verify_evidence(
    der: &[u8],
    ev: &Evidence,
    policy: &VerificationPolicy,
) -> Result<CertInfo, String> {
    verify_evidence_typed(der, ev, policy).map_err(|e| e.message)
}

/// Verify the evidence `ev` obtained for the connection whose leaf is `der`,
/// against `policy`, in this order: v2 leaf shape, evidence family against
/// `policy.tee`, measurement registers, `report_data` (predicted from the leaf
/// SPKI and `ev`, never taken from the peer), image profile, expected OIDs,
/// then the attestation server (quote signature and TCB, GPU verdict).
///
/// Every local check maps to [`VerifyErrorKind::QuoteInvalid`]; the remote
/// attestation-service call carries its own
/// [`VerifyErrorKind::AsUnreachable`] / [`VerifyErrorKind::AsRejected`].
pub fn verify_evidence_typed(
    der: &[u8],
    ev: &Evidence,
    policy: &VerificationPolicy,
) -> Result<CertInfo, VerifyError> {
    let bad = |m: String| VerifyError::new(VerifyErrorKind::QuoteInvalid, m);
    let mut info = inspect_der_certificate(der);
    if info.v1_leaf {
        return Err(bad(
            "v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier".into(),
        ));
    }
    if ev.quote.starts_with(b"MOCK_QUOTE:") {
        return Err(bad("evidence is a MOCK quote".into()));
    }

    // 1. Evidence family against the policy.
    let tee =
        tee_type_of(&ev.tee).ok_or_else(|| bad(format!("unknown evidence family {:?}", ev.tee)))?;
    if policy.tee == TeeType::NvidiaGpu {
        return Err(bad(
            "TeeType::NvidiaGpu is not a primary evidence family in RA-TLS v2; verify a tdx-gpu connection with TeeType::Tdx".into(),
        ));
    }
    if tee != policy.tee {
        return Err(bad(format!(
            "expected {:?} evidence, got {}",
            policy.tee, ev.tee
        )));
    }
    if ev.tee == "tdx-gpu" && ev.gpu_evidence.as_deref().map_or(true, |g| g.is_empty()) {
        return Err(bad("tdx-gpu evidence without gpu_evidence".into()));
    }

    // 2. Measurement registers.
    verify_measurements(&ev.quote, policy).map_err(bad)?;

    // 3. report_data: predicted from the leaf and the evidence.
    let spki = spki_der_of(der).map_err(bad)?;
    let expected = expected_report_data(&spki, ev).map_err(bad)?;
    let actual = quote_report_data(&ev.tee, &ev.quote).map_err(bad)?;
    if actual != expected.as_slice() {
        return Err(bad(format!(
            "report_data mismatch ({} mode):\n  got:      {}\n  expected: {}",
            ev.mode,
            hex::encode(actual),
            hex::encode(expected)
        )));
    }

    // 4. Certificate extensions.
    verify_image_profile(&info.custom_oids, policy).map_err(bad)?;
    verify_expected_oids(&info.custom_oids, &policy.expected_oids).map_err(bad)?;

    info.quote = Some(quote_info_of(ev));
    info.gpu_evidence = ev.gpu_evidence.clone();
    info.attestation = ev.mode;
    info.evidence = Some(ev.clone());

    // 5. Attestation server: quote signature, collateral, TCB; GPU verdict.
    if let Some(ref config) = policy.quote_verification {
        info.quote_verification =
            Some(verify_quote(&ev.quote, ev.gpu_evidence.as_deref(), config)?);
    }

    Ok(info)
}

/// Reject non-production image profiles unless explicitly allowed.
///
/// The Image Profile extension (OID 1.3.6.1.4.1.65230.1.2) carries the
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
                    raw.len(),
                    min_sz
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

/// Verify that each expected custom OID matches a certificate extension.
fn verify_expected_oids(actual: &[OidExtension], expected: &[ExpectedOid]) -> Result<(), String> {
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

/// Verify the raw quote against a remote quote verification service.
fn verify_quote(
    quote_raw: &[u8],
    gpu_evidence: Option<&[u8]>,
    config: &QuoteVerificationConfig,
) -> Result<QuoteVerificationResult, VerifyError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // Combined CPU + NVIDIA GPU attestation: the server verifies both the TDX
    // quote and the GPU evidence (genuine device, CC mode, nonce-bound report)
    // in one "tdx-gpu" request.
    let body = match gpu_evidence.filter(|g| !g.is_empty()) {
        Some(gpu) => serde_json::json!({
            "quote": STANDARD.encode(quote_raw),
            "type": "tdx-gpu",
            "gpuQuote": STANDARD.encode(gpu),
        }),
        None => serde_json::json!({
            "quote": STANDARD.encode(quote_raw),
        }),
    };

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
                VerifyError::new(
                    VerifyErrorKind::AsRejected,
                    format!(
                        "quote verification failed: HTTP {} — {}",
                        code,
                        if body.is_empty() {
                            "(empty body)".to_string()
                        } else {
                            body
                        }
                    ),
                )
            }
            // Transport failure (DNS, connect, timeout, TLS) — no verdict.
            other => VerifyError::new(
                VerifyErrorKind::AsUnreachable,
                format!("quote verification request failed: {}", other),
            ),
        }
    })?;

    // A response we cannot interpret is not a verdict — treat as unreachable so
    // the caller offers a continue/bypass rather than a hard rejection.
    let resp_body: serde_json::Value = resp.into_json().map_err(|e| {
        VerifyError::new(
            VerifyErrorKind::AsUnreachable,
            format!("failed to parse quote verification response: {}", e),
        )
    })?;

    let status_str = resp_body["status"].as_str().ok_or_else(|| {
        VerifyError::new(
            VerifyErrorKind::AsUnreachable,
            "quote verification response missing 'status' field".to_string(),
        )
    })?;
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
    let tcb_status = resp_body["tcbStatus"].as_str().map(String::from);

    let result = QuoteVerificationResult {
        status,
        tcb_date,
        advisory_ids,
        tcb_status,
    };

    if gpu_evidence.is_some() {
        let gpu = &resp_body["gpuAttestation"];
        if gpu.is_null() {
            return Err(VerifyError::new(
                VerifyErrorKind::AsUnreachable,
                "tdx-gpu verification: server returned no GPU attestation result".to_string(),
            ));
        }
        if gpu["verified"].as_bool() != Some(true) {
            return Err(VerifyError::new(
                VerifyErrorKind::AsRejected,
                format!(
                    "GPU attestation failed: status={} error={}",
                    gpu["status"].as_str().unwrap_or(""),
                    gpu["error"].as_str().unwrap_or("")
                ),
            ));
        }
    }

    if result.status != QuoteVerificationStatus::Ok
        && !config.accepted_statuses.contains(&result.status)
    {
        // The service gave a clear negative verdict on the quote's TCB status.
        return Err(VerifyError::new(
            VerifyErrorKind::AsRejected,
            format!(
                "quote verification failed: status={}, advisories={:?}",
                result.status, result.advisory_ids
            ),
        ));
    }

    // Opt-in Intel TCB-status enforcement (secure floor + relaxations; Revoked never
    // accepted). Client-side defence in depth.
    if config.enforce_tcb_status {
        if let Err(msg) = tcb_status_acceptable(
            result.tcb_status.as_deref().unwrap_or(""),
            &config.acceptable_tcb_statuses,
        ) {
            return Err(VerifyError::new(
                VerifyErrorKind::AsRejected,
                format!(
                    "quote verification failed: {} (advisories={:?})",
                    msg, result.advisory_ids
                ),
            ));
        }
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
//  Fleet trust anchors: the presented chain must reach a Privasys CA
// ---------------------------------------------------------------------------

/// Every enclave enrolled on the Privasys platform serves an RA-TLS leaf
/// issued by the Privasys Intermediate CA of its environment (production or
/// development), staged into the enclave at approval time. Requiring the
/// presented chain to reach one of these anchors confines acceptance to
/// enclaves Privasys provisioned: a genuine TEE elsewhere running the same
/// measured image, or one whose attestation key has leaked, cannot present
/// a leaf that chains here. The quote checks (measurements, OIDs,
/// `report_data` binding) are unchanged; the chain check is a
/// fleet-membership check layered on top of them.
///
/// Hostname verification is deliberately not part of the chain check:
/// RA-TLS peers are commonly dialled by IP, and the identity a relying
/// party cares about is the quote and the app identity in the certificate,
/// not the DNS name.
pub mod fleet {
    use std::io;
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::client::WebPkiServerVerifier;
    use rustls::crypto::ring::default_provider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

    /// Privasys production intermediate CA (PEM).
    pub const PRIVASYS_INTERMEDIATE_CA_PEM: &str =
        include_str!("anchors/privasys-intermediate-ca.pem");
    /// Privasys development intermediate CA (PEM).
    pub const PRIVASYS_INTERMEDIATE_CA_DEV_PEM: &str =
        include_str!("anchors/privasys-intermediate-ca-dev.pem");

    fn add_pem(store: &mut RootCertStore, pem: &[u8]) -> io::Result<usize> {
        let certs = rustls_pemfile::certs(&mut &pem[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let n = certs.len();
        for cert in certs {
            store
                .add(cert)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?;
        }
        Ok(n)
    }

    /// The embedded Privasys trust anchors (production and development
    /// intermediate CAs).
    pub fn privasys_trust_anchors() -> io::Result<Arc<RootCertStore>> {
        let mut store = RootCertStore::empty();
        add_pem(&mut store, PRIVASYS_INTERMEDIATE_CA_PEM.as_bytes())?;
        add_pem(&mut store, PRIVASYS_INTERMEDIATE_CA_DEV_PEM.as_bytes())?;
        Ok(Arc::new(store))
    }

    /// Trust anchors from a PEM file (every certificate in the file, root or
    /// intermediate, becomes an anchor).
    pub fn trust_anchors_from_file(path: &str) -> io::Result<Arc<RootCertStore>> {
        let pem = std::fs::read(path)?;
        let mut store = RootCertStore::empty();
        if add_pem(&mut store, &pem)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no PEM certificate in CA cert file {}", path),
            ));
        }
        Ok(Arc::new(store))
    }

    /// Verifies the server chain against the anchors, ignoring the name
    /// check (the leaf may be dialled by IP). Signature checks are
    /// delegated to the webpki verifier unchanged.
    #[derive(Debug)]
    pub struct FleetVerifier {
        inner: Arc<WebPkiServerVerifier>,
    }

    impl FleetVerifier {
        pub fn new(anchors: Arc<RootCertStore>) -> io::Result<Self> {
            let inner =
                WebPkiServerVerifier::builder_with_provider(anchors, Arc::new(default_provider()))
                    .build()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))?;
            Ok(Self { inner })
        }
    }

    impl ServerCertVerifier for FleetVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            match self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Ok(v) => Ok(v),
                Err(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                    | CertificateError::NotValidForNameContext { .. },
                )) => Ok(ServerCertVerified::assertion()),
                Err(e) => Err(e),
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    /// The public PKI roots (Mozilla's bundle via `webpki-roots`), for
    /// connections that ask for no evidence and reach a host that is not an
    /// enclave (the identity provider, for instance).
    pub fn public_trust_anchors() -> Arc<RootCertStore> {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(store)
    }

    /// Standard verification against the public PKI roots, hostname
    /// included (what a browser does).
    pub fn public_verifier() -> io::Result<Arc<WebPkiServerVerifier>> {
        WebPkiServerVerifier::builder_with_provider(
            public_trust_anchors(),
            Arc::new(default_provider()),
        )
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{:?}", e)))
    }

    /// Accepts a chain that reaches the fleet anchors (no name check) or
    /// verifies against the public PKI with the name check: the chain policy
    /// of an unattested connection under [`super::TrustSelection::Auto`].
    #[derive(Debug)]
    pub struct EitherVerifier {
        fleet: FleetVerifier,
        public: Arc<WebPkiServerVerifier>,
    }

    impl EitherVerifier {
        pub fn new(fleet: FleetVerifier) -> io::Result<Self> {
            Ok(Self {
                fleet,
                public: public_verifier()?,
            })
        }
    }

    impl ServerCertVerifier for EitherVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let fleet_err = match self.fleet.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Ok(v) => return Ok(v),
                Err(e) => e,
            };
            self.public
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map_err(|public_err| {
                    Error::General(format!(
                        "chain reaches neither a Privasys fleet anchor ({fleet_err}) nor the public PKI ({public_err})"
                    ))
                })
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.public.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            self.public.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.public.supported_verify_schemes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn embedded_anchors_are_the_two_privasys_intermediates() {
            let store = privasys_trust_anchors().expect("embedded anchors parse");
            assert_eq!(store.len(), 2);
            FleetVerifier::new(store).expect("verifier builds from the anchors");
        }

        #[test]
        fn custom_anchor_file_must_exist_and_hold_a_certificate() {
            assert!(trust_anchors_from_file("/nonexistent/ca.pem").is_err());
            let dir = std::env::temp_dir().join(format!("ratls-anchors-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let empty = dir.join("empty.pem");
            std::fs::write(&empty, b"not a certificate\n").unwrap();
            assert!(trust_anchors_from_file(empty.to_str().unwrap()).is_err());
            let one = dir.join("one.pem");
            std::fs::write(&one, PRIVASYS_INTERMEDIATE_CA_DEV_PEM).unwrap();
            assert_eq!(
                trust_anchors_from_file(one.to_str().unwrap())
                    .unwrap()
                    .len(),
                1
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

/// Which anchors the server chain must reach (see [`ConnectOptions::trust`]).
///
/// An attested connection (deterministic or challenge mode) must chain to the
/// Privasys fleet anchors, or to the caller's CA file: the evidence proves the
/// key, the chain proves the key was minted for a fleet member, and a valid
/// public-PKI certificate for the same name (a gateway's terminate path, or any
/// CA) must not be able to stand in. A connection that asks for no evidence
/// ([`AttestationMode::None`]) is an ordinary TLS connection as far as the
/// chain is concerned: hosts that are not enclaves, such as the identity
/// provider, present public-PKI certificates and never chain to the fleet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrustSelection {
    /// Fleet anchors for attested modes; for [`AttestationMode::None`] the
    /// chain is accepted when it reaches the fleet anchors (no name check) or
    /// verifies against the public PKI roots with the name check.
    #[default]
    Auto,
    /// The fleet anchors (or the CA file) in every mode.
    Fleet,
    /// The public PKI roots with the name check. Refused with an attested mode.
    Public,
}

impl TrustSelection {
    /// Parses `"auto"`, `"fleet"` or `"public"`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fleet" => Some(Self::Fleet),
            "public" => Some(Self::Public),
            _ => None,
        }
    }
}

/// Options for [`RaTlsClient::connect_with`].
#[derive(Default)]
pub struct ConnectOptions {
    /// PEM file whose certificates become the trust anchors for the server
    /// chain. `None` uses the embedded Privasys intermediate CAs (see
    /// [`fleet`]). The chain check is mandatory in both cases.
    pub ca_cert_pem: Option<String>,
    /// What to ask the server for after the handshake. Default: challenge.
    pub attestation: AttestationMode,
    /// Carrier of the attest messages. Default: HTTP.
    pub framing: Framing,
    /// DER client certificate chain (leaf first) for mutual RA-TLS: a v2
    /// identity, leaf key, chain, OIDs, no evidence.
    pub client_cert_der: Option<Vec<Vec<u8>>>,
    /// PKCS#8 private key of the client certificate.
    pub client_key_pkcs8: Option<Vec<u8>>,
    /// Produces this client's evidence when the server requires it on a
    /// mutual leg. Without it such a server fails the connection.
    pub client_evidence: Option<ClientEvidenceSource>,
    /// Fixes the 32-byte challenge context (challenge mode). A verifier that
    /// relays a challenge chosen elsewhere sets it so the evidence commits to
    /// that value; `None` draws a fresh random context per attestation.
    pub context: Option<[u8; CONTEXT_LEN]>,
    /// Which anchors the server chain must reach. Defaults to
    /// [`TrustSelection::Auto`].
    pub trust: TrustSelection,
}

/// A verified RA-TLS v2 connection.
pub struct RaTlsClient {
    stream: StreamOwned<ClientConnection, TcpStream>,
    peer_certs: Vec<Vec<u8>>,
    host: String,
    mode: AttestationMode,
    framing: Framing,
    evidence: Option<Evidence>,
    client_evidence: Option<ClientEvidenceSource>,
    presented_cert_der: Option<Vec<u8>>,
    last_policy: Option<VerificationPolicy>,
    context: Option<[u8; CONTEXT_LEN]>,
}

impl RaTlsClient {
    /// Connect in challenge mode (the default): after the handshake the
    /// server's evidence is requested, bound to this connection's TLS
    /// exporter and a fresh context. Verify it with
    /// [`RaTlsClient::verify_certificate`] before sending application data.
    ///
    /// - `host`: server hostname or IP
    /// - `port`: server port
    /// - `ca_cert_pem`: optional PEM file of trust anchors; `None` uses the
    ///   embedded Privasys intermediate CAs (see [`fleet`]).
    pub fn connect(host: &str, port: u16, ca_cert_pem: Option<&str>) -> io::Result<Self> {
        Self::connect_with(
            host,
            port,
            ConnectOptions {
                ca_cert_pem: ca_cert_pem.map(str::to_string),
                ..ConnectOptions::default()
            },
        )
    }

    /// Connect in deterministic mode: the runtime's cached quote, bound to
    /// the leaf key and a minute timestamp only (the "trust the TEE" tier).
    pub fn connect_deterministic(
        host: &str,
        port: u16,
        ca_cert_pem: Option<&str>,
    ) -> io::Result<Self> {
        Self::connect_with(
            host,
            port,
            ConnectOptions {
                ca_cert_pem: ca_cert_pem.map(str::to_string),
                attestation: AttestationMode::Deterministic,
                ..ConnectOptions::default()
            },
        )
    }

    /// Connect with a client certificate (mutual RA-TLS), in challenge mode.
    /// A server that requires client evidence needs
    /// [`ConnectOptions::client_evidence`]; use [`RaTlsClient::connect_with`].
    pub fn connect_mutual(
        host: &str,
        port: u16,
        ca_cert_pem: Option<&str>,
        client_cert_der: Vec<Vec<u8>>,
        client_key_pkcs8: Vec<u8>,
    ) -> io::Result<Self> {
        Self::connect_with(
            host,
            port,
            ConnectOptions {
                ca_cert_pem: ca_cert_pem.map(str::to_string),
                client_cert_der: Some(client_cert_der),
                client_key_pkcs8: Some(client_key_pkcs8),
                ..ConnectOptions::default()
            },
        )
    }

    /// Connect with explicit options.
    pub fn connect_with(host: &str, port: u16, opts: ConnectOptions) -> io::Result<Self> {
        let builder =
            Self::config_builder(opts.ca_cert_pem.as_deref(), opts.trust, opts.attestation)?;
        let mut presented = None;
        let config = match (opts.client_cert_der, opts.client_key_pkcs8) {
            (Some(chain), Some(key)) => {
                presented = chain.first().cloned();
                let certs: Vec<CertificateDer<'static>> = chain
                    .into_iter()
                    .map(|der| CertificateDer::from(der).into_owned())
                    .collect();
                let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))?
            }
            (None, None) => builder.with_no_client_auth(),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "client_cert_der and client_key_pkcs8 must be given together",
                ))
            }
        };
        let mut client = Self::finish_connect(host, port, config)?;
        client.mode = opts.attestation;
        client.framing = opts.framing;
        client.client_evidence = opts.client_evidence;
        client.context = opts.context;
        client.presented_cert_der = presented;
        // Evidence exchange, before any application data. A failure here
        // drops the connection: a caller never gets a client whose evidence
        // is missing in a mode that asked for it.
        if let Err(e) = client.attest(opts.attestation) {
            return Err(e);
        }
        Ok(client)
    }

    /// The `ClientConfig` builder shared by every constructor: server chain
    /// verified against the Privasys fleet anchors, or against the
    /// certificates in `ca_cert_pem` when one is given. TLS 1.3 only: the
    /// exporter of the challenge mode needs it.
    fn config_builder(
        ca_cert_pem: Option<&str>,
        trust: TrustSelection,
        attestation: AttestationMode,
    ) -> io::Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>> {
        let anchors = match ca_cert_pem {
            Some(path) => fleet::trust_anchors_from_file(path)?,
            None => fleet::privasys_trust_anchors()?,
        };
        let fleet_verifier = fleet::FleetVerifier::new(anchors)?;
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match trust {
            TrustSelection::Fleet => Arc::new(fleet_verifier),
            TrustSelection::Public => {
                if attestation != AttestationMode::None {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TrustSelection::Public is only valid with AttestationMode::None (an attested connection must chain to the fleet)",
                    ));
                }
                fleet::public_verifier()?
            }
            TrustSelection::Auto => {
                if attestation == AttestationMode::None {
                    Arc::new(fleet::EitherVerifier::new(fleet_verifier)?)
                } else {
                    Arc::new(fleet_verifier)
                }
            }
        };
        Ok(
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(verifier),
        )
    }

    /// Shared TCP + TLS connection logic.
    fn finish_connect(host: &str, port: u16, mut config: ClientConfig) -> io::Result<Self> {
        // Advertise the Privasys RA-TLS marker first so gateways that
        // front enclave hosts know to *splice* the connection (pure L4
        // forwarding) instead of terminating with their public LE cert.
        // Then advertise `http/1.1` so the actual TLS server on the
        // spliced upstream (Caddy in enclave-os-virtual, default NextProtos
        // `["h2", "http/1.1"]`) can negotiate a real HTTP version. We do
        // NOT advertise `h2`: this client speaks HTTP/1.1 over the raw
        // connection.
        let wants = [RATLS_ALPN_PROTO, b"http/1.1".as_slice()];
        for (i, proto) in wants.iter().enumerate() {
            if !config.alpn_protocols.iter().any(|p| p.as_slice() == *proto) {
                let insert_at = i.min(config.alpn_protocols.len());
                config.alpn_protocols.insert(insert_at, proto.to_vec());
            }
        }

        let server_name: ServerName<'static> = host.to_string().try_into().unwrap_or_else(|_| {
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
            mode: AttestationMode::None,
            framing: Framing::Http,
            evidence: None,
            client_evidence: None,
            presented_cert_der: None,
            last_policy: None,
            context: None,
        })
    }

    // -- evidence exchange --------------------------------------------------

    /// The 32-byte exporter value of this connection for `label` and
    /// `context` (RFC 8446 section 7.5).
    fn export_hctx(&self, label: &[u8], context: &[u8]) -> io::Result<[u8; HCTX_LEN]> {
        let out = self
            .stream
            .conn
            .export_keying_material([0u8; HCTX_LEN], label, Some(context))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("exporter: {e}")))?;
        Ok(out)
    }

    fn attest(&mut self, mode: AttestationMode) -> io::Result<()> {
        let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
        if mode == AttestationMode::None {
            self.evidence = None;
            return Ok(());
        }
        let der = self
            .peer_certs
            .first()
            .ok_or_else(|| invalid("no peer certificate".into()))?;
        let spki = spki_der_of(der).map_err(invalid)?;
        let mut ev = Evidence {
            mode,
            tee: String::new(),
            quote: Vec::new(),
            gpu_evidence: None,
            quote_time: String::new(),
            context: None,
            hctx: None,
            client_evidence_required: false,
            client_context: None,
        };
        let mut req = attest::AttestRequest {
            v: PROTOCOL_VERSION,
            mode: mode.as_str(),
            leaf: attest::leaf_id(&spki),
            context: None,
        };
        if mode == AttestationMode::Challenge {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut ctx = [0u8; CONTEXT_LEN];
            match self.context {
                Some(fixed) => ctx = fixed,
                None => SystemRandom::new()
                    .fill(&mut ctx)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "rng"))?,
            }
            let hctx = self.export_hctx(EXPORTER_LABEL_SERVER, &ctx)?;
            ev.context = Some(ctx);
            ev.hctx = Some(hctx);
            req.context = Some(attest::b64_encode(&ctx));
        }
        let body = serde_json::to_vec(&req).map_err(|e| invalid(e.to_string()))?;
        let (status, resp_body) = self.attest_round_trip(&body)?;
        let resp: attest::AttestResponse = serde_json::from_slice(&resp_body)
            .map_err(|e| invalid(format!("attest response: {e}")))?;
        if status != 200 || resp.error.is_some() {
            let msg = resp
                .error
                .unwrap_or_else(|| String::from_utf8_lossy(&resp_body).trim().to_string());
            if status == 404 {
                return Err(invalid(format!(
                    "server has no RA-TLS v2 evidence endpoint ({ATTEST_PATH}): {msg}"
                )));
            }
            return Err(invalid(format!("attest failed ({status}): {msg}")));
        }
        if resp.v != PROTOCOL_VERSION {
            return Err(invalid(format!(
                "attest response version {}, want {}",
                resp.v, PROTOCOL_VERSION
            )));
        }
        if resp.mode != mode.as_str() {
            return Err(invalid(format!(
                "attest response mode {:?}, requested {}",
                resp.mode, mode
            )));
        }
        if tee_type_of(&resp.tee).is_none() {
            return Err(invalid(format!(
                "attest response: unknown tee {:?}",
                resp.tee
            )));
        }
        ev.tee = resp.tee;
        ev.quote = attest::b64_decode(&resp.quote).map_err(|e| invalid(format!("quote: {e}")))?;
        if ev.quote.is_empty() {
            return Err(invalid("attest response: empty quote".into()));
        }
        if let Some(g) = resp.gpu_evidence.filter(|g| !g.is_empty()) {
            ev.gpu_evidence =
                Some(attest::b64_decode(&g).map_err(|e| invalid(format!("gpu_evidence: {e}")))?);
        }
        attest::check_quote_time(&resp.quote_time, attest::now_unix()).map_err(invalid)?;
        ev.quote_time = resp.quote_time;
        match resp.client_evidence.as_str() {
            "" | "none" => {}
            "required" => {
                ev.client_evidence_required = true;
                let cc = resp.client_context.ok_or_else(|| {
                    invalid("server requires client evidence without a client_context".into())
                })?;
                let cc = attest::b64_decode(&cc).map_err(invalid)?;
                let arr: [u8; CONTEXT_LEN] = cc
                    .try_into()
                    .map_err(|_| invalid(format!("client_context is not {CONTEXT_LEN} bytes")))?;
                ev.client_context = Some(arr);
            }
            other => {
                return Err(invalid(format!(
                    "attest response: unknown client_evidence {other:?}"
                )))
            }
        }
        let required = ev.client_evidence_required;
        let client_context = ev.client_context;
        self.evidence = Some(ev);
        if required {
            self.present(client_context.expect("client_context set with required"))?;
        }
        Ok(())
    }

    /// Answer a server that requires client evidence (mutual leg).
    fn present(&mut self, client_context: [u8; CONTEXT_LEN]) -> io::Result<()> {
        let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
        let source = self.client_evidence.as_ref().ok_or_else(|| {
            invalid(
                "server requires client evidence and ConnectOptions::client_evidence is not set"
                    .into(),
            )
        })?;
        let cert = self.presented_cert_der.as_ref().ok_or_else(|| {
            invalid(
                "server requires client evidence but no client certificate was presented".into(),
            )
        })?;
        let spki = spki_der_of(cert).map_err(invalid)?;
        let hctx = self.export_hctx(EXPORTER_LABEL_CLIENT, &client_context)?;
        let req = ClientEvidenceRequest {
            report_data: client_report_data(&spki, &client_context, &hctx, None),
            spki_der: spki,
            context: client_context,
            hctx,
        };
        let ce = source(&req).map_err(|e| invalid(format!("client evidence: {e}")))?;
        if ce.quote.is_empty() {
            return Err(invalid("client evidence source returned no quote".into()));
        }
        let msg = attest::PresentRequest {
            v: PROTOCOL_VERSION,
            mode: "present",
            context: attest::b64_encode(&client_context),
            tee: ce.tee,
            quote: attest::b64_encode(&ce.quote),
            gpu_evidence: ce.gpu_evidence.as_deref().map(attest::b64_encode),
            quote_time: ce.quote_time,
        };
        let body = serde_json::to_vec(&msg).map_err(|e| invalid(e.to_string()))?;
        let (status, resp_body) = self.attest_round_trip(&body)?;
        if self.framing == Framing::Raw {
            let ack: attest::Ack = serde_json::from_slice(&resp_body)
                .map_err(|e| invalid(format!("client evidence acknowledgement: {e}")))?;
            if ack.v != PROTOCOL_VERSION || ack.error.is_some() {
                return Err(invalid(format!(
                    "client evidence rejected: {}",
                    ack.error.unwrap_or_default()
                )));
            }
            return Ok(());
        }
        if status != 204 && status != 200 {
            return Err(invalid(format!(
                "client evidence rejected ({status}): {}",
                String::from_utf8_lossy(&resp_body).trim()
            )));
        }
        Ok(())
    }

    /// One attest message and its answer, on the configured framing.
    fn attest_round_trip(&mut self, body: &[u8]) -> io::Result<(u16, Vec<u8>)> {
        match self.framing {
            Framing::Raw => {
                attest::write_frame(&mut self.stream, body)?;
                let resp = attest::read_frame(&mut self.stream)?;
                Ok((200, resp))
            }
            Framing::Http => {
                self.send_http_request("POST", ATTEST_PATH, Some(body), None, None, false)?;
                self.recv_http_response()
            }
        }
    }

    /// The evidence obtained for this connection, `None` in
    /// [`AttestationMode::None`]. Verified only after
    /// [`RaTlsClient::verify_certificate`] returned without error.
    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }

    /// The mode this connection was attested in.
    pub fn attestation_mode(&self) -> AttestationMode {
        self.mode
    }

    /// Repeat the evidence exchange with a fresh context and, when a policy
    /// was verified before, verify the new evidence against it. Long-lived
    /// connections call it every few minutes and drop the connection on error.
    pub fn reattest(&mut self) -> io::Result<()> {
        if self.mode == AttestationMode::None {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "connection was opened with AttestationMode::None",
            ));
        }
        if self.framing == Framing::Raw {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "re-attestation is not possible on the raw binding; reconnect instead",
            ));
        }
        self.attest(self.mode)?;
        if let Some(policy) = self.last_policy.clone() {
            self.verify_certificate_typed(&policy)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.message))?;
        }
        Ok(())
    }

    // -- inspection and verification ------------------------------------------

    /// Inspect the server's leaf certificate.
    pub fn inspect_certificate(&self) -> CertInfo {
        match self.peer_certs.first() {
            Some(der) => inspect_der_certificate(der),
            None => CertInfo::empty(),
        }
    }

    /// Verify the server's leaf certificate and the evidence obtained for this
    /// connection against a policy (see [`verify_evidence_typed`]). Call it
    /// before sending any application data. In [`AttestationMode::None`] only
    /// the certificate extensions are verified.
    pub fn verify_certificate(&mut self, policy: &VerificationPolicy) -> Result<CertInfo, String> {
        self.verify_certificate_typed(policy).map_err(|e| e.message)
    }

    /// Typed variant of [`RaTlsClient::verify_certificate`]: returns a
    /// categorised [`VerifyError`] so a caller can tell a definite bad verdict
    /// from an unreachable attestation service and offer the right recovery.
    pub fn verify_certificate_typed(
        &mut self,
        policy: &VerificationPolicy,
    ) -> Result<CertInfo, VerifyError> {
        let der = self
            .peer_certs
            .first()
            .ok_or_else(|| VerifyError::new(VerifyErrorKind::Connection, "no peer certificate"))?;
        self.last_policy = Some(policy.clone());
        if self.mode == AttestationMode::None {
            return verify_certificate_extensions(der, policy);
        }
        let ev = self.evidence.as_ref().ok_or_else(|| {
            VerifyError::new(
                VerifyErrorKind::QuoteInvalid,
                "no attestation evidence for this connection",
            )
        })?;
        verify_evidence_typed(der, ev, policy)
    }

    /// Cheap, network-free check that the evidence of this connection binds
    /// the peer's leaf key: `report_data` recomputed from the leaf SPKI and
    /// the evidence must equal the quote's. Used on the data plane (every
    /// request) so the transport is never blind to a swapped certificate or a
    /// relayed quote. A connection opened with [`AttestationMode::None`] is a
    /// non-enclave peer (portal, IdP, a plain FIDO2 relying party) and passes:
    /// whether such a peer is acceptable is the caller's decision. There is no
    /// attestation-service call and no measurement pinning here; those belong
    /// to the verification gate.
    pub fn check_report_data_binding(&self) -> Result<(), VerifyError> {
        let der = self
            .peer_certs
            .first()
            .ok_or_else(|| VerifyError::new(VerifyErrorKind::Connection, "no peer certificate"))?;
        let bad = |m: String| VerifyError::new(VerifyErrorKind::QuoteInvalid, m);
        let info = inspect_der_certificate(der);
        if info.v1_leaf {
            return Err(bad(
                "v1 RA-TLS certificate (evidence inside the certificate)".into(),
            ));
        }
        let ev = match self.evidence.as_ref() {
            Some(ev) => ev,
            None => return Ok(()),
        };
        if ev.quote.starts_with(b"MOCK_QUOTE:") {
            return Err(bad("evidence is a MOCK quote".into()));
        }
        let spki = spki_der_of(der).map_err(bad)?;
        let expected = expected_report_data(&spki, ev).map_err(bad)?;
        let actual = quote_report_data(&ev.tee, &ev.quote).map_err(bad)?;
        if actual != expected.as_slice() {
            return Err(bad(
                "report_data does not bind this connection's leaf key".into()
            ));
        }
        Ok(())
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
                let clean_name: String = name
                    .chars()
                    .filter(|c| *c != '\r' && *c != '\n' && *c != ':')
                    .collect();
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

        let header_section = std::str::from_utf8(&buf[..header_end])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Parse status
        let status_line = header_section.lines().next().unwrap_or("");
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Parse the framing headers (names are case-insensitive, RFC 9112).
        // Transfer-Encoding matters as much as Content-Length: Go's http
        // server only sets Content-Length for responses that fit its 2 KiB
        // buffer and CHUNKS anything larger, so ignoring chunked framing
        // silently truncated every response over ~2 KiB to an empty body
        // (the wallet's "empty drive" bug, 2026-07-31).
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut connection_close = false;
        for line in header_section.lines().skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.parse().ok();
            } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
                chunked = value.to_ascii_lowercase().contains("chunked");
            } else if name.eq_ignore_ascii_case("Connection") {
                connection_close = value.eq_ignore_ascii_case("close");
            }
        }

        let body_start = header_end + 4;
        let mut rest = if body_start < buf.len() {
            buf[body_start..].to_vec()
        } else {
            Vec::new()
        };

        if chunked {
            let body = self.decode_chunked(&mut rest, &mut tmp)?;
            return Ok((status_code, body));
        }

        let mut body = rest;
        match content_length {
            Some(len) => {
                while body.len() < len {
                    let n = self.stream.read(&mut tmp)?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                body.truncate(len);
            }
            None => {
                // Without Content-Length or chunked framing, a body exists
                // only when the server ends it by closing the connection
                // (RFC 9112 §6.3); otherwise (204, HEAD, ...) there is none.
                if connection_close {
                    loop {
                        let n = self.stream.read(&mut tmp)?;
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&tmp[..n]);
                    }
                } else {
                    body.clear();
                }
            }
        }

        Ok((status_code, body))
    }

    /// Decode a chunked transfer coding (RFC 9112 §7.1): hex size line,
    /// chunk data, CRLF, repeated until the terminal zero-size chunk.
    /// `rest` holds bytes already read past the headers. Trailer fields
    /// are not expected from our servers and are left unread.
    fn decode_chunked(&mut self, rest: &mut Vec<u8>, tmp: &mut [u8]) -> io::Result<Vec<u8>> {
        fn find_crlf(hay: &[u8]) -> Option<usize> {
            hay.windows(2).position(|w| w == b"\r\n")
        }
        let mut body = Vec::new();
        let mut pos = 0usize;
        loop {
            // Buffer a complete size line.
            let line_end = loop {
                if let Some(i) = find_crlf(&rest[pos..]) {
                    break pos + i;
                }
                let n = self.stream.read(tmp)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed inside chunked body",
                    ));
                }
                rest.extend_from_slice(&tmp[..n]);
            };
            let size_str = std::str::from_utf8(&rest[pos..line_end])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let size_hex = size_str.trim().split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid chunk size line {size_str:?}"),
                )
            })?;
            pos = line_end + 2;
            // Buffer the chunk data plus its trailing CRLF.
            while rest.len() < pos + size + 2 {
                let n = self.stream.read(tmp)?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed inside chunked body",
                    ));
                }
                rest.extend_from_slice(&tmp[..n]);
            }
            if size == 0 {
                return Ok(body);
            }
            body.extend_from_slice(&rest[pos..pos + size]);
            pos += size + 2;
        }
    }

    /// GET /healthz — liveness probe (no auth).
    pub fn healthz(&mut self) -> io::Result<serde_json::Value> {
        self.send_http_request("GET", "/healthz", None, None, None, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "healthz failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// GET /readyz — readiness probe (monitoring+ role).
    pub fn readyz(&mut self, auth_token: Option<&str>) -> io::Result<serde_json::Value> {
        self.send_http_request("GET", "/readyz", None, auth_token, None, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "readyz failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// GET /status — enclave status (monitoring+ role).
    pub fn status(&mut self, auth_token: Option<&str>) -> io::Result<serde_json::Value> {
        self.send_http_request("GET", "/status", None, auth_token, None, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "status failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// GET /metrics — Prometheus metrics (monitoring+ role).
    pub fn metrics(&mut self, auth_token: Option<&str>) -> io::Result<String> {
        self.send_http_request("GET", "/metrics", None, auth_token, None, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "metrics failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
            ));
        }
        String::from_utf8(body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// POST /data — send module command, return response body.
    pub fn send_data(&mut self, data: &[u8], auth_token: Option<&str>) -> io::Result<Vec<u8>> {
        self.send_http_request("POST", "/data", Some(data), auth_token, None, false)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "send_data failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
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
        self.send_http_request(
            "PUT",
            "/attestation-servers",
            Some(&body),
            auth_token,
            None,
            false,
        )?;
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
        serde_json::from_slice(&resp).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// POST /shutdown — request graceful shutdown.
    pub fn shutdown(&mut self, auth_token: Option<&str>) -> io::Result<()> {
        self.send_http_request("POST", "/shutdown", None, auth_token, None, true)?;
        let (status, body) = self.recv_http_response()?;
        if status != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "shutdown failed ({}): {}",
                    status,
                    String::from_utf8_lossy(&body)
                ),
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
            println!(
                "    {} ({}): {}",
                ext.label,
                ext.oid,
                hex::encode(&ext.value)
            );
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
    use super::{digest, CertInfo, ExpectedOid, TeeType, VerificationPolicy, OID_WORKLOAD_APP_ID};

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
                let b = hex::decode(sgx).map_err(|_| format!("invalid SGX MRENCLAVE {:?}", sgx))?;
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
                let b =
                    hex::decode(&t.mrtd).map_err(|_| format!("invalid TDX MRTD {:?}", t.mrtd))?;
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
        use crate::{sgx_report, OidExtension, QuoteInfo, OID_SGX_QUOTE, OID_WORKLOAD_CODE_HASH};

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
                ..CertInfo::empty()
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
                ..CertInfo::empty()
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
