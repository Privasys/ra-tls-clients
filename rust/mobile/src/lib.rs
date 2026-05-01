// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! C FFI bindings for the RA-TLS client library.
//!
//! Designed for consumption by iOS (Swift) and Android (Kotlin/JNI) native
//! modules in the Privasys Wallet mobile app.
//!
//! # Memory model
//!
//! All returned strings are heap-allocated C strings (`malloc`/`strdup`).
//! The caller must free them with `ratls_free_string()`.
//!
//! # Thread safety
//!
//! Each function is independent and thread-safe. No global state is shared.
//!
//! # Error handling
//!
//! Functions return a JSON-encoded result string. On error, the JSON
//! contains `{ "error": "message" }`. On success, it contains the
//! attestation data.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use ratls_client::{
    CertInfo, QuoteVerificationConfig, QuoteVerificationStatus,
    ReportDataMode, TeeType, VerificationPolicy,
};

// ---------------------------------------------------------------------------
//  JSON result types (serialized back to the caller)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct AttestationResult {
    valid: bool,
    tee_type: Option<String>,
    mrenclave: Option<String>,
    mrsigner: Option<String>,
    mrtd: Option<String>,
    config_merkle_root: Option<String>,
    code_hash: Option<String>,
    /// Per-workload OCI image reference (`OID_WORKLOAD_IMAGE_REF`). Populated
    /// only on enclave-os-virtual container certificates.
    image_ref: Option<String>,
    attestation_servers_hash: Option<String>,
    dek_origin: Option<String>,
    quote_verification_status: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    advisory_ids: Vec<String>,
    cert_subject: String,
    cert_not_before: String,
    cert_not_after: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    custom_oids: Vec<OidEntry>,
}

#[derive(serde::Serialize)]
struct OidEntry {
    oid: String,
    label: String,
    value_hex: String,
}

#[derive(serde::Serialize)]
struct ErrorResult {
    error: String,
}

// ---------------------------------------------------------------------------
//  Helper functions
// ---------------------------------------------------------------------------

/// Convert a CertInfo to JSON result.
fn cert_info_to_result(info: &CertInfo, tee_type: Option<TeeType>) -> AttestationResult {
    let tee_str = tee_type.map(|t| match t {
        TeeType::Sgx => "sgx".to_string(),
        TeeType::Tdx => "tdx".to_string(),
        TeeType::SevSnp => "sev-snp".to_string(),
        TeeType::NvidiaGpu => "nvidia-gpu".to_string(),
    });

    // Extract known OID values as hex strings
    let find_oid = |oid: &str| -> Option<String> {
        info.custom_oids
            .iter()
            .find(|o| o.oid == oid)
            .map(|o| hex::encode(&o.value))
    };

    AttestationResult {
        valid: true,
        tee_type: tee_str,
        mrenclave: info.quote.as_ref().and_then(|q| {
            if q.oid == ratls_client::OID_SGX_QUOTE {
                let format = ratls_client::detect_sgx_format(&q.raw);
                let range = match format {
                    ratls_client::SgxQuoteFormat::DcapV3 => ratls_client::sgx_quote::MRENCLAVE,
                    ratls_client::SgxQuoteFormat::RawReport => ratls_client::sgx_report::MRENCLAVE,
                };
                if q.raw.len() > range.end {
                    Some(hex::encode(&q.raw[range]))
                } else {
                    None
                }
            } else {
                None
            }
        }),
        mrsigner: info.quote.as_ref().and_then(|q| {
            if q.oid == ratls_client::OID_SGX_QUOTE {
                let format = ratls_client::detect_sgx_format(&q.raw);
                let range = match format {
                    ratls_client::SgxQuoteFormat::DcapV3 => ratls_client::sgx_quote::MRSIGNER,
                    ratls_client::SgxQuoteFormat::RawReport => ratls_client::sgx_report::MRSIGNER,
                };
                if q.raw.len() > range.end {
                    Some(hex::encode(&q.raw[range]))
                } else {
                    None
                }
            } else {
                None
            }
        }),
        mrtd: info.quote.as_ref().and_then(|q| {
            if q.oid == ratls_client::OID_TDX_QUOTE && q.raw.len() >= ratls_client::tdx_quote::MIN_SIZE {
                Some(hex::encode(&q.raw[ratls_client::tdx_quote::MRTD]))
            } else {
                None
            }
        }),
        // Container RA-TLS certs in enclave-os-virtual carry per-workload
        // OIDs (.65230.3.x) holding that container's own measurements;
        // platform / management certs carry the VM-wide OIDs (.65230.1.x,
        // .65230.2.x). Prefer the workload-scoped value when present so
        // SNI-routed container endpoints surface the right measurement
        // (the platform OIDs cover the whole VM and are never present on
        // a per-container cert), and fall back to the platform OID for
        // management endpoints. SGX (enclave-os-mini) only emits the
        // platform OIDs, so the fallback is what gets picked up there.
        config_merkle_root: find_oid(ratls_client::OID_WORKLOAD_CONFIG_MERKLE_ROOT)
            .or_else(|| find_oid(ratls_client::OID_CONFIG_MERKLE_ROOT)),
        code_hash: find_oid(ratls_client::OID_WORKLOAD_CODE_HASH)
            .or_else(|| find_oid(ratls_client::OID_COMBINED_WORKLOADS_HASH)),
        image_ref: info.custom_oids.iter()
            .find(|o| o.oid == ratls_client::OID_WORKLOAD_IMAGE_REF)
            .and_then(|o| String::from_utf8(o.value.clone()).ok()),
        attestation_servers_hash: find_oid(ratls_client::OID_ATTESTATION_SERVERS_HASH),
        // OID_WORKLOAD_KEY_SOURCE (.65230.3.4) on container certs and
        // OID_DEK_ORIGIN (.65230.2.6) on platform certs both encode a
        // BYOK fingerprint or `"generated"` as a UTF-8 string.
        dek_origin: info.custom_oids.iter()
            .find(|o| o.oid == ratls_client::OID_WORKLOAD_KEY_SOURCE
                || o.oid == ratls_client::OID_DEK_ORIGIN)
            .and_then(|o| String::from_utf8(o.value.clone()).ok()),
        quote_verification_status: info.quote_verification.as_ref().map(|qv| qv.status.to_string()),
        advisory_ids: info.quote_verification.as_ref()
            .map(|qv| qv.advisory_ids.clone())
            .unwrap_or_default(),
        cert_subject: info.subject.clone(),
        cert_not_before: info.not_before.clone(),
        cert_not_after: info.not_after.clone(),
        custom_oids: info.custom_oids.iter().map(|o| OidEntry {
            oid: o.oid.clone(),
            label: o.label.clone(),
            value_hex: hex::encode(&o.value),
        }).collect(),
    }
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn json_error(msg: &str) -> *mut c_char {
    let result = ErrorResult { error: msg.to_string() };
    to_c_string(&serde_json::to_string(&result).unwrap_or_else(|_| {
        r#"{"error":"serialization failed"}"#.to_string()
    }))
}

unsafe fn read_c_str(ptr: *const c_char) -> Result<String, &'static str> {
    if ptr.is_null() {
        return Err("null pointer");
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| "invalid UTF-8")
}

// ---------------------------------------------------------------------------
//  C FFI functions
// ---------------------------------------------------------------------------

/// Connect to an enclave via RA-TLS and inspect its attestation certificate.
///
/// Returns a JSON string with attestation details. The caller must free
/// the returned string with `ratls_free_string()`.
///
/// # Parameters
/// - `host`: hostname or IP address (C string)
/// - `port`: port number
/// - `ca_cert_pem_path`: optional path to a CA certificate PEM file
///   (C string, NULL to skip CA verification — typical for RA-TLS)
///
/// # Returns
/// JSON string: `{ "valid": true, "tee_type": "sgx", ... }` or `{ "error": "..." }`
#[no_mangle]
pub unsafe extern "C" fn ratls_inspect(
    host: *const c_char,
    port: u16,
    ca_cert_pem_path: *const c_char,
) -> *mut c_char {
    let host_str = match read_c_str(host) {
        Ok(s) => s,
        Err(e) => return json_error(e),
    };

    let ca_path = if ca_cert_pem_path.is_null() {
        None
    } else {
        match read_c_str(ca_cert_pem_path) {
            Ok(s) => Some(s),
            Err(e) => return json_error(e),
        }
    };

    let client = match ratls_client::RaTlsClient::connect(
        &host_str, port, ca_path.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => return json_error(&format!("connection failed: {e}")),
    };

    let info = client.inspect_certificate();
    let tee_type = info.quote.as_ref().map(|q| {
        if q.oid == ratls_client::OID_SGX_QUOTE {
            TeeType::Sgx
        } else if q.oid == ratls_client::OID_SEV_SNP_REPORT {
            TeeType::SevSnp
        } else if q.oid == ratls_client::OID_NVIDIA_GPU_EVIDENCE {
            TeeType::NvidiaGpu
        } else {
            TeeType::Tdx
        }
    });
    let result = cert_info_to_result(&info, tee_type);
    to_c_string(&serde_json::to_string(&result).unwrap_or_default())
}

/// Connect to an enclave, verify its RA-TLS certificate against a policy,
/// and return verified attestation details.
///
/// # Parameters
/// - `host`, `port`, `ca_cert_pem_path`: same as `ratls_inspect`
/// - `policy_json`: JSON-encoded verification policy (see below)
///
/// Policy JSON example:
/// ```json
/// {
///   "tee": "sgx",
///   "mrenclave": "abcd1234...",
///   "report_data_mode": "deterministic",
///   "attestation_server": "https://as.privasys.org/verify",
///   "attestation_server_token": "optional-bearer-token"
/// }
/// ```
///
/// For challenge-response freshness, set `report_data_mode` to `"challenge"`
/// and provide a `"nonce"` (hex). The nonce is sent in the TLS ClientHello
/// via extension `0xFFBB` so the enclave binds it into its certificate.
#[no_mangle]
pub unsafe extern "C" fn ratls_verify(
    host: *const c_char,
    port: u16,
    ca_cert_pem_path: *const c_char,
    policy_json: *const c_char,
) -> *mut c_char {
    let host_str = match read_c_str(host) {
        Ok(s) => s,
        Err(e) => return json_error(e),
    };

    let ca_path = if ca_cert_pem_path.is_null() {
        None
    } else {
        match read_c_str(ca_cert_pem_path) {
            Ok(s) => Some(s),
            Err(e) => return json_error(e),
        }
    };

    let policy_str = match read_c_str(policy_json) {
        Ok(s) => s,
        Err(e) => return json_error(e),
    };

    let policy = match parse_policy_json(&policy_str) {
        Ok(p) => p,
        Err(e) => return json_error(&e),
    };

    // Choose connection method: challenge-response sends nonce in ClientHello
    let client = match &policy.report_data {
        ReportDataMode::ChallengeResponse { nonce } => {
            ratls_client::RaTlsClient::connect_challenged(
                &host_str, port, ca_path.as_deref(), nonce.clone(),
            )
        }
        _ => ratls_client::RaTlsClient::connect(
            &host_str, port, ca_path.as_deref(),
        ),
    };

    let client = match client {
        Ok(c) => c,
        Err(e) => return json_error(&format!("connection failed: {e}")),
    };

    match client.verify_certificate(&policy) {
        Ok(verified_info) => {
            let result = cert_info_to_result(&verified_info, Some(policy.tee));
            to_c_string(&serde_json::to_string(&result).unwrap_or_default())
        }
        Err(e) => json_error(&format!("verification failed: {e}")),
    }
}

/// Connect to an enclave via RA-TLS and perform an HTTP POST request.
///
/// Returns a JSON string with `{ "status": <http_code>, "body": "<response>" }`
/// or `{ "error": "..." }`. The caller must free with `ratls_free_string()`.
///
/// # Parameters
/// - `host`: hostname or IP address
/// - `port`: port number
/// - `ca_cert_pem_path`: optional CA cert path (NULL for RA-TLS self-signed)
/// - `path`: HTTP path (e.g. "/fido2/register/begin")
/// - `body`: JSON request body (C string)
#[no_mangle]
pub unsafe extern "C" fn ratls_post(
    host: *const c_char,
    port: u16,
    ca_cert_pem_path: *const c_char,
    path: *const c_char,
    body: *const c_char,
) -> *mut c_char {
    let host_str = match read_c_str(host) {
        Ok(s) => s,
        Err(e) => return json_error(e),
    };

    let ca_path = if ca_cert_pem_path.is_null() {
        None
    } else {
        match read_c_str(ca_cert_pem_path) {
            Ok(s) => Some(s),
            Err(e) => return json_error(e),
        }
    };

    let path_str = match read_c_str(path) {
        Ok(s) => s,
        Err(e) => return json_error(e),
    };

    let body_str = match read_c_str(body) {
        Ok(s) => s,
        Err(e) => return json_error(e),
    };

    let mut client = match ratls_client::RaTlsClient::connect(
        &host_str, port, ca_path.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => return json_error(&format!("connection failed: {e}")),
    };

    let (status, resp_body) = match client.http_post(
        &path_str,
        body_str.as_bytes(),
        None,
    ) {
        Ok(r) => r,
        Err(e) => return json_error(&format!("request failed: {e}")),
    };

    let resp_str = String::from_utf8_lossy(&resp_body);

    #[derive(serde::Serialize)]
    struct PostResult {
        status: u16,
        body: String,
    }

    let result = PostResult {
        status,
        body: resp_str.into_owned(),
    };

    to_c_string(&serde_json::to_string(&result).unwrap_or_else(|_| {
        r#"{"error":"serialization failed"}"#.to_string()
    }))
}

/// Free a string returned by `ratls_inspect`, `ratls_verify`, or `ratls_post`.
#[no_mangle]
pub unsafe extern "C" fn ratls_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ---------------------------------------------------------------------------
//  Policy JSON parsing
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct PolicyJson {
    tee: String,
    #[serde(default)]
    mrenclave: Option<String>,
    #[serde(default)]
    mrsigner: Option<String>,
    #[serde(default)]
    mrtd: Option<String>,
    #[serde(default = "default_report_data_mode")]
    report_data_mode: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    attestation_server: Option<String>,
    #[serde(default)]
    attestation_server_token: Option<String>,
}

fn default_report_data_mode() -> String {
    "deterministic".to_string()
}

fn parse_policy_json(json: &str) -> Result<VerificationPolicy, String> {
    let p: PolicyJson =
        serde_json::from_str(json).map_err(|e| format!("invalid policy JSON: {e}"))?;

    let tee = match p.tee.as_str() {
        "sgx" => TeeType::Sgx,
        "tdx" => TeeType::Tdx,
        "sev-snp" => TeeType::SevSnp,
        "nvidia-gpu" => TeeType::NvidiaGpu,
        other => return Err(format!("unknown tee type: {other}")),
    };

    let mr_enclave = p.mrenclave.as_deref().map(decode_hex32).transpose()?;
    let mr_signer = p.mrsigner.as_deref().map(decode_hex32).transpose()?;
    let mr_td = p.mrtd.as_deref().map(decode_hex48).transpose()?;

    let report_data = match p.report_data_mode.as_str() {
        "skip" => ReportDataMode::Skip,
        "deterministic" => ReportDataMode::Deterministic,
        "challenge" => {
            let nonce = p.nonce.as_deref()
                .ok_or("nonce required for challenge mode")?;
            let bytes = hex::decode(nonce).map_err(|e| format!("nonce hex: {e}"))?;
            ReportDataMode::ChallengeResponse { nonce: bytes }
        }
        other => return Err(format!("unknown report_data_mode: {other}")),
    };

    let quote_verification = p.attestation_server.map(|endpoint| QuoteVerificationConfig {
        endpoint,
        token: p.attestation_server_token,
        accepted_statuses: vec![
            QuoteVerificationStatus::Ok,
            QuoteVerificationStatus::SwHardeningNeeded,
        ],
        timeout_secs: 10,
    });

    Ok(VerificationPolicy {
        tee,
        mr_enclave,
        mr_signer,
        mr_td,
        measurement: None,
        host_data: None,
        report_data,
        expected_oids: Vec::new(),
        quote_verification,
    })
}

fn decode_hex32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn decode_hex48(hex_str: &str) -> Result<[u8; 48], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
