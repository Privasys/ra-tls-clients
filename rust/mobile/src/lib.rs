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
    AttestationMode, CertInfo, QuoteVerificationConfig, QuoteVerificationStatus, TeeType,
    VerificationPolicy,
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
    // TDX runtime measurement registers 1 and 2. Together with MRTD these are
    // the platform-runtime fingerprint the session-relay enc_pub is pinned to
    // (management-service hashes MRTD|RTMR1|RTMR2), so the wallet persists +
    // diffs them to detect a platform upgrade that rotates a sealed session
    // even when MRTD is unchanged. Absent for non-TDX quotes.
    #[serde(skip_serializing_if = "Option::is_none")]
    rtmr1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtmr2: Option<String>,

    // ---- Platform / VM-wide OIDs (.65230.1.x, .65230.2.x) -----------
    config_merkle_root: Option<String>,
    combined_workloads_hash: Option<String>,
    dek_origin: Option<String>,
    attestation_servers_hash: Option<String>,

    // ---- Per-workload OIDs (.65230.3.x) -----------------------------
    workload_config_merkle_root: Option<String>,
    workload_code_hash: Option<String>,
    workload_image_ref: Option<String>,
    workload_key_source: Option<String>,

    quote_verification_status: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    advisory_ids: Vec<String>,
    /// RA-TLS v2 attestation mode of the connection: "challenge",
    /// "deterministic" or "none" (certificate extensions only).
    attestation: String,
    /// quote_time of the evidence (minute precision), when attested.
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_time: Option<String>,
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
    /// Stable failure category so the caller can pick the right recovery UX:
    /// `as_unreachable` → offer to continue; `quote_invalid`/`as_rejected` →
    /// show the problem with an explicit override; `connection`/`config` → hard
    /// error. Omitted only for the legacy `json_error` path.
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
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

    let is_sgx = info.evidence.as_ref().map_or(false, |e| e.tee == "sgx");
    let is_tdx = info
        .evidence
        .as_ref()
        .map_or(false, |e| e.tee.starts_with("tdx"));

    AttestationResult {
        valid: true,
        tee_type: tee_str,
        mrenclave: info.quote.as_ref().and_then(|q| {
            if is_sgx {
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
            if is_sgx {
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
            if is_tdx && q.raw.len() >= ratls_client::tdx_quote::MIN_SIZE {
                Some(hex::encode(&q.raw[ratls_client::tdx_quote::MRTD]))
            } else {
                None
            }
        }),
        rtmr1: info.quote.as_ref().and_then(|q| {
            if is_tdx && q.raw.len() >= ratls_client::tdx_quote::MIN_SIZE {
                Some(hex::encode(&q.raw[ratls_client::tdx_quote::RTMR1]))
            } else {
                None
            }
        }),
        rtmr2: info.quote.as_ref().and_then(|q| {
            if is_tdx && q.raw.len() >= ratls_client::tdx_quote::MIN_SIZE {
                Some(hex::encode(&q.raw[ratls_client::tdx_quote::RTMR2]))
            } else {
                None
            }
        }),
        // One OID per field; never conflate platform (.1.x/.2.x) with
        // workload (.3.x). Caller decides which to trust.
        config_merkle_root: find_oid(ratls_client::OID_CONFIG_MERKLE_ROOT),
        combined_workloads_hash: find_oid(ratls_client::OID_COMBINED_WORKLOADS_HASH),
        attestation_servers_hash: find_oid(ratls_client::OID_ATTESTATION_SERVERS_HASH),
        dek_origin: info
            .custom_oids
            .iter()
            .find(|o| o.oid == ratls_client::OID_DEK_ORIGIN)
            .and_then(|o| String::from_utf8(o.value.clone()).ok()),

        workload_config_merkle_root: find_oid(ratls_client::OID_WORKLOAD_CONFIG_MERKLE_ROOT),
        workload_code_hash: find_oid(ratls_client::OID_WORKLOAD_CODE_HASH),
        workload_image_ref: info
            .custom_oids
            .iter()
            .find(|o| o.oid == ratls_client::OID_WORKLOAD_IMAGE_REF)
            .and_then(|o| String::from_utf8(o.value.clone()).ok()),
        workload_key_source: info
            .custom_oids
            .iter()
            .find(|o| o.oid == ratls_client::OID_WORKLOAD_KEY_SOURCE)
            .and_then(|o| String::from_utf8(o.value.clone()).ok()),
        quote_verification_status: info
            .quote_verification
            .as_ref()
            .map(|qv| qv.status.to_string()),
        advisory_ids: info
            .quote_verification
            .as_ref()
            .map(|qv| qv.advisory_ids.clone())
            .unwrap_or_default(),
        attestation: info.attestation.as_str().to_string(),
        quote_time: info.evidence.as_ref().map(|e| e.quote_time.clone()),
        cert_subject: info.subject.clone(),
        cert_not_before: info.not_before.clone(),
        cert_not_after: info.not_after.clone(),
        custom_oids: info
            .custom_oids
            .iter()
            .map(|o| OidEntry {
                oid: o.oid.clone(),
                label: o.label.clone(),
                value_hex: hex::encode(&o.value),
            })
            .collect(),
    }
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn json_error(msg: &str) -> *mut c_char {
    let result = ErrorResult {
        error: msg.to_string(),
        kind: None,
    };
    to_c_string(
        &serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
    )
}

/// Like [`json_error`] but tags the failure with a stable [`ErrorResult::kind`]
/// so the caller can branch its recovery UX.
fn json_error_kind(msg: &str, kind: &str) -> *mut c_char {
    let result = ErrorResult {
        error: msg.to_string(),
        kind: Some(kind.to_string()),
    };
    to_c_string(
        &serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
    )
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

    // Inspection asks for deterministic evidence so the TEE family and the
    // measurements can be shown; nothing is verified against a policy here.
    let client =
        match ratls_client::RaTlsClient::connect_deterministic(&host_str, port, ca_path.as_deref())
        {
            Ok(c) => c,
            Err(e) => return json_error(&format!("connection failed: {e}")),
        };

    let mut info = client.inspect_certificate();
    let tee_type = client
        .evidence()
        .and_then(|ev| ratls_client::tee_type_of(&ev.tee));
    if let Some(ev) = client.evidence() {
        info.evidence = Some(ev.clone());
        info.attestation = ev.mode;
        // Unverified display of the evidence body (measurements), as the
        // v1 inspect showed the certificate's quote.
        if let Ok(rd) = ratls_client::quote_report_data(&ev.tee, &ev.quote) {
            info.quote = Some(ratls_client::QuoteInfo {
                oid: String::new(),
                label: ev.tee.clone(),
                critical: false,
                raw: ev.quote.clone(),
                is_mock: false,
                version: None,
                report_data: Some(rd.to_vec()),
            });
        }
    }
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
///   "attestation": "challenge",
///   "attestation_server": "https://as.privasys.org/verify",
///   "attestation_server_token": "optional-bearer-token"
/// }
/// ```
///
/// `attestation` is `"challenge"` (default: evidence bound to this
/// connection's TLS exporter and a fresh context), `"deterministic"` (the
/// runtime's cached quote) or `"none"` (certificate extensions only). The
/// legacy key `report_data_mode` is accepted with the same values
/// (`"skip"` maps to `"none"`); a `nonce` is ignored.
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

    let (policy, attestation) = match parse_policy_json(&policy_str) {
        Ok(p) => p,
        Err(e) => return json_error_kind(&e, "config"),
    };
    let trust = match parse_trust(&policy_str) {
        Ok(t) => t,
        Err(e) => return json_error_kind(&e, "config"),
    };

    let client = ratls_client::RaTlsClient::connect_with(
        &host_str,
        port,
        ratls_client::ConnectOptions {
            ca_cert_pem: ca_path,
            attestation,
            trust,
            ..ratls_client::ConnectOptions::default()
        },
    );

    let mut client = match client {
        Ok(c) => c,
        Err(e) => return json_error_kind(&format!("connection failed: {e}"), "connection"),
    };

    // Typed verification so the caller can distinguish an unreachable
    // attestation service (offer to continue) from a definite bad verdict
    // (show the problem, allow an explicit override).
    match client.verify_certificate_typed(&policy) {
        Ok(verified_info) => {
            let result = cert_info_to_result(&verified_info, Some(policy.tee));
            to_c_string(&serde_json::to_string(&result).unwrap_or_default())
        }
        Err(e) => json_error_kind(&e.message, e.kind.as_str()),
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
    headers_json: *const c_char,
) -> *mut c_char {
    let method = c"POST".as_ptr();
    ratls_request(
        method,
        host,
        port,
        ca_cert_pem_path,
        path,
        body,
        headers_json,
    )
}

/// Connect to an enclave via RA-TLS and perform an HTTP request with an
/// arbitrary method (GET, POST, PUT, DELETE, …).
///
/// Returns a JSON string with `{ "status": <http_code>, "body": "<response>" }`
/// or `{ "error": "..." }`. The caller must free with `ratls_free_string()`.
///
/// # Parameters
/// - `method`: HTTP method (C string, e.g. "GET"). Empty/NULL → "POST".
/// - `host`: hostname or IP address
/// - `port`: port number
/// - `ca_cert_pem_path`: optional CA cert path (NULL for RA-TLS self-signed)
/// - `path`: HTTP path (e.g. "/tools/list_root")
/// - `body`: request body (C string; empty/NULL sends no body, correct for GET/DELETE)
/// - `headers_json`: optional JSON object of extra request headers
#[no_mangle]
pub unsafe extern "C" fn ratls_request(
    method: *const c_char,
    host: *const c_char,
    port: u16,
    ca_cert_pem_path: *const c_char,
    path: *const c_char,
    body: *const c_char,
    headers_json: *const c_char,
) -> *mut c_char {
    ratls_request_with(
        method,
        host,
        port,
        ca_cert_pem_path,
        path,
        body,
        headers_json,
        std::ptr::null(),
    )
}

/// `ratls_request` with connection options: `options_json` is an optional
/// JSON object `{"attestation": "challenge" | "deterministic" | "none",
/// "trust": "auto" | "fleet" | "public"}`. The defaults (NULL or empty)
/// are challenge mode and automatic trust, the attested request of
/// `ratls_request`. A host that is not an enclave (the identity provider)
/// is reached with `{"attestation": "none", "trust": "public"}`: an ordinary
/// TLS connection verified against the public PKI, no evidence exchange.
#[no_mangle]
pub unsafe extern "C" fn ratls_request_with(
    method: *const c_char,
    host: *const c_char,
    port: u16,
    ca_cert_pem_path: *const c_char,
    path: *const c_char,
    body: *const c_char,
    headers_json: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let defaults = (
        ratls_client::AttestationMode::Challenge,
        ratls_client::TrustSelection::Auto,
    );
    let (attestation, trust) = if options_json.is_null() {
        defaults
    } else {
        match read_c_str(options_json) {
            Ok(s) if s.trim().is_empty() => defaults,
            Ok(s) => {
                #[derive(serde::Deserialize)]
                struct O {
                    #[serde(default)]
                    attestation: Option<String>,
                }
                let o: O = match serde_json::from_str(&s) {
                    Ok(o) => o,
                    Err(e) => {
                        return json_error_kind(&format!("invalid options_json: {e}"), "config")
                    }
                };
                let attestation = match o.attestation.as_deref().unwrap_or("challenge") {
                    "challenge" => ratls_client::AttestationMode::Challenge,
                    "deterministic" => ratls_client::AttestationMode::Deterministic,
                    "none" => ratls_client::AttestationMode::None,
                    other => {
                        return json_error_kind(
                            &format!("unknown attestation mode: {other}"),
                            "config",
                        )
                    }
                };
                let trust = match parse_trust(&s) {
                    Ok(t) => t,
                    Err(e) => return json_error_kind(&e, "config"),
                };
                (attestation, trust)
            }
            Err(e) => return json_error(e),
        }
    };
    let method_str = if method.is_null() {
        "POST".to_string()
    } else {
        match read_c_str(method) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_uppercase(),
            Ok(_) => "POST".to_string(),
            Err(e) => return json_error(e),
        }
    };

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

    // A NULL or empty body sends no body — correct for GET/DELETE, and
    // avoids a spurious Content-Length: 0 on bodyless methods.
    let body_bytes: Option<Vec<u8>> = if body.is_null() {
        None
    } else {
        match read_c_str(body) {
            Ok(s) if !s.is_empty() => Some(s.into_bytes()),
            Ok(_) => None,
            Err(e) => return json_error(e),
        }
    };

    // Optional extra request headers, a JSON object of name → value (e.g.
    // {"X-Privasys-Voucher": "<jwt>"}). NULL or empty means none.
    let extra_headers: Vec<(String, String)> = if headers_json.is_null() {
        Vec::new()
    } else {
        match read_c_str(headers_json) {
            Ok(s) if !s.trim().is_empty() => {
                match serde_json::from_str::<std::collections::BTreeMap<String, String>>(&s) {
                    Ok(m) => m.into_iter().collect(),
                    Err(e) => return json_error(&format!("invalid headers_json: {e}")),
                }
            }
            Ok(_) => Vec::new(),
            Err(e) => return json_error(e),
        }
    };

    let mut client = match ratls_client::RaTlsClient::connect_with(
        &host_str,
        port,
        ratls_client::ConnectOptions {
            ca_cert_pem: ca_path,
            attestation,
            trust,
            ..ratls_client::ConnectOptions::default()
        },
    ) {
        Ok(c) => c,
        Err(e) => return json_error_kind(&format!("connection failed: {e}"), "connection"),
    };

    // Data-plane binding check: the evidence obtained at connect must commit
    // to this connection's leaf key (and, in challenge mode, to its exporter).
    // Fail closed: never send a request over a swapped certificate or a relayed
    // quote. Local and network-free; full verification with measurement
    // pinning and the attestation service happens at the flow gate. An
    // unattested request (attestation "none") has no evidence to check: its
    // chain was verified against the trust selection in the handshake.
    if attestation != ratls_client::AttestationMode::None {
        if let Err(e) = client.check_report_data_binding() {
            return json_error_kind(&e.message, e.kind.as_str());
        }
    }

    let (status, resp_body) = match client.http_request(
        &method_str,
        &path_str,
        body_bytes.as_deref(),
        None,
        if extra_headers.is_empty() {
            None
        } else {
            Some(&extra_headers)
        },
    ) {
        Ok(r) => r,
        Err(e) => return json_error(&format!("request failed: {e}")),
    };

    let resp_str = String::from_utf8_lossy(&resp_body);

    #[derive(serde::Serialize)]
    struct RequestResult {
        status: u16,
        body: String,
    }

    let result = RequestResult {
        status,
        body: resp_str.into_owned(),
    };

    to_c_string(
        &serde_json::to_string(&result)
            .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string()),
    )
}

/// Free a string returned by `ratls_inspect`, `ratls_verify`,
/// `ratls_post`, or `ratls_request`.
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
    #[serde(default)]
    attestation: Option<String>,
    /// Legacy name of `attestation` ("skip" | "deterministic" | "challenge").
    #[serde(default)]
    report_data_mode: Option<String>,
    #[serde(default)]
    attestation_server: Option<String>,
    #[serde(default)]
    attestation_server_token: Option<String>,
    /// Which anchors the server chain must reach: "auto" (default), "fleet"
    /// or "public" (unattested connections only).
    #[serde(default)]
    trust: Option<String>,
}

/// Parses the optional `trust` key of a policy or options JSON object.
fn parse_trust(json: &str) -> Result<ratls_client::TrustSelection, String> {
    #[derive(serde::Deserialize)]
    struct T {
        #[serde(default)]
        trust: Option<String>,
    }
    let t: T = serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    match t.trust.as_deref() {
        None => Ok(ratls_client::TrustSelection::Auto),
        Some(s) => ratls_client::TrustSelection::parse(s)
            .ok_or_else(|| format!("unknown trust selection: {s} (auto | fleet | public)")),
    }
}

fn parse_policy_json(json: &str) -> Result<(VerificationPolicy, AttestationMode), String> {
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

    let mode_str = p
        .attestation
        .or(p.report_data_mode)
        .unwrap_or_else(|| "challenge".to_string());
    let attestation = match mode_str.as_str() {
        "challenge" => AttestationMode::Challenge,
        "deterministic" => AttestationMode::Deterministic,
        "none" | "skip" => AttestationMode::None,
        other => return Err(format!("unknown attestation mode: {other}")),
    };

    let quote_verification = p
        .attestation_server
        .map(|endpoint| QuoteVerificationConfig {
            endpoint,
            token: p.attestation_server_token,
            accepted_statuses: vec![
                QuoteVerificationStatus::Ok,
                QuoteVerificationStatus::SwHardeningNeeded,
            ],
            enforce_tcb_status: false,
            acceptable_tcb_statuses: Vec::new(),
            timeout_secs: 10,
        });

    Ok((
        VerificationPolicy {
            tee,
            mr_enclave,
            mr_signer,
            mr_td,
            measurement: None,
            host_data: None,
            expected_oids: Vec::new(),
            quote_verification,
            allow_debug_images: false,
            allowed_platform_ids: Vec::new(),
        },
        attestation,
    ))
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
