// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

/// @file ratls_mobile.h
/// @brief C FFI for RA-TLS attestation verification on iOS and Android.
///
/// All returned strings are heap-allocated JSON. The caller MUST free them
/// with ratls_free_string().

#ifndef RATLS_MOBILE_H
#define RATLS_MOBILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Connect to an enclave and inspect its RA-TLS certificate.
///
/// @param host         Hostname or IP (null-terminated UTF-8).
/// @param port         TCP port number.
/// @param ca_cert_path Optional path to a CA PEM file (NULL to skip CA verification).
/// @return             JSON string — call ratls_free_string() when done.
///
/// Success: { "valid": true, "tee_type": "sgx"|"tdx", "mrenclave": "hex", ... }
/// Error:   { "error": "description" }
char *ratls_inspect(const char *host, uint16_t port, const char *ca_cert_path);

/// Connect to an enclave and verify its RA-TLS certificate against a policy.
///
/// @param host         Hostname or IP (null-terminated UTF-8).
/// @param port         TCP port number.
/// @param ca_cert_path Optional path to a CA PEM file (NULL to skip CA verification).
/// @param policy_json  JSON-encoded VerificationPolicy (null-terminated).
/// @return             JSON string — call ratls_free_string() when done.
///
/// Policy JSON fields:
///   - "tee": "sgx" | "tdx"                                (required)
///   - "mrenclave": "hex64"                                 (optional, SGX)
///   - "mrsigner": "hex64"                                  (optional, SGX)
///   - "mrtd": "hex96"                                      (optional, TDX)
///   - "report_data_mode": "deterministic"|"challenge"|"skip" (default: "deterministic")
///   - "nonce": "hex"                                       (required if mode = "challenge")
///   - "attestation_server": "https://..."                  (optional)
///   - "attestation_server_token": "bearer-token"           (optional)
///
/// In challenge mode the nonce is sent in the TLS ClientHello (extension 0xFFBB)
/// so the enclave binds it into a fresh attestation certificate.
///
/// Success: { "valid": true, ... }
/// Error:   { "error": "description" }
char *ratls_verify(const char *host, uint16_t port, const char *ca_cert_path,
                   const char *policy_json);

/// Connect to an enclave via RA-TLS and perform an HTTP POST request.
///
/// @param host         Hostname or IP (null-terminated UTF-8).
/// @param port         TCP port number.
/// @param ca_cert_path Optional path to a CA PEM file (NULL to skip CA verification).
/// @param path         HTTP path (e.g. "/fido2/register/begin").
/// @param body         JSON request body (null-terminated UTF-8).
/// @param headers_json Optional JSON object of extra request headers
///                     (e.g. {"X-Privasys-Voucher": "<jwt>"}); NULL or "" for none.
/// @return             JSON string — call ratls_free_string() when done.
///
/// Success: { "status": 200, "body": "{...}" }
/// Error:   { "error": "description" }
char *ratls_post(const char *host, uint16_t port, const char *ca_cert_path,
                 const char *path, const char *body, const char *headers_json);

/// Connect to an enclave via RA-TLS and perform an HTTP request with an
/// arbitrary method (GET, POST, PUT, DELETE, ...).
///
/// @param method       HTTP method (null-terminated UTF-8, e.g. "GET").
///                     Empty or NULL defaults to "POST".
/// @param host         Hostname or IP (null-terminated UTF-8).
/// @param port         TCP port number.
/// @param ca_cert_path Optional path to a CA PEM file (NULL to skip CA verification).
/// @param path         HTTP path (e.g. "/tools/list_root").
/// @param body         Request body (null-terminated UTF-8). Empty or NULL sends
///                     no body — correct for GET/DELETE.
/// @param headers_json Optional JSON object of extra request headers; NULL/"" for none.
/// @return             JSON string — call ratls_free_string() when done.
///
/// Success: { "status": 200, "body": "{...}" }
/// Error:   { "error": "description" }
char *ratls_request(const char *method, const char *host, uint16_t port,
                    const char *ca_cert_path, const char *path, const char *body,
                    const char *headers_json);

/// Free a string previously returned by ratls_inspect, ratls_verify,
/// ratls_post, or ratls_request.
void ratls_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* RATLS_MOBILE_H */
