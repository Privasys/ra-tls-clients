// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! A re-attestation that fails closes the connection, as connect does: a
//! caller that ignores the error and carries on sends nothing.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ratls_client::{tdx_quote, AttestationMode, ConnectOptions, RaTlsClient, ATTEST_PATH};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

// The throwaway test chain of the TypeScript suite (test only).
const TEST_INT_PEM: &str = "
-----BEGIN CERTIFICATE-----
MIIBzjCCAXSgAwIBAgIUJzpQxvUXIvsr2a42hqdWoitrVrEwCgYIKoZIzj0EAwIw
LzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEVMBMGA1UEAwwMVGVzdCBSb290IENB
MB4XDTI2MDkwMzIyNDEzMFoXDTQ2MDgyOTIyNDEzMFowNzEWMBQGA1UECgwNUHJp
dmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATR08rSX+rzkqk9JSbNIRL9h+FkLzV+IrAydZjf
l6QgbvkRYpPLm+TG6qBTjN/OivzGI6MraNwivxtCLAXbWCwDo2YwZDASBgNVHRMB
Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUo97Wc5XDoLk+
6u1owtYk9xqHsIAwHwYDVR0jBBgwFoAU0egHSXwwMsN3Nnq2Gj4ciEF5n6AwCgYI
KoZIzj0EAwIDSAAwRQIgAYlVC6kjlDBH3bvUuRbeGfasnSEysYuiAFsS+fcPld4C
IQD7fZ4+YdASXdBDIVWuV/Y+MGatiItSSM8h97Kyy+AvWw==
-----END CERTIFICATE-----

";
const TEST_LEAF_PEM: &str = "
-----BEGIN CERTIFICATE-----
MIICeTCCAiCgAwIBAgIUfUggqUJUTiNkvZseSvZA61cMUa4wCgYIKoZIzj0EAwIw
NzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1l
ZGlhdGUgQ0EwHhcNMjYwOTAzMjI1OTQ5WhcNNDYwODI5MjI1OTQ5WjAnMRYwFAYD
VQQKDA1Qcml2YXN5cyBUZXN0MQ0wCwYDVQQDDARsZWFmMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE8mCYAdUnf3Wp8tx7pL1goYTJBmAaPzVMexefNcCqtkPAA1To
QFVcRx76VFCgoc5Yg+fdglJUSklhY6UusRO7EaOCARgwggEUMAkGA1UdEwQCMAAw
DgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwGAYKKwYBBAGD/U4BAgQKcHJvZHVj
dGlvbjAeBgorBgEEAYP9TgQBBBABI0VniavN7wEjRWeJq83vMC4GCisGAQQBg/1O
BAIEIAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/MBIGCisGAQQBg/1O
BwEEBAAAAAAwHQYDVR0OBBYEFGVs/nZ/hGvbn3MIImRTkpFeIuR1MB8GA1UdIwQY
MBaAFKPe1nOVw6C5PurtaMLWJPcah7CAMAoGCCqGSM49BAMCA0cAMEQCIEZanrse
0gRCVeW08t25qU1AISjgC4Tf9WKZAMH/6yRnAiAQOC4qOWAzrKT02JnrMPxyeSSe
1jYiEoj3DXoZ63W/ZQ==
-----END CERTIFICATE-----

";
const TEST_LEAF_KEY_PEM: &str = "
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGcB19WyRZHU/MvdWxfw0tPD9KuAX6rVxbpuguZnfo/xoAoGCCqGSM49
AwEHoUQDQgAE8mCYAdUnf3Wp8tx7pL1goYTJBmAaPzVMexefNcCqtkPAA1ToQFVc
Rx76VFCgoc5Yg+fdglJUSklhY6UusRO7EQ==
-----END EC PRIVATE KEY-----

";

/// "YYYY-MM-DDTHH:MMZ" for now, UTC.
fn quote_time_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Read one HTTP/1.1 request; None when the peer closed.
fn read_request(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match tls.read(&mut byte) {
            Ok(1) => buf.push(byte[0]),
            _ => return None,
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    tls.read_exact(&mut body).ok()?;
    Some(head.split(' ').nth(1).unwrap_or_default().to_string())
}

fn reply(tls: &mut StreamOwned<ServerConnection, TcpStream>, status: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = tls.write_all(msg.as_bytes());
    let _ = tls.flush();
}

/// A loopback server whose first evidence exchange succeeds and every later
/// one fails. Returns its port and the request paths it receives.
fn start_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut format!("{TEST_LEAF_PEM}{TEST_INT_PEM}").as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut TEST_LEAF_KEY_PEM.as_bytes())
            .unwrap()
            .unwrap();
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let seen = paths.clone();
    std::thread::spawn(move || {
        let mut attests = 0;
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let mut tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), tcp);
            while let Some(path) = read_request(&mut tls) {
                seen.lock().unwrap().push(path.clone());
                if path != ATTEST_PATH {
                    reply(&mut tls, "200 OK", r#"{"status":"ok"}"#);
                    continue;
                }
                attests += 1;
                if attests > 1 {
                    reply(
                        &mut tls,
                        "500 Internal Server Error",
                        r#"{"v":2,"error":"evidence unavailable"}"#,
                    );
                    continue;
                }
                let mut quote = vec![0u8; tdx_quote::MIN_SIZE];
                quote[0] = 4;
                let body = format!(
                    r#"{{"v":2,"mode":"deterministic","tee":"tdx","quote":"{}","gpu_evidence":null,"quote_time":"{}","client_evidence":"none","client_context":null}}"#,
                    URL_SAFE_NO_PAD.encode(&quote),
                    quote_time_now()
                );
                reply(&mut tls, "200 OK", &body);
            }
        }
    });
    (port, paths)
}

#[test]
fn failed_reattest_closes_the_connection() {
    let (port, paths) = start_server();
    let anchor = std::env::temp_dir().join(format!("ratls-reattest-anchor-{port}.pem"));
    std::fs::write(&anchor, TEST_INT_PEM).unwrap();
    let mut client = RaTlsClient::connect_with(
        "127.0.0.1",
        port,
        ConnectOptions {
            ca_cert_pem: Some(anchor.to_string_lossy().into_owned()),
            attestation: AttestationMode::Deterministic,
            ..ConnectOptions::default()
        },
    )
    .expect("connect");
    let _ = std::fs::remove_file(&anchor);

    assert!(
        client.reattest().is_err(),
        "re-attestation succeeded against failing evidence"
    );
    let err = client
        .http_post("/after-failure", b"must not be sent", None, None)
        .expect_err("a request went out after a failed re-attestation");
    assert_eq!(err.kind(), std::io::ErrorKind::NotConnected);
    assert!(client.healthz().is_err());
    std::thread::sleep(std::time::Duration::from_millis(100));
    let seen = paths.lock().unwrap().clone();
    assert!(
        !seen
            .iter()
            .any(|p| p == "/after-failure" || p == "/healthz"),
        "server saw {seen:?}"
    );
}
