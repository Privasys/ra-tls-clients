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

/// Map OID dotted-string → human label.
pub fn oid_label(oid: &str) -> &'static str {
    match oid {
        OID_SGX_QUOTE => "SGX Quote",
        OID_TDX_QUOTE => "TDX Quote",
        _ => "Unknown",
    }
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
    }

    q
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
            }
        }
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
        let preview_len = q.raw.len().min(32);
        println!("    Preview   : {}...", hex::encode(&q.raw[..preview_len]));
    } else {
        println!();
        println!("  No RA-TLS extension found.");
    }
}
