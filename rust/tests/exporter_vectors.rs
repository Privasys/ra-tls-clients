//! Pins the RFC 8446 section 7.5 exporter computation for the RA-TLS v2 labels
//! against the shared vectors in `tests/vectors/ratls-v2/exporter.json`,
//! independently of the TLS stack: a stack that returns the expected `hctx`
//! for the recorded `exporter_master_secret` derives the same binding as every
//! other SDK.

use ring::hmac;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    hash: String,
    exporter_master_secret: String,
    label: String,
    context: String,
    length: usize,
    hctx: String,
    client_label: String,
    client_hctx: String,
}

#[derive(Deserialize)]
struct File {
    vectors: Vec<Vector>,
}

fn hash_of(alg: hmac::Algorithm, data: &[u8]) -> Vec<u8> {
    let d = match alg {
        a if a == hmac::HMAC_SHA256 => ring::digest::digest(&ring::digest::SHA256, data),
        _ => ring::digest::digest(&ring::digest::SHA384, data),
    };
    d.as_ref().to_vec()
}

/// HKDF-Expand-Label (RFC 8446 section 7.1) with a manual HKDF-Expand.
fn hkdf_expand_label(
    alg: hmac::Algorithm,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let key = hmac::Key::new(alg, secret);
    let mut out = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&prev);
        ctx.update(&info);
        ctx.update(&[counter]);
        prev = ctx.sign().as_ref().to_vec();
        out.extend_from_slice(&prev);
        counter += 1;
    }
    out.truncate(length);
    out
}

/// TLS-Exporter(label, context, length) over the exporter master secret.
fn tls_exporter(
    alg: hmac::Algorithm,
    ems: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    let empty = hash_of(alg, b"");
    let derived = hkdf_expand_label(alg, ems, label, &empty, empty.len());
    let ctx_hash = hash_of(alg, context);
    hkdf_expand_label(alg, &derived, "exporter", &ctx_hash, length)
}

#[test]
fn exporter_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/vectors/ratls-v2/exporter.json"
    );
    let raw = std::fs::read_to_string(path).expect("read exporter.json");
    let file: File = serde_json::from_str(&raw).expect("parse exporter.json");
    assert!(!file.vectors.is_empty());
    for v in &file.vectors {
        let alg = match v.hash.as_str() {
            "sha256" => hmac::HMAC_SHA256,
            "sha384" => hmac::HMAC_SHA384,
            other => panic!("{}: unknown hash {other}", v.name),
        };
        assert_eq!(
            v.label.as_bytes(),
            ratls_client::attest::EXPORTER_LABEL_SERVER,
            "{}",
            v.name
        );
        assert_eq!(
            v.client_label.as_bytes(),
            ratls_client::attest::EXPORTER_LABEL_CLIENT,
            "{}",
            v.name
        );
        let ems = hex::decode(&v.exporter_master_secret).unwrap();
        let ctx = hex::decode(&v.context).unwrap();
        assert_eq!(
            hex::encode(tls_exporter(alg, &ems, &v.label, &ctx, v.length)),
            v.hctx,
            "{} server",
            v.name
        );
        assert_eq!(
            hex::encode(tls_exporter(alg, &ems, &v.client_label, &ctx, v.length)),
            v.client_hctx,
            "{} client",
            v.name
        );
    }
}
