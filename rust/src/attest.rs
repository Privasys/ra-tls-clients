// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS v2: attestation evidence after the handshake (`docs/ratls-v2.md`).
//!
//! The certificate identifies the enclave (leaf key, chain to the Privasys
//! intermediate, Privasys OIDs) and carries no evidence. After the handshake the
//! client asks for a quote on the same connection, before any application data,
//! and checks that its `report_data` commits to the leaf key and, in challenge
//! mode, to a value only the two ends of this TLS connection can derive (an
//! RFC 8446 section 7.5 exporter keyed by `exporter_master_secret`).

use std::io::{self, Read, Write};

use base64::Engine;
use ring::digest;
use serde::{Deserialize, Serialize};

use crate::{detect_sgx_format, sev_snp_report, sgx_offsets, tdx_quote, TeeType};

/// Reserved path of the evidence endpoint on every RA-TLS v2 server (HTTP binding).
pub const ATTEST_PATH: &str = "/__privasys/attest";
/// The `v` field of every attest message.
pub const PROTOCOL_VERSION: u32 = 2;
/// Exporter label of the server evidence of a connection.
pub const EXPORTER_LABEL_SERVER: &[u8] = b"EXPORTER-privasys-ratls-attest-v2";
/// Exporter label of the client evidence of a connection (mutual leg).
pub const EXPORTER_LABEL_CLIENT: &[u8] = b"EXPORTER-privasys-ratls-attest-v2-client";
/// Length of a challenge context.
pub const CONTEXT_LEN: usize = 32;
/// Length of the exporter output.
pub const HCTX_LEN: usize = 32;
/// Largest raw-binding frame accepted.
pub const MAX_FRAME: usize = 65536;
/// Length of `quote_time` (`YYYY-MM-DDTHH:MMZ`).
pub const QUOTE_TIME_LEN: usize = 17;

const QUOTE_MAX_AGE_SECS: i64 = 24 * 3600 + 5 * 60;
const QUOTE_SKEW_SECS: i64 = 5 * 60;

/// What the client asks the server for after the handshake. The default is
/// `Challenge`, the safe choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttestationMode {
    /// A quote bound to this connection through the TLS exporter and a fresh
    /// context (Level 3 binding).
    #[default]
    Challenge,
    /// The runtime's cached quote, bound to the leaf key and a minute
    /// timestamp only (the "trust the TEE" tier).
    Deterministic,
    /// No request; the server tags the connection attestation-not-requested
    /// and verification covers the certificate extensions only.
    None,
}

impl AttestationMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationMode::Challenge => "challenge",
            AttestationMode::Deterministic => "deterministic",
            AttestationMode::None => "none",
        }
    }
}

impl std::fmt::Display for AttestationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the attest messages are carried on the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Framing {
    /// `POST /__privasys/attest` as an HTTP/1.1 request.
    #[default]
    Http,
    /// One `u32` big-endian length-prefixed JSON frame in each direction as
    /// the first application records, for legs that do not speak HTTP.
    Raw,
}

/// The evidence a server returned for a connection.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub mode: AttestationMode,
    /// Evidence family: "sgx", "tdx", "tdx-gpu".
    pub tee: String,
    /// Raw DCAP quote.
    pub quote: Vec<u8>,
    /// NVIDIA CC evidence bundle, when present.
    pub gpu_evidence: Option<Vec<u8>>,
    /// The 17-byte `quote_time`, an input of `report_data` in deterministic mode.
    pub quote_time: String,
    /// The client's context (challenge mode).
    pub context: Option<[u8; CONTEXT_LEN]>,
    /// This connection's exporter output for `context` (challenge mode).
    pub hctx: Option<[u8; HCTX_LEN]>,
    /// The server asked for client evidence (mutual leg) with this context.
    pub client_evidence_required: bool,
    pub client_context: Option<[u8; CONTEXT_LEN]>,
}

/// What a client-evidence source receives on a mutual leg.
#[derive(Debug, Clone)]
pub struct ClientEvidenceRequest {
    /// DER SubjectPublicKeyInfo of the presented client certificate.
    pub spki_der: Vec<u8>,
    /// The server-chosen `client_context`.
    pub context: [u8; CONTEXT_LEN],
    /// This connection's exporter output under [`EXPORTER_LABEL_CLIENT`].
    pub hctx: [u8; HCTX_LEN],
    /// The value the quote must carry (without a GPU fold).
    pub report_data: [u8; 64],
}

/// What a client-evidence source returns.
#[derive(Debug, Clone)]
pub struct ClientEvidence {
    pub tee: String,
    pub quote: Vec<u8>,
    pub gpu_evidence: Option<Vec<u8>>,
    pub quote_time: String,
}

/// Produces this client's own evidence for a mutual leg.
pub type ClientEvidenceSource =
    Box<dyn Fn(&ClientEvidenceRequest) -> Result<ClientEvidence, String> + Send + Sync>;

// -- messages ---------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct AttestRequest<'a> {
    pub v: u32,
    pub mode: &'a str,
    pub leaf: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AttestResponse {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub tee: String,
    #[serde(default)]
    pub quote: String,
    #[serde(default)]
    pub gpu_evidence: Option<String>,
    #[serde(default)]
    pub quote_time: String,
    #[serde(default)]
    pub client_evidence: String,
    #[serde(default)]
    pub client_context: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct PresentRequest {
    pub v: u32,
    pub mode: &'static str,
    pub context: String,
    pub tee: String,
    pub quote: String,
    pub gpu_evidence: Option<String>,
    pub quote_time: String,
}

#[derive(Deserialize)]
pub(crate) struct Ack {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub error: Option<String>,
}

pub(crate) fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("base64url: {e}"))
}

// -- report_data ------------------------------------------------------------

fn report_data_hash(spki_der: &[u8], binding: &[u8]) -> [u8; 64] {
    let pk = digest::digest(&digest::SHA256, spki_der);
    let mut buf = Vec::with_capacity(32 + binding.len());
    buf.extend_from_slice(pk.as_ref());
    buf.extend_from_slice(binding);
    let h = digest::digest(&digest::SHA512, &buf);
    let mut out = [0u8; 64];
    out.copy_from_slice(h.as_ref());
    out
}

/// The `report_data` a quote must carry for the leaf whose SPKI is `spki_der`
/// and the evidence `ev`:
///
/// ```text
/// deterministic: SHA-512( SHA-256(SPKI_DER) || quote_time )
/// challenge:     SHA-512( SHA-256(SPKI_DER) || context || hctx )
/// ```
///
/// with `SHA-256(gpu_evidence)` appended to the binding when GPU evidence is
/// present. The verifier predicts this value; it never accepts one from the peer.
pub fn expected_report_data(spki_der: &[u8], ev: &Evidence) -> Result<[u8; 64], String> {
    let mut binding = match ev.mode {
        AttestationMode::Deterministic => {
            if ev.quote_time.len() != QUOTE_TIME_LEN {
                return Err("deterministic evidence needs a quote_time".into());
            }
            ev.quote_time.as_bytes().to_vec()
        }
        AttestationMode::Challenge => {
            let (ctx, hctx) = match (ev.context, ev.hctx) {
                (Some(c), Some(h)) => (c, h),
                _ => return Err("challenge evidence needs a context and an exporter value".into()),
            };
            let mut b = ctx.to_vec();
            b.extend_from_slice(&hctx);
            b
        }
        AttestationMode::None => return Err("no report_data for attestation mode none".into()),
    };
    if let Some(gpu) = ev.gpu_evidence.as_deref().filter(|g| !g.is_empty()) {
        binding.extend_from_slice(digest::digest(&digest::SHA256, gpu).as_ref());
    }
    Ok(report_data_hash(spki_der, &binding))
}

/// `report_data` of the client evidence on a mutual leg:
/// `SHA-512( SHA-256(client SPKI) || client_context || hctx_c )` with the same GPU fold.
pub fn client_report_data(
    spki_der: &[u8],
    client_context: &[u8],
    hctx: &[u8],
    gpu_evidence: Option<&[u8]>,
) -> [u8; 64] {
    let mut binding = client_context.to_vec();
    binding.extend_from_slice(hctx);
    if let Some(gpu) = gpu_evidence.filter(|g| !g.is_empty()) {
        binding.extend_from_slice(digest::digest(&digest::SHA256, gpu).as_ref());
    }
    report_data_hash(spki_der, &binding)
}

/// The 64-byte `report_data` of a raw quote of the given evidence family.
pub fn quote_report_data<'a>(tee: &str, quote: &'a [u8]) -> Result<&'a [u8], String> {
    let range = match tee {
        "sgx" => {
            let (_, _, rd, _) = sgx_offsets(detect_sgx_format(quote));
            rd
        }
        "tdx" | "tdx-gpu" => tdx_quote::REPORT_DATA,
        "sev-snp" => sev_snp_report::REPORT_DATA,
        other => return Err(format!("unknown evidence family {other:?}")),
    };
    if quote.len() < range.end {
        return Err("quote too small to contain report_data".into());
    }
    Ok(&quote[range])
}

/// The [`TeeType`] of an evidence family string.
pub fn tee_type_of(tee: &str) -> Option<TeeType> {
    match tee {
        "sgx" => Some(TeeType::Sgx),
        "tdx" | "tdx-gpu" => Some(TeeType::Tdx),
        "sev-snp" => Some(TeeType::SevSnp),
        _ => None,
    }
}

/// Rejects a `quote_time` older than the cache lifetime (24 h) or ahead of the
/// clock by more than 5 minutes. `now_unix` is seconds since the epoch.
pub fn check_quote_time(raw: &str, now_unix: i64) -> Result<i64, String> {
    let t = parse_quote_time(raw)
        .ok_or_else(|| format!("quote_time {raw:?} is not YYYY-MM-DDTHH:MMZ"))?;
    if t > now_unix + QUOTE_SKEW_SECS {
        return Err(format!("quote_time {raw} is in the future"));
    }
    if now_unix - t > QUOTE_MAX_AGE_SECS {
        return Err(format!("quote_time {raw} is older than 24 hours"));
    }
    Ok(t)
}

/// Parses `YYYY-MM-DDTHH:MMZ` to seconds since the epoch.
pub fn parse_quote_time(raw: &str) -> Option<i64> {
    let b = raw.as_bytes();
    if b.len() != QUOTE_TIME_LEN
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b'Z'
    {
        return None;
    }
    let num = |s: &[u8]| -> Option<i64> {
        let mut v = 0i64;
        for &c in s {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as i64;
        }
        Some(v)
    };
    let (y, m, d) = (num(&b[0..4])?, num(&b[5..7])?, num(&b[8..10])?);
    let (hh, mm) = (num(&b[11..13])?, num(&b[14..16])?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 {
        return None;
    }
    // Days from civil (Howard Hinnant), valid for the proleptic Gregorian calendar.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60)
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// -- raw framing ------------------------------------------------------------

pub(crate) fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    w.write_all(&frame)
}

pub(crate) fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// SHA-256 of the SPKI DER of a leaf, base64url: the `leaf` field of a request.
pub(crate) fn leaf_id(spki_der: &[u8]) -> String {
    b64_encode(digest::digest(&digest::SHA256, spki_der).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_time_parses_and_bounds() {
        let t = parse_quote_time("2026-09-04T12:00Z").unwrap();
        assert_eq!(t, 1788523200);
        assert!(check_quote_time("2026-09-04T11:59Z", t).is_ok());
        assert!(check_quote_time("2026-09-03T12:03Z", t).is_ok());
        assert!(check_quote_time("2026-09-03T11:50Z", t).is_err());
        assert!(check_quote_time("2026-09-04T12:06Z", t).is_err());
        assert!(parse_quote_time("2026-09-04T12:00:00Z").is_none());
    }

    #[test]
    fn recipes_match_definition() {
        let spki = [7u8; 91];
        let pk = digest::digest(&digest::SHA256, &spki);
        let det = Evidence {
            mode: AttestationMode::Deterministic,
            tee: "tdx".into(),
            quote: vec![],
            gpu_evidence: None,
            quote_time: "2026-09-04T10:15Z".into(),
            context: None,
            hctx: None,
            client_evidence_required: false,
            client_context: None,
        };
        let mut pre = pk.as_ref().to_vec();
        pre.extend_from_slice(b"2026-09-04T10:15Z");
        let want = digest::digest(&digest::SHA512, &pre);
        assert_eq!(
            expected_report_data(&spki, &det).unwrap().as_slice(),
            want.as_ref()
        );

        let ctx = [0xC0u8; 32];
        let hctx = [0xE1u8; 32];
        let ch = Evidence {
            mode: AttestationMode::Challenge,
            context: Some(ctx),
            hctx: Some(hctx),
            gpu_evidence: Some(b"PGAE\x01 gpu".to_vec()),
            ..det.clone()
        };
        let mut pre = pk.as_ref().to_vec();
        pre.extend_from_slice(&ctx);
        pre.extend_from_slice(&hctx);
        pre.extend_from_slice(digest::digest(&digest::SHA256, b"PGAE\x01 gpu").as_ref());
        let want = digest::digest(&digest::SHA512, &pre);
        assert_eq!(
            expected_report_data(&spki, &ch).unwrap().as_slice(),
            want.as_ref()
        );
        assert_eq!(
            client_report_data(&spki, &ctx, &hctx, Some(b"PGAE\x01 gpu")).as_slice(),
            want.as_ref()
        );
        assert!(expected_report_data(
            &spki,
            &Evidence {
                mode: AttestationMode::None,
                ..det.clone()
            }
        )
        .is_err());
    }

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"v":2}"#).unwrap();
        let got = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(got, br#"{"v":2}"#);
        assert!(write_frame(&mut buf, &vec![0u8; MAX_FRAME + 1]).is_err());
    }
}
