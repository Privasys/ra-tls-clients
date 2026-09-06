# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

"""RA-TLS v2 tests for the Python SDK (docs/ratls-v2.md section 8).

Checks the shared JSON vectors in tests/vectors/ratls-v2/ (report_data.json,
and messages.json / exporter.json when present), the message parser and its
rejections, the raw framing, the exporter step through a pure HKDF-Expand-Label
implementation (no TLS stack), certificate inspection and evidence
verification on synthetic leaves, the dependency-set encoding, and, when the
cryptography package is installed, a loopback TLS 1.3 exchange against a fake
v2 server in both bindings.

Run: python -m pytest python/
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import ssl
import struct
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ratls_client as rc  # noqa: E402
from ratls_client import (  # noqa: E402
    AttestationMode, DependencyEntry, DependencySet, DepMeasurement, DepTdxMeasurement,
    Evidence, ExpectedOid, Framing, RaTlsClient, TeeType, TlsBackend, TrustMode, VerificationPolicy,
    build_attest_request, check_quote_time, client_report_data, decode_dependency_set,
    encode_dependency_set, encode_frame, expected_report_data, fold_identity_hex,
    hkdf_expand_label, inspect_der_certificate, parse_attest_response, quote_report_data,
    read_frame, tls_exporter, verify_certificate_extensions, verify_evidence,
    verify_peer_is_dependency,
)
from oids_gen import (  # noqa: E402
    OID_IMAGE_PROFILE, OID_SGX_QUOTE, OID_TDX_QUOTE, OID_WORKLOAD_APP_ID, OID_WORKLOAD_CODE_HASH,
    OID_WORKLOAD_MODEL_DIGEST,
)

VECTORS_DIR = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "ratls-v2"

# The P-256 generator point as an SPKI, the fixed key of every SDK's vectors.
VECTOR_SPKI = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f2"
    "77037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb640"
    "6837bf51f5")
QUOTE_TIME = "2026-09-04T10:15Z"
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


def load_vectors(name: str):
    path = VECTORS_DIR / name
    return json.loads(path.read_text()) if path.exists() else None


# ---------------------------------------------------------------------------
#  Tiny DER writer for synthetic (unsigned) leaves
# ---------------------------------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def der_oid(s: str) -> bytes:
    comps = [int(c) for c in s.split(".")]
    out = bytearray([40 * comps[0] + comps[1]])
    for c in comps[2:]:
        chunk = bytearray([c & 0x7F])
        c >>= 7
        while c:
            chunk.insert(0, 0x80 | (c & 0x7F))
            c >>= 7
        out += chunk
    return tlv(0x06, bytes(out))


def der_name(cn: str) -> bytes:
    return tlv(0x30, tlv(0x31, tlv(0x30, der_oid("2.5.4.3") + tlv(0x0C, cn.encode()))))


def der_ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    crit = tlv(0x01, b"\xff") if critical else b""
    return tlv(0x30, der_oid(oid) + crit + tlv(0x04, value))


def make_cert(exts: list[bytes], spki: bytes = VECTOR_SPKI) -> bytes:
    """An X.509 v3 certificate with the given extensions and a dummy signature.
    Signatures are the handshake's business; inspection never checks them."""
    sig_alg = tlv(0x30, der_oid("1.2.840.10045.4.3.2"))
    tbs = tlv(0x30, (
        tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x2a") + sig_alg
        + der_name("Privasys Intermediate CA")
        + tlv(0x30, tlv(0x17, b"260904101500Z") + tlv(0x17, b"260905101500Z"))
        + der_name("enclave") + spki
        + (tlv(0xA3, tlv(0x30, b"".join(exts))) if exts else b"")))
    return tlv(0x30, tbs + sig_alg + tlv(0x03, b"\x00" + b"\x30\x06\x02\x01\x01\x02\x01\x01"))


MRTD = bytes(range(48))
APP_ID = bytes.fromhex("0123456789abcdef0123456789abcdef")
CALLER_APP_ID = bytes.fromhex("fedcba9876543210fedcba9876543210")


def tdx_quote_with(report_data: bytes, mrtd: bytes = MRTD) -> bytes:
    raw = bytearray(rc.TDX_QUOTE_MIN_SIZE)
    raw[0:2] = b"\x04\x00"
    raw[rc.TDX_QUOTE_MRTD] = mrtd
    raw[rc.TDX_QUOTE_REPORT_DATA] = report_data
    return bytes(raw)


def sgx_quote_with(report_data: bytes) -> bytes:
    raw = bytearray(rc.SGX_QUOTE_MIN_SIZE)
    raw[0:2] = b"\x03\x00"
    raw[rc.SGX_QUOTE_REPORT_DATA] = report_data
    return bytes(raw)


def b64u(b: bytes) -> str:
    return rc._b64(b)


# ---------------------------------------------------------------------------
#  report_data
# ---------------------------------------------------------------------------

REPORT_DATA_VECTORS = load_vectors("report_data.json")


@pytest.mark.skipif(REPORT_DATA_VECTORS is None, reason="tests/vectors/ratls-v2/report_data.json missing")
@pytest.mark.parametrize("vec", REPORT_DATA_VECTORS or [], ids=lambda v: v["name"])
def test_report_data_vectors(vec):
    ev = Evidence(mode=AttestationMode(vec["mode"]))
    if vec["mode"] == "deterministic":
        ev.quote_time_raw = vec["quote_time"]
    else:
        ev.context = bytes.fromhex(vec["context"])
        ev.hctx = bytes.fromhex(vec["hctx"])
    if vec.get("gpu_evidence"):
        ev.gpu_evidence = bytes.fromhex(vec["gpu_evidence"])
    got = expected_report_data(bytes.fromhex(vec["spki_der"]), ev)
    assert got.hex() == vec["report_data"]
    assert len(got) == 64


def test_report_data_vectors_cover_both_modes_with_and_without_gpu():
    assert REPORT_DATA_VECTORS is not None
    names = {v["name"] for v in REPORT_DATA_VECTORS}
    assert {"deterministic", "deterministic-gpu", "challenge", "challenge-gpu"} <= names


def test_report_data_recipes():
    pk = hashlib.sha256(VECTOR_SPKI).digest()
    det = Evidence(mode=AttestationMode.DETERMINISTIC, quote_time_raw=QUOTE_TIME)
    assert expected_report_data(VECTOR_SPKI, det) == hashlib.sha512(pk + QUOTE_TIME.encode()).digest()

    ctx, hctx = bytes([0xC0]) * 32, bytes([0xE1]) * 32
    ch = Evidence(mode=AttestationMode.CHALLENGE, context=ctx, hctx=hctx)
    assert expected_report_data(VECTOR_SPKI, ch) == hashlib.sha512(pk + ctx + hctx).digest()

    # The GPU fold appends SHA-256(gpu_evidence) after the binding.
    gpu = b"PGAE\x01 gpu evidence envelope"
    ch.gpu_evidence = gpu
    assert expected_report_data(VECTOR_SPKI, ch) == hashlib.sha512(
        pk + ctx + hctx + hashlib.sha256(gpu).digest()).digest()

    # Malformed evidence never yields a value.
    with pytest.raises(ValueError):
        expected_report_data(VECTOR_SPKI, Evidence(mode=AttestationMode.CHALLENGE, context=ctx[:31], hctx=hctx))
    with pytest.raises(ValueError):
        expected_report_data(VECTOR_SPKI, Evidence(mode=AttestationMode.DETERMINISTIC))
    with pytest.raises(ValueError):
        expected_report_data(VECTOR_SPKI, Evidence(mode=AttestationMode.NONE))


def test_client_report_data_matches_server_recipe():
    ctx, hctx = bytes([1]) * 32, bytes([2]) * 32
    ev = Evidence(mode=AttestationMode.CHALLENGE, context=ctx, hctx=hctx)
    assert client_report_data(VECTOR_SPKI, ctx, hctx) == expected_report_data(VECTOR_SPKI, ev)
    ev.gpu_evidence = b"gpu"
    assert client_report_data(VECTOR_SPKI, ctx, hctx, b"gpu") == expected_report_data(VECTOR_SPKI, ev)


def test_quote_report_data_offsets():
    rd = bytes(range(64))
    assert quote_report_data("tdx", tdx_quote_with(rd)) == rd
    assert quote_report_data("tdx-gpu", tdx_quote_with(rd)) == rd
    assert quote_report_data("sgx", sgx_quote_with(rd)) == rd
    raw_report = bytearray(rc.SGX_REPORT_SIZE)
    raw_report[rc.SGX_REPORT_REPORT_DATA] = rd
    assert quote_report_data("sgx", bytes(raw_report)) == rd
    snp = bytearray(rc.SEV_SNP_REPORT_MIN_SIZE)
    snp[rc.SEV_SNP_REPORT_DATA] = rd
    assert quote_report_data("sev-snp", bytes(snp)) == rd
    with pytest.raises(ValueError):
        quote_report_data("tdx", b"\x04\x00short")
    with pytest.raises(ValueError):
        quote_report_data("nvidia-gpu", tdx_quote_with(rd))


# ---------------------------------------------------------------------------
#  quote_time
# ---------------------------------------------------------------------------

def test_check_quote_time():
    assert check_quote_time("2026-09-04T11:59Z", NOW) == datetime(2026, 9, 4, 11, 59, tzinfo=timezone.utc)
    check_quote_time("2026-09-03T12:03Z", NOW)             # 23h57m old, within 24h + skew
    check_quote_time("2026-09-04T12:04Z", NOW)             # 4 minutes ahead, within skew
    with pytest.raises(ValueError, match="older than 24 hours"):
        check_quote_time("2026-09-03T11:50Z", NOW)
    with pytest.raises(ValueError, match="in the future"):
        check_quote_time("2026-09-04T12:06Z", NOW)
    with pytest.raises(ValueError):
        check_quote_time("2026-09-04T12:00:00Z", NOW)      # seconds are not part of the layout
    with pytest.raises(ValueError):
        check_quote_time("2026-09-04 12:00Z", NOW)


# ---------------------------------------------------------------------------
#  Exporter (RFC 8446 section 7.5) without a TLS stack
# ---------------------------------------------------------------------------

# Generated on 2026-09-03 with a loopback TLS 1.3 connection between a CPython
# ssl server (OpenSSL 3.0.18, keylog_filename giving EXPORTER_SECRET) and a Go
# 1.26 crypto/tls client calling ConnectionState.ExportKeyingMaterial for both
# labels, with context = c0 c1 ... df. Two suites, so both hash sizes are covered.
INLINE_EXPORTER_VECTORS = [
    {
        "name": "TLS_AES_128_GCM_SHA256", "hash": "sha256",
        "exporter_master_secret": "17f32629ff38faaa7c23496c19e7a3a28a040b896560c4e5e86186454aaf74e4",
        "label": rc.EXPORTER_LABEL_SERVER,
        "context": "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "length": 32,
        "hctx": "907268c026c4a010af461aa5ae8113e19fbc0ed53b45bb203940e0aeec822499",
        "client_label": rc.EXPORTER_LABEL_CLIENT,
        "client_hctx": "a57634d73fcaea9834b13f152de2b9d7ec1c71a47f8e8ffbbcb97a9b83b4886b",
    },
    {
        "name": "TLS_AES_256_GCM_SHA384", "hash": "sha384",
        "exporter_master_secret": ("2f448e34be0270ff9c8dc44f615c7b7371ce043cc830107e8c9c268e624cceb7"
                                   "ca6245b072fb355935f5c44c26e6a8ec"),
        "label": rc.EXPORTER_LABEL_SERVER,
        "context": "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "length": 32,
        "hctx": "91da8ee68056b2475da639b1c3ffb7ba5c21fcb2811f0c62f605f38d6926d25d",
        "client_label": rc.EXPORTER_LABEL_CLIENT,
        "client_hctx": "8495d448f3742c5d59d695638b8a35486512633e47db3becf997e74c0ee5bfad",
    },
]

EXPORTER_VECTORS = load_vectors("exporter.json") or []
if isinstance(EXPORTER_VECTORS, dict):
    # The shared file wraps its list in {"description", "vectors"}.
    EXPORTER_VECTORS = EXPORTER_VECTORS.get("vectors", [EXPORTER_VECTORS])


@pytest.mark.parametrize("vec", INLINE_EXPORTER_VECTORS + EXPORTER_VECTORS,
                         ids=lambda v: v.get("name", "exporter.json"))
def test_exporter_vectors(vec):
    ems = bytes.fromhex(vec["exporter_master_secret"])
    ctx = bytes.fromhex(vec["context"])
    h = vec.get("hash", "sha256")
    assert tls_exporter(ems, vec["label"], ctx, vec.get("length", 32), h).hex() == vec["hctx"]
    if "client_hctx" in vec:
        assert tls_exporter(ems, vec["client_label"], ctx, 32, h).hex() == vec["client_hctx"]


def test_hkdf_expand_label_rfc8448():
    # RFC 8448 section 3: Derive-Secret(early_secret, "derived", "") for the
    # zero PSK, the same HKDF-Expand-Label with Hash("") context that
    # tls_exporter applies to the exporter_master_secret.
    early = bytes.fromhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    derived = hkdf_expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    assert derived.hex() == "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"


def test_exporter_context_and_label_separate_outputs():
    ems = bytes(32)
    a = tls_exporter(ems, rc.EXPORTER_LABEL_SERVER, bytes(32))
    b = tls_exporter(ems, rc.EXPORTER_LABEL_SERVER, bytes([1]) + bytes(31))
    c = tls_exporter(ems, rc.EXPORTER_LABEL_CLIENT, bytes(32))
    assert len({a, b, c}) == 3 and len(a) == rc.HCTX_LEN


# ---------------------------------------------------------------------------
#  Messages
# ---------------------------------------------------------------------------

def _response(**over) -> dict:
    base = {"v": 2, "mode": "deterministic", "tee": "tdx", "quote": b64u(tdx_quote_with(bytes(64))),
            "gpu_evidence": None, "quote_time": "2026-09-04T11:50Z", "client_evidence": "none",
            "client_context": None}
    base.update(over)
    return base


# Inline message vectors: (name, mode requested, status, body, expected error
# substring or None). messages.json, when present, is checked with the same
# shape: {"name", "mode", "status", "body" (object or string), "error"}.
INLINE_MESSAGE_VECTORS = [
    ("deterministic-ok", "deterministic", 200, _response(), None),
    ("challenge-ok", "challenge", 200, _response(mode="challenge"), None),
    ("gpu-ok", "deterministic", 200, _response(tee="tdx-gpu", gpu_evidence=b64u(b"PGAE\x01 gpu")), None),
    ("sgx-ok", "deterministic", 200, _response(tee="sgx", quote=b64u(sgx_quote_with(bytes(64)))), None),
    ("client-evidence-required", "deterministic", 200,
     _response(client_evidence="required", client_context=b64u(bytes(32))), None),
    ("padded-base64-ok", "deterministic", 200, _response(quote=b64u(tdx_quote_with(bytes(64))) + "=="), None),
    ("wrong-version", "deterministic", 200, _response(v=1), "version 1"),
    ("missing-version", "deterministic", 200, {k: v for k, v in _response().items() if k != "v"}, "version"),
    ("wrong-mode-echo", "deterministic", 200, _response(mode="challenge"), "mode 'challenge', requested"),
    ("wrong-mode-echo-2", "challenge", 200, _response(mode="deterministic"), "requested 'challenge'"),
    ("unknown-tee", "deterministic", 200, _response(tee="sev-snp-gpu"), "unknown tee"),
    ("quote-not-base64url", "deterministic", 200, _response(quote="not base64!"), "quote is not base64url"),
    ("quote-empty", "deterministic", 200, _response(quote=""), "quote is not base64url"),
    ("gpu-not-base64url", "deterministic", 200, _response(gpu_evidence="%%"), "gpu_evidence is not base64url"),
    ("quote-time-missing", "deterministic", 200, {k: v for k, v in _response().items() if k != "quote_time"},
     "quote_time missing"),
    ("quote-time-seconds", "deterministic", 200, _response(quote_time="2026-09-04T11:50:00Z"), "quote_time"),
    ("quote-time-stale", "deterministic", 200, _response(quote_time="2026-09-02T11:50Z"), "older than 24 hours"),
    ("quote-time-future", "deterministic", 200, _response(quote_time="2026-09-04T12:30Z"), "in the future"),
    ("client-context-short", "deterministic", 200,
     _response(client_evidence="required", client_context=b64u(bytes(31))), "client_context is not a 32-byte"),
    ("client-context-missing", "deterministic", 200,
     _response(client_evidence="required"), "without a client_context"),
    ("client-evidence-unknown", "deterministic", 200, _response(client_evidence="maybe"), "unknown client_evidence"),
    ("error-field", "deterministic", 200, {"v": 2, "error": "quote provider unavailable"}, "quote provider unavailable"),
    ("http-404", "deterministic", 404, "not found", "no RA-TLS v2 evidence endpoint"),
    ("http-503", "deterministic", 503, {"v": 2, "error": "quote provider unavailable"}, "attest failed (503)"),
    ("not-json", "deterministic", 200, "<html>", "attest response"),
    ("not-object", "deterministic", 200, [1, 2], "attest response"),
]


def _file_message_vectors():
    out = []
    for v in load_vectors("messages.json") or []:
        if "body" in v and "mode" in v:
            out.append((v.get("name", "messages.json"), v["mode"], v.get("status", 200), v["body"], v.get("error")))
    return out


@pytest.mark.parametrize("name,mode,status,body,error", INLINE_MESSAGE_VECTORS + _file_message_vectors(),
                         ids=lambda x: x if isinstance(x, str) and not x.startswith("<") else None)
def test_parse_attest_response(name, mode, status, body, error):
    raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    if error is None:
        ev = parse_attest_response(raw, AttestationMode(mode), status, now=NOW)
        assert ev.mode is AttestationMode(mode)
        assert ev.quote and ev.quote_time_raw == body["quote_time"]
        assert ev.quote_time == check_quote_time(body["quote_time"], NOW)
        if body.get("gpu_evidence"):
            assert ev.gpu_evidence == rc._b64_decode(body["gpu_evidence"])
        else:
            assert ev.gpu_evidence is None
        assert ev.client_evidence_required == (body.get("client_evidence") == "required")
    else:
        with pytest.raises(ValueError) as exc:
            parse_attest_response(raw, AttestationMode(mode), status, now=NOW)
        assert error in str(exc.value), str(exc.value)


def test_build_attest_request():
    leaf = rc.leaf_id(VECTOR_SPKI)
    assert leaf == b64u(hashlib.sha256(VECTOR_SPKI).digest()) and "=" not in leaf
    det = json.loads(build_attest_request(AttestationMode.DETERMINISTIC, VECTOR_SPKI))
    assert det == {"v": 2, "mode": "deterministic", "leaf": leaf}
    ctx = bytes([0xC0]) * 32
    ch = json.loads(build_attest_request(AttestationMode.CHALLENGE, VECTOR_SPKI, ctx))
    assert ch == {"v": 2, "mode": "challenge", "leaf": leaf, "context": b64u(ctx)}
    assert rc._b64_decode(ch["context"]) == ctx
    with pytest.raises(ValueError):
        build_attest_request(AttestationMode.CHALLENGE, VECTOR_SPKI, ctx[:31])
    with pytest.raises(ValueError):
        build_attest_request(AttestationMode.CHALLENGE, VECTOR_SPKI)
    with pytest.raises(ValueError):
        build_attest_request(AttestationMode.NONE, VECTOR_SPKI)


# ---------------------------------------------------------------------------
#  Raw framing
# ---------------------------------------------------------------------------

def test_raw_frames_round_trip():
    frame = encode_frame(b'{"v":2}')
    assert frame == struct.pack(">I", 7) + b'{"v":2}'
    buf = io.BytesIO(frame + encode_frame(b"second"))
    assert read_frame(buf.read) == b'{"v":2}'
    assert read_frame(buf.read) == b"second"
    with pytest.raises(ValueError):
        encode_frame(bytes(rc.MAX_FRAME + 1))
    with pytest.raises(ValueError):
        read_frame(io.BytesIO(struct.pack(">I", rc.MAX_FRAME + 1) + b"x").read)
    with pytest.raises(ConnectionError):
        read_frame(io.BytesIO(struct.pack(">I", 10) + b"short").read)
    # A byte-at-a-time reader still assembles the frame.
    src = io.BytesIO(frame)
    assert read_frame(lambda n: src.read(1)) == b'{"v":2}'


# ---------------------------------------------------------------------------
#  Certificate inspection and verification
# ---------------------------------------------------------------------------

def test_inspect_marks_v1_leaf():
    for oid in (OID_TDX_QUOTE, OID_SGX_QUOTE):
        der = make_cert([der_ext(oid, b"\x04\x00 evidence", critical=True)])
        info = inspect_der_certificate(der)
        assert info.v1_leaf and info.quote is not None and info.quote.oid == oid
        assert info.quote.critical
        with pytest.raises(ValueError, match="v1 RA-TLS certificate"):
            verify_certificate_extensions(der, VerificationPolicy(tee=TeeType.TDX))
        with pytest.raises(ValueError, match="v1 RA-TLS certificate"):
            verify_evidence(der, Evidence(mode=AttestationMode.DETERMINISTIC), VerificationPolicy(tee=TeeType.TDX))


def test_inspect_v2_leaf():
    der = make_cert([
        der_ext("2.5.29.19", b"\x30\x00"),                              # basicConstraints, not Privasys
        der_ext(OID_WORKLOAD_APP_ID, APP_ID),
        der_ext(OID_IMAGE_PROFILE, b"production"),
        der_ext(OID_WORKLOAD_MODEL_DIGEST, bytes(32)),                 # app-defined 5.4.* sub-arc
    ])
    info = inspect_der_certificate(der)
    assert not info.v1_leaf and info.quote is None
    assert info.attestation is AttestationMode.NONE
    assert info.spki_der == VECTOR_SPKI and len(info.spki_der) == 91
    assert info.pubkey_sha256 == "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
    assert info.subject == "CN=enclave" and info.issuer == "CN=Privasys Intermediate CA"
    assert info.serial == 42 and info.sig_algo == "ecdsa-with-SHA256"
    assert info.not_before == datetime(2026, 9, 4, 10, 15, tzinfo=timezone.utc)
    assert info.not_after == datetime(2026, 9, 5, 10, 15, tzinfo=timezone.utc)
    assert [e.oid for e in info.custom_oids] == [OID_WORKLOAD_APP_ID, OID_IMAGE_PROFILE, OID_WORKLOAD_MODEL_DIGEST]
    assert info.custom_oids[0].value == APP_ID and info.custom_oids[0].label == "Workload App ID"
    assert info.custom_oids[2].label == "Model Digest"
    assert len(info.extensions) == 4
    assert rc.app_id_from_cert(info) == APP_ID.hex()


def test_verify_certificate_extensions_policy():
    prod = make_cert([der_ext(OID_IMAGE_PROFILE, b"production"), der_ext(OID_WORKLOAD_APP_ID, APP_ID)])
    dev = make_cert([der_ext(OID_IMAGE_PROFILE, b"dev")])
    verify_certificate_extensions(prod, VerificationPolicy(tee=TeeType.TDX))
    verify_certificate_extensions(prod, VerificationPolicy(
        tee=TeeType.TDX, expected_oids=[ExpectedOid(OID_WORKLOAD_APP_ID, APP_ID)]))
    with pytest.raises(ValueError, match="not found in certificate"):
        verify_certificate_extensions(prod, VerificationPolicy(
            tee=TeeType.TDX, expected_oids=[ExpectedOid(OID_WORKLOAD_CODE_HASH, bytes(32))]))
    with pytest.raises(ValueError, match="Workload App ID .* mismatch"):
        verify_certificate_extensions(prod, VerificationPolicy(
            tee=TeeType.TDX, expected_oids=[ExpectedOid(OID_WORKLOAD_APP_ID, bytes(16))]))
    with pytest.raises(ValueError, match="'dev' image"):
        verify_certificate_extensions(dev, VerificationPolicy(tee=TeeType.TDX))
    verify_certificate_extensions(dev, VerificationPolicy(tee=TeeType.TDX, allow_debug_images=True))


def _deterministic_evidence(spki: bytes, tee: str = "tdx", gpu: bytes | None = None,
                            quote_time: str = QUOTE_TIME) -> Evidence:
    ev = Evidence(mode=AttestationMode.DETERMINISTIC, tee=tee, quote_time_raw=quote_time, gpu_evidence=gpu)
    rd = expected_report_data(spki, ev)
    ev.quote = sgx_quote_with(rd) if tee == "sgx" else tdx_quote_with(rd)
    return ev


def test_verify_evidence_predicts_report_data():
    der = make_cert([der_ext(OID_IMAGE_PROFILE, b"production"), der_ext(OID_WORKLOAD_APP_ID, APP_ID)])
    ctx, hctx = bytes([7]) * 32, bytes([9]) * 32
    ev = Evidence(mode=AttestationMode.CHALLENGE, tee="tdx", context=ctx, hctx=hctx, quote_time_raw=QUOTE_TIME)
    ev.quote = tdx_quote_with(expected_report_data(VECTOR_SPKI, ev))
    policy = VerificationPolicy(tee=TeeType.TDX, mr_td=MRTD, expected_oids=[ExpectedOid(OID_WORKLOAD_APP_ID, APP_ID)])

    info = verify_evidence(der, ev, policy)
    assert info.attestation is AttestationMode.CHALLENGE and info.evidence is ev
    assert info.quote is not None and info.quote.oid == OID_TDX_QUOTE and info.quote.version == 4
    assert info.quote.report_data == quote_report_data("tdx", ev.quote)

    # Evidence minted for another connection (other exporter value) fails.
    other = Evidence(**{**ev.__dict__, "hctx": bytes([10]) * 32})
    with pytest.raises(ValueError, match="report_data mismatch"):
        verify_evidence(der, other, policy)
    # Wrong family against the policy, no evidence, unknown family.
    with pytest.raises(ValueError, match="expected sgx evidence, got tdx"):
        verify_evidence(der, ev, VerificationPolicy(tee=TeeType.SGX))
    with pytest.raises(ValueError, match="no attestation evidence"):
        verify_evidence(der, None, policy)
    with pytest.raises(ValueError, match="unknown evidence family"):
        verify_evidence(der, Evidence(**{**ev.__dict__, "tee": "tpm"}), policy)
    with pytest.raises(ValueError, match="not a primary evidence family"):
        verify_evidence(der, ev, VerificationPolicy(tee=TeeType.NVIDIA_GPU))
    # tdx-gpu needs gpu_evidence; a GPU fold changes report_data.
    with pytest.raises(ValueError, match="without gpu_evidence"):
        verify_evidence(der, Evidence(**{**ev.__dict__, "tee": "tdx-gpu"}), policy)
    with pytest.raises(ValueError, match="report_data mismatch"):
        verify_evidence(der, Evidence(**{**ev.__dict__, "tee": "tdx-gpu", "gpu_evidence": b"gpu"}), policy)
    gpu_ev = Evidence(**{**ev.__dict__, "tee": "tdx-gpu", "gpu_evidence": b"gpu"})
    gpu_ev.quote = tdx_quote_with(expected_report_data(VECTOR_SPKI, gpu_ev))
    assert verify_evidence(der, gpu_ev, policy).gpu_evidence == b"gpu"
    # Measurement registers and mock quotes.
    with pytest.raises(ValueError, match="MRTD mismatch"):
        verify_evidence(der, ev, VerificationPolicy(tee=TeeType.TDX, mr_td=bytes(48)))
    with pytest.raises(ValueError, match="RTMR1 mismatch"):
        verify_evidence(der, ev, VerificationPolicy(tee=TeeType.TDX, rtmr1=bytes([1]) * 48))
    with pytest.raises(ValueError, match="MOCK quote"):
        verify_evidence(der, Evidence(**{**ev.__dict__, "quote": b"MOCK_QUOTE:" + bytes(64)}), policy)
    with pytest.raises(ValueError, match="too small"):
        verify_evidence(der, Evidence(**{**ev.__dict__, "quote": ev.quote[:600]}), policy)


def test_verify_evidence_deterministic_and_extensions():
    prod = make_cert([der_ext(OID_IMAGE_PROFILE, b"production")])
    dev = make_cert([der_ext(OID_IMAGE_PROFILE, b"dev")])
    ev = _deterministic_evidence(VECTOR_SPKI)
    info = verify_evidence(prod, ev, VerificationPolicy(tee=TeeType.TDX))
    assert info.attestation is AttestationMode.DETERMINISTIC
    # A different quote_time is a different report_data.
    stale = Evidence(**{**ev.__dict__, "quote_time_raw": "2026-09-04T10:16Z"})
    with pytest.raises(ValueError, match="report_data mismatch"):
        verify_evidence(prod, stale, VerificationPolicy(tee=TeeType.TDX))
    # Certificate extension policy still applies after the evidence checks.
    with pytest.raises(ValueError, match="'dev' image"):
        verify_evidence(dev, ev, VerificationPolicy(tee=TeeType.TDX))
    verify_evidence(dev, ev, VerificationPolicy(tee=TeeType.TDX, allow_debug_images=True))
    # SGX, both blob formats.
    sgx = _deterministic_evidence(VECTOR_SPKI, tee="sgx")
    verify_evidence(prod, sgx, VerificationPolicy(tee=TeeType.SGX, mr_enclave=bytes(32), mr_signer=bytes(32)))
    with pytest.raises(ValueError, match="MRENCLAVE mismatch"):
        verify_evidence(prod, sgx, VerificationPolicy(tee=TeeType.SGX, mr_enclave=bytes([1]) * 32))


# ---------------------------------------------------------------------------
#  Dependency set (OID 7.1)
# ---------------------------------------------------------------------------

def _dep_set() -> DependencySet:
    tdx = DepMeasurement(tdx=DepTdxMeasurement(MRTD.hex().upper(), bytes(48).hex(), bytes(48).hex()))
    return DependencySet(entries=[
        DependencyEntry(app_id=APP_ID.hex(), measurements=[DepMeasurement(sgx="ab" * 32), tdx],
                        required_oids=[ExpectedOid(OID_WORKLOAD_APP_ID, APP_ID)], folded_identity="AB" * 32),
        DependencyEntry(app_id="00" * 16, measurements=[DepMeasurement(sgx="cd" * 32)]),
    ])


def test_dependency_set_encoding_is_canonical():
    s = _dep_set()
    enc = encode_dependency_set(s)
    reordered = DependencySet(entries=list(reversed(s.entries)))
    reordered.entries[1].measurements.reverse()
    assert encode_dependency_set(reordered) == enc
    dec = decode_dependency_set(enc)
    assert [e.app_id for e in dec.entries] == ["00" * 16, APP_ID.hex()]
    assert dec.entries[1].measurements[0].canonical() == "sgx:" + "ab" * 32
    assert dec.entries[1].measurements[1].canonical() == "tdx:" + MRTD.hex() + ":" + bytes(48).hex() * 1 + ":" + bytes(48).hex()
    assert dec.entries[1].folded_identity == "ab" * 32
    assert encode_dependency_set(dec) == enc
    with pytest.raises(ValueError, match="trailing"):
        decode_dependency_set(enc + b"\x00")
    with pytest.raises(ValueError, match="truncated"):
        decode_dependency_set(enc[:-1])
    # The set travels in OID 7.1 of the dependent's own leaf.
    leaf = inspect_der_certificate(make_cert([der_ext(rc.OID_ATTESTED_DEPENDENCY_SET, enc)]))
    assert encode_dependency_set(rc.dependency_set_from_cert(leaf)) == enc
    assert rc.dependency_set_from_cert(inspect_der_certificate(make_cert([]))) is None
    # A change anywhere in the subtree changes the fold.
    a = fold_identity_hex(["sgx:" + "ee" * 32], [], s)
    s.entries[1].folded_identity = "ff" * 32
    assert fold_identity_hex(["sgx:" + "ee" * 32], [], s) != a and len(a) == 64


def test_verify_peer_is_dependency():
    der = make_cert([der_ext(OID_WORKLOAD_APP_ID, APP_ID), der_ext(OID_IMAGE_PROFILE, b"production")])
    peer = verify_evidence(der, _deterministic_evidence(VECTOR_SPKI), VerificationPolicy(tee=TeeType.TDX))
    verify_peer_is_dependency(peer, TeeType.TDX, _dep_set())
    with pytest.raises(ValueError, match="not a declared dependency"):
        verify_peer_is_dependency(peer, TeeType.TDX, DependencySet())
    wrong = _dep_set()
    wrong.entries[0].measurements = [DepMeasurement(tdx=DepTdxMeasurement(bytes(48).hex(), bytes(48).hex(), bytes(48).hex()))]
    with pytest.raises(ValueError, match="matches no pinned measurement"):
        verify_peer_is_dependency(peer, TeeType.TDX, wrong)
    unverified = inspect_der_certificate(der)
    with pytest.raises(ValueError, match="carries no quote"):
        verify_peer_is_dependency(unverified, TeeType.TDX, _dep_set())
    no_app = verify_evidence(make_cert([]), _deterministic_evidence(VECTOR_SPKI), VerificationPolicy(tee=TeeType.TDX))
    with pytest.raises(ValueError, match="carries no app-id"):
        verify_peer_is_dependency(no_app, TeeType.TDX, _dep_set())


# ---------------------------------------------------------------------------
#  Client: modes and the CPython exporter limitation
# ---------------------------------------------------------------------------

def test_default_mode_follows_the_transport():
    assert not hasattr(ssl.SSLSocket, "export_keying_material"), \
        "CPython grew a TLS exporter: the standard library transport can do challenge mode now"
    client = RaTlsClient("127.0.0.1", 1)
    if rc.HAVE_PYOPENSSL:
        assert client.backend is TlsBackend.PYOPENSSL and client.attestation is AttestationMode.CHALLENGE
    else:
        assert client.backend is TlsBackend.STDLIB and client.attestation is AttestationMode.DETERMINISTIC
    assert client.attestation_tag == "none"           # nothing served yet
    assert client.tls_backend is None
    # The standard library transport: deterministic by default, no challenge mode.
    stdlib = RaTlsClient("127.0.0.1", 1, tls_backend=TlsBackend.STDLIB)
    assert stdlib.backend is TlsBackend.STDLIB and stdlib.attestation is AttestationMode.DETERMINISTIC
    with pytest.raises(NotImplementedError, match="pyOpenSSL"):
        RaTlsClient("127.0.0.1", 1, attestation=AttestationMode.CHALLENGE, tls_backend=TlsBackend.STDLIB)
    # Mode none never needs the exporter: always the standard library.
    assert RaTlsClient("127.0.0.1", 1, attestation=AttestationMode.NONE).backend is TlsBackend.STDLIB
    if rc.HAVE_PYOPENSSL:
        with pytest.raises(ValueError, match="attested modes only"):
            RaTlsClient("127.0.0.1", 1, attestation=AttestationMode.NONE, tls_backend=TlsBackend.PYOPENSSL)
        assert RaTlsClient("127.0.0.1", 1, attestation=AttestationMode.DETERMINISTIC).backend is TlsBackend.PYOPENSSL
    else:
        with pytest.raises(ImportError, match="pip install pyopenssl"):
            RaTlsClient("127.0.0.1", 1, tls_backend=TlsBackend.PYOPENSSL)
        with pytest.raises(NotImplementedError, match="pyOpenSSL"):
            RaTlsClient("127.0.0.1", 1, attestation=AttestationMode.CHALLENGE)
    with pytest.raises(ValueError, match="32 bytes"):
        RaTlsClient("127.0.0.1", 1, context=bytes(16))
    with pytest.raises(ValueError, match="unknown tls backend"):
        RaTlsClient("127.0.0.1", 1, tls_backend="pyopenssl")  # type: ignore[arg-type]
    assert rc.ATTESTATION_HEADER == "X-Privasys-Attestation"


def test_present_message_and_ack():
    cc = bytes([7]) * 32
    ce = rc.ClientEvidence(tee="tdx", quote=b"q" * 700, quote_time=QUOTE_TIME)
    msg = json.loads(rc.build_present(cc, ce))
    assert msg == {"v": 2, "mode": "present", "context": b64u(cc), "tee": "tdx", "quote": b64u(b"q" * 700),
                   "gpu_evidence": None, "quote_time": QUOTE_TIME}
    ce.gpu_evidence = b"gpu"
    assert json.loads(rc.build_present(cc, ce))["gpu_evidence"] == b64u(b"gpu")
    with pytest.raises(ValueError, match="32 bytes"):
        rc.build_present(cc[:31], ce)
    rc.check_present_ack(b'{"v":2}')
    for bad in (b'{"v":2,"error":"nope"}', b'{"v":1}', b"garbage"):
        with pytest.raises(ValueError, match="client evidence rejected"):
            rc.check_present_ack(bad)


def test_embedded_anchors_load():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=rc.PRIVASYS_TRUST_ANCHORS_PEM)
    subjects = {tuple(x[0] for x in c["subject"]) for c in ctx.get_ca_certs()}
    names = {dict(s).get("commonName") for s in subjects}
    assert names == {"Privasys Intermediate CA", "Privasys Ltd Intermediate CA (DEV)"}


# ---------------------------------------------------------------------------
#  Loopback exchange against a fake v2 server (needs cryptography for the PKI)
# ---------------------------------------------------------------------------

class _PyOpenSslServerConn:
    """socket-like view of a server-side pyOpenSSL connection, plus the
    exporter and the client's SPKI for the mutual leg."""

    def __init__(self, conn):
        self.c = conn

    def recv(self, n):
        from OpenSSL import SSL
        try:
            return self.c.recv(n)
        except (SSL.ZeroReturnError, SSL.SysCallError):
            return b""

    def sendall(self, data):
        self.c.sendall(data)

    def export(self, label: str, context: bytes) -> bytes:
        return self.c.export_keying_material(label.encode(), 32, context)

    def peer_spki(self):
        from OpenSSL import crypto
        cert = self.c.get_peer_certificate()
        return rc.spki_der_of(crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)) if cert else None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self.c.shutdown()
        except Exception:
            pass
        self.c.close()


class FakeServer:
    """A TLS 1.3 server answering the attest exchange like a runtime would:
    quotes with the predicted report_data (deterministic, and challenge when
    it runs on pyOpenSSL, where it also verifies the mutual leg),
    per-connection tag, HTTP or raw binding. Behaviour knobs for negative
    tests. Runs on pyOpenSSL when importable, like the client under test."""

    def __init__(self, chain_pem: bytes, key_pem: bytes, leaf_spki: bytes, tmp_path: Path,
                 backend: TlsBackend | None = None):
        self.leaf_spki = leaf_spki
        self.backend = backend or (TlsBackend.PYOPENSSL if rc.HAVE_PYOPENSSL else TlsBackend.STDLIB)
        self.bad_report_data = False
        self.framing = Framing.HTTP
        self.require_client_evidence = False
        self.attest_calls = 0
        self.presented: bool | None = None     # the verdict of the last present message
        self.client_spki: bytes | None = None  # SPKI of the last presented client certificate
        chain, key = tmp_path / "chain.pem", tmp_path / "key.pem"
        chain.write_bytes(chain_pem)
        key.write_bytes(key_pem)
        if self.backend is TlsBackend.STDLIB:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ctx.load_cert_chain(str(chain), str(key))
        else:
            from OpenSSL import SSL
            self.ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
            self.ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
            self.ctx.use_certificate_chain_file(str(chain))
            self.ctx.use_privatekey_file(str(key))
            self.ctx.set_alpn_select_callback(lambda _c, protos: b"http/1.1" if b"http/1.1" in protos else protos[0])
            # Ask for a client certificate and accept any: the present message is what is verified.
            self.ctx.set_verify(SSL.VERIFY_PEER, lambda *_a: True)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _accept(self, conn):
        if self.backend is TlsBackend.STDLIB:
            return self.ctx.wrap_socket(conn, server_side=True)
        from OpenSSL import SSL
        c = SSL.Connection(self.ctx, conn)
        c.set_accept_state()
        c.do_handshake()
        return _PyOpenSslServerConn(c)

    def _handle(self, conn):
        try:
            tls = self._accept(conn)
        except Exception:
            conn.close()
            return
        tag = "none"
        client_context = None
        try:
            with tls:
                if self.framing is Framing.RAW:
                    req = json.loads(read_frame(tls.recv))
                    resp, client_context = self._attest(req, tls)
                    tls.sendall(encode_frame(json.dumps(resp).encode()))
                    if client_context is not None:
                        present = json.loads(read_frame(tls.recv))
                        ok = self._verify_present(present, tls, client_context)
                        tls.sendall(encode_frame(b'{"v":2}' if ok else b'{"v":2,"error":"client evidence rejected"}'))
                    return
                while True:
                    head, body = self._read_http(tls)
                    if head is None:
                        return
                    method, path = head.split(" ")[:2]
                    if method == "POST" and path == rc.ATTEST_PATH:
                        req = json.loads(body)
                        if req.get("mode") == "present":
                            if client_context is not None and self._verify_present(req, tls, client_context):
                                tls.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                            else:
                                self._reply(tls, 403, b'{"v":2,"error":"client evidence rejected"}')
                            continue
                        resp, client_context = self._attest(req, tls)
                        status = 400 if "error" in resp else 200
                        if "error" not in resp:
                            tag = resp["mode"]
                        self._reply(tls, status, json.dumps(resp).encode())
                    elif path == "/healthz":
                        self._reply(tls, 200, json.dumps({"status": "ok", "attestation": tag}).encode())
                    elif path == "/chunked":
                        payload = b'{"big":"' + b"x" * 5000 + b'"}'
                        tls.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                    + b"%x\r\n" % 3000 + payload[:3000] + b"\r\n"
                                    + b"%x\r\n" % (len(payload) - 3000) + payload[3000:] + b"\r\n0\r\n\r\n")
                    else:
                        self._reply(tls, 404, b"not found")
        except (OSError, ValueError, ConnectionError):
            pass

    def _attest(self, req: dict, tls) -> tuple[dict, bytes | None]:
        """The attest response and, when client evidence is required, the client_context."""
        self.attest_calls += 1
        if req.get("v") != 2 or req.get("leaf") != rc.leaf_id(self.leaf_spki):
            return {"v": 2, "error": "unknown leaf"}, None
        mode = req.get("mode")
        quote_time = datetime.now(timezone.utc).strftime(rc.QUOTE_TIME_LAYOUT)
        if mode == "deterministic":
            ev = Evidence(mode=AttestationMode.DETERMINISTIC, quote_time_raw=quote_time)
        elif mode == "challenge" and self.backend is TlsBackend.PYOPENSSL:
            ctx = rc._b64_decode(req["context"])
            if len(ctx) != 32:
                return {"v": 2, "error": "context length"}, None
            ev = Evidence(mode=AttestationMode.CHALLENGE, context=ctx,
                          hctx=tls.export(rc.EXPORTER_LABEL_SERVER, ctx))
        else:
            return {"v": 2, "error": "mode not served by this fake"}, None
        rd = expected_report_data(self.leaf_spki, ev)
        if self.bad_report_data:
            rd = bytes(64)
        resp = {"v": 2, "mode": mode, "tee": "tdx", "quote": b64u(tdx_quote_with(rd)),
                "gpu_evidence": None, "quote_time": quote_time, "client_evidence": "none",
                "client_context": None}
        client_context = None
        if self.require_client_evidence:
            client_context = os.urandom(32)
            resp["client_evidence"], resp["client_context"] = "required", b64u(client_context)
        return resp, client_context

    def _verify_present(self, req: dict, tls, client_context: bytes) -> bool:
        """Verifies a present message as a runtime would (section 5): the
        echoed context, and report_data predicted from the presented client
        certificate and this connection's exporter under the client label."""
        self.presented = False
        self.client_spki = tls.peer_spki() if hasattr(tls, "peer_spki") else None
        if req.get("v") != 2 or req.get("context") != b64u(client_context) or self.client_spki is None:
            return False
        try:
            quote, tee = rc._b64_decode(req["quote"]), req["tee"]
            gpu = rc._b64_decode(req["gpu_evidence"]) if req.get("gpu_evidence") else None
            hctx_c = tls.export(rc.EXPORTER_LABEL_CLIENT, client_context)
            want = rc.client_report_data(self.client_spki, client_context, hctx_c, gpu)
            self.presented = quote_report_data(tee, quote) == want
        except (KeyError, ValueError):
            return False
        return self.presented

    @staticmethod
    def _read_http(tls):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = tls.recv(4096)
            if not chunk:
                return None, b""
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        length = 0
        for line in lines[1:]:
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1])
        while len(rest) < length:
            rest += tls.recv(4096)
        return lines[0], rest[:length]

    @staticmethod
    def _reply(tls, status: int, body: bytes):
        reason = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found"}[status]
        tls.sendall(f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n".encode() + body)

    def close(self):
        self.sock.close()


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Root -> intermediate -> v2 leaf, built with cryptography."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import timedelta

    now = datetime.now(timezone.utc)

    def make(cn, issuer_name, issuer_key, ca, exts=()):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        for oid, value in exts:
            b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False)
        return key, b.sign(issuer_key or key, hashes.SHA256())

    root_key, root = make("Test Root CA", None, None, True)
    int_key, inter = make("Test Intermediate CA", root.subject, root_key, True)
    leaf_key, leaf = make("enclave", inter.subject, int_key, False, [
        (OID_IMAGE_PROFILE, b"production"), (OID_WORKLOAD_APP_ID, APP_ID)])
    # A caller enclave's identity for the mutual leg: same intermediate, its own app id.
    caller_key, caller = make("caller", inter.subject, int_key, False, [
        (OID_IMAGE_PROFILE, b"production"), (OID_WORKLOAD_APP_ID, CALLER_APP_ID)])
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)  # noqa: E731
    pkcs8 = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,  # noqa: E731
                                      serialization.NoEncryption())
    spki = lambda c: c.public_key().public_bytes(serialization.Encoding.DER,  # noqa: E731
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    d = tmp_path_factory.mktemp("pki")
    (d / "intermediate.pem").write_bytes(pem(inter))
    (d / "root.pem").write_bytes(pem(root))
    (d / "other.pem").write_bytes(pem(make("Other CA", None, None, True)[1]))
    (d / "caller.pem").write_bytes(pem(caller) + pem(inter))
    (d / "caller-key.pem").write_bytes(pkcs8(caller_key))
    return {
        "dir": d, "chain_pem": pem(leaf) + pem(inter), "key_pem": pkcs8(leaf_key),
        "leaf_spki": spki(leaf), "leaf_der": leaf.public_bytes(serialization.Encoding.DER),
        "caller_spki": spki(caller),
    }


@pytest.fixture
def server(pki, tmp_path):
    srv = FakeServer(pki["chain_pem"], pki["key_pem"], pki["leaf_spki"], tmp_path)
    yield srv
    srv.close()


POLICY = VerificationPolicy(tee=TeeType.TDX, mr_td=MRTD, expected_oids=[ExpectedOid(OID_WORKLOAD_APP_ID, APP_ID)])


def test_loopback_http_binding(pki, server):
    ca = str(pki["dir"] / "intermediate.pem")           # an intermediate as anchor: partial chain
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, server_name="enclave.test",
                     attestation=AttestationMode.DETERMINISTIC) as client:
        assert client.tls_version == "TLSv1.3"
        assert client.tls_backend is server.backend
        assert client.peer_certificate_der == pki["leaf_der"]
        assert client.attestation_tag == "deterministic"
        assert client.evidence is not None and client.evidence.tee == "tdx"
        info = client.verify_certificate(POLICY)
        assert info.attestation is AttestationMode.DETERMINISTIC
        assert info.quote is not None and info.quote.report_data == expected_report_data(pki["leaf_spki"], client.evidence)
        assert rc.app_id_from_cert(info) == APP_ID.hex()
        assert client.healthz() == {"status": "ok", "attestation": "deterministic"}
        # Re-attestation on the same connection, verified against the last policy.
        client.reattest()
        assert server.attest_calls == 2
        # Chunked bodies over the attested connection.
        status, body = client.http_do("GET", "/chunked")
        assert status == 200 and len(json.loads(body)["big"]) == 5000
        with pytest.raises(ValueError, match="expected sgx evidence"):
            client.verify_certificate(VerificationPolicy(tee=TeeType.SGX))
    with RaTlsClient("127.0.0.1", server.port, ca_cert=str(pki["dir"] / "root.pem")) as client:
        client.verify_certificate(POLICY)              # the root as anchor also chains


def test_loopback_raw_binding(pki, server):
    server.framing = Framing.RAW
    ca = str(pki["dir"] / "intermediate.pem")
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, framing=Framing.RAW,
                     attestation=AttestationMode.DETERMINISTIC) as client:
        assert client.attestation_tag == "deterministic"
        client.verify_certificate(POLICY)
        with pytest.raises(ValueError, match="raw binding"):
            client.reattest()


def test_loopback_mode_none(pki, server):
    ca = str(pki["dir"] / "intermediate.pem")
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, attestation=AttestationMode.NONE) as client:
        assert client.attestation_tag == "none" and client.evidence is None
        info = client.verify_certificate(POLICY)      # extensions only
        assert info.quote is None and info.attestation is AttestationMode.NONE
        assert client.healthz()["attestation"] == "none"
        with pytest.raises(ValueError):
            client.reattest()
        with pytest.raises(ValueError, match="no attestation evidence"):
            verify_evidence(client.peer_certificate_der, None, POLICY)
    assert server.attest_calls == 0


def test_loopback_failures(pki, server):
    ca = str(pki["dir"] / "intermediate.pem")
    # A quote whose report_data the client did not predict fails verification.
    server.bad_report_data = True
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca) as client:
        with pytest.raises(ValueError, match="report_data mismatch"):
            client.verify_certificate(POLICY)
    server.bad_report_data = False
    # The mutual leg cannot be answered on the standard library transport (no exporter).
    server.require_client_evidence = True
    with pytest.raises(NotImplementedError, match="client evidence"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=ca, tls_backend=TlsBackend.STDLIB).connect()
    server.require_client_evidence = False
    # A chain that reaches none of the anchors fails the handshake.
    with pytest.raises(ssl.SSLError):
        RaTlsClient("127.0.0.1", server.port, ca_cert=str(pki["dir"] / "other.pem")).connect()
    with pytest.raises(ssl.SSLError):
        RaTlsClient("127.0.0.1", server.port).connect()   # embedded Privasys anchors


# ---------------------------------------------------------------------------
#  pyOpenSSL transport: challenge mode, re-attestation, the mutual leg
# ---------------------------------------------------------------------------

needs_pyopenssl = pytest.mark.skipif(not rc.HAVE_PYOPENSSL, reason="pyOpenSSL not installed")


@needs_pyopenssl
def test_loopback_challenge(pki, server):
    ca = str(pki["dir"] / "intermediate.pem")
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, server_name="enclave.test") as client:
        assert client.tls_backend is TlsBackend.PYOPENSSL and client.tls_version == "TLSv1.3"
        assert client.attestation is AttestationMode.CHALLENGE and client.attestation_tag == "challenge"
        ev = client.evidence
        assert ev is not None and len(ev.context) == 32 and len(ev.hctx) == 32
        info = client.verify_certificate(POLICY)
        assert info.attestation is AttestationMode.CHALLENGE
        assert info.quote.report_data == rc.client_report_data(pki["leaf_spki"], ev.context, ev.hctx)
        assert client.healthz() == {"status": "ok", "attestation": "challenge"}
        # Re-attestation: a fresh context, verified against the last policy.
        client.reattest()
        assert client.evidence.context != ev.context and server.attest_calls == 2
        status, body = client.http_do("GET", "/chunked")
        assert status == 200 and len(json.loads(body)["big"]) == 5000
    # A relayed context is used verbatim once; re-attestation draws its own.
    relayed = bytes([0xC0]) * 32
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, context=relayed) as client:
        assert client.evidence.context == relayed
        client.reattest()
        assert client.evidence.context != relayed
    # Evidence minted for another connection fails: the fake's exporter differs per connection.
    server.bad_report_data = True
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca) as client:
        with pytest.raises(ValueError, match="report_data mismatch"):
            client.verify_certificate(POLICY)
    server.bad_report_data = False
    # Raw binding, challenge mode.
    server.framing = Framing.RAW
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, framing=Framing.RAW) as client:
        assert client.attestation_tag == "challenge"
        client.verify_certificate(POLICY)


def _caller_evidence(req):
    """A client evidence source: a fake TDX quote carrying the requested report_data."""
    assert len(req.context) == 32 and len(req.hctx) == 32
    assert req.report_data == rc.client_report_data(req.spki_der, req.context, req.hctx)
    return rc.ClientEvidence(tee="tdx", quote=tdx_quote_with(req.report_data),
                             quote_time=datetime.now(timezone.utc).strftime(rc.QUOTE_TIME_LAYOUT))


@needs_pyopenssl
def test_loopback_mutual_leg(pki, server):
    ca = str(pki["dir"] / "intermediate.pem")
    caller, caller_key = str(pki["dir"] / "caller.pem"), str(pki["dir"] / "caller-key.pem")
    server.require_client_evidence = True
    for framing in (Framing.HTTP, Framing.RAW):
        server.framing = framing
        with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, framing=framing, client_cert=caller,
                         client_key=caller_key, client_evidence=_caller_evidence) as client:
            assert client.attestation_tag == "challenge"
            assert client.evidence.client_evidence_required and len(client.evidence.client_context) == 32
            assert server.presented is True and server.client_spki == pki["caller_spki"]
            client.verify_certificate(POLICY)
            if framing is Framing.HTTP:
                assert client.healthz()["attestation"] == "challenge"
    server.framing = Framing.HTTP
    # The key file defaults to the certificate file when both live in one PEM.
    both = pki["dir"] / "caller-both.pem"
    both.write_bytes(Path(caller).read_bytes() + Path(caller_key).read_bytes())
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, client_cert=str(both),
                     client_evidence=_caller_evidence) as client:
        assert server.presented is True
    # No source, no certificate, a source without a quote, a quote for another key: all fail closed.
    with pytest.raises(ValueError, match="client_evidence is not set"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=ca, client_cert=caller, client_key=caller_key).connect()
    with pytest.raises(ValueError, match="no client certificate"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=ca, client_evidence=_caller_evidence).connect()
    with pytest.raises(ValueError, match="returned no quote"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=ca, client_cert=caller, client_key=caller_key,
                    client_evidence=lambda req: rc.ClientEvidence(tee="tdx", quote=b"")).connect()
    wrong = lambda req: rc.ClientEvidence(tee="tdx", quote=tdx_quote_with(bytes(64)), quote_time=QUOTE_TIME)  # noqa: E731
    with pytest.raises(ValueError, match="client evidence rejected \\(403\\)"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=ca, client_cert=caller, client_key=caller_key,
                    client_evidence=wrong).connect()
    assert server.presented is False
    server.framing = Framing.RAW
    with pytest.raises(ValueError, match="client evidence rejected"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=ca, framing=Framing.RAW, client_cert=caller,
                    client_key=caller_key, client_evidence=wrong).connect()
    server.framing = Framing.HTTP
    server.require_client_evidence = False
    # A missing certificate file and an empty one are refused at construction.
    with pytest.raises(OSError):
        RaTlsClient("127.0.0.1", 1, client_cert=str(pki["dir"] / "missing.pem"))
    empty = pki["dir"] / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="no certificate"):
        RaTlsClient("127.0.0.1", 1, client_cert=str(empty))


@needs_pyopenssl
def test_loopback_pyopenssl_chain_failures(pki, server):
    # A chain that reaches none of the anchors fails the handshake on the pyOpenSSL transport too.
    with pytest.raises(ssl.SSLCertVerificationError, match="fleet anchor"):
        RaTlsClient("127.0.0.1", server.port, ca_cert=str(pki["dir"] / "other.pem")).connect()
    with pytest.raises(ssl.SSLCertVerificationError):
        RaTlsClient("127.0.0.1", server.port).connect()   # embedded Privasys anchors
    assert server.attest_calls == 0
    # A server that only speaks the standard library still serves deterministic to a pyOpenSSL client.
    with RaTlsClient("127.0.0.1", server.port, ca_cert=str(pki["dir"] / "intermediate.pem"),
                     attestation=AttestationMode.DETERMINISTIC) as client:
        assert client.tls_backend is TlsBackend.PYOPENSSL and client.attestation_tag == "deterministic"
        client.verify_certificate(POLICY)


# ---------------------------------------------------------------------------
#  Trust modes: fleet, public, auto
# ---------------------------------------------------------------------------

def test_trust_option_validation():
    with pytest.raises(ValueError, match='trust "public" cannot be combined with attestation mode "(challenge|deterministic)"'):
        RaTlsClient("127.0.0.1", 1, trust=TrustMode.PUBLIC)
    with pytest.raises(ValueError, match='attestation mode "deterministic"'):
        RaTlsClient("127.0.0.1", 1, trust=TrustMode.PUBLIC, attestation=AttestationMode.DETERMINISTIC)
    with pytest.raises(ValueError, match='ca_cert .*trust "public"'):
        RaTlsClient("127.0.0.1", 1, trust=TrustMode.PUBLIC, attestation=AttestationMode.NONE, ca_cert="anchor.pem")
    with pytest.raises(ValueError, match="unknown trust mode"):
        RaTlsClient("127.0.0.1", 1, trust="public")  # type: ignore[arg-type]
    client = RaTlsClient("127.0.0.1", 1, trust=TrustMode.PUBLIC, attestation=AttestationMode.NONE)
    assert client.trust is TrustMode.PUBLIC and client.trust_resolved is None
    assert RaTlsClient("127.0.0.1", 1).trust is TrustMode.AUTO
    assert RaTlsClient("127.0.0.1", 1, trust=TrustMode.FLEET).trust is TrustMode.FLEET


@pytest.fixture
def self_signed_server(tmp_path):
    """A server whose certificate is under no anchor at all: a host that is not an enclave."""
    x509 = pytest.importorskip("cryptography.x509")
    import ipaddress
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "self-signed")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    srv = FakeServer(cert.public_bytes(serialization.Encoding.PEM), key_pem, spki, tmp_path)
    yield srv
    srv.close()


def test_loopback_auto_without_evidence_accepts_the_fleet_chain(pki, server):
    ca = str(pki["dir"] / "intermediate.pem")
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, attestation=AttestationMode.NONE) as client:
        assert client.trust is TrustMode.AUTO
        assert client.trust_resolved is TrustMode.FLEET
        assert client.healthz()["attestation"] == "none"
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca, attestation=AttestationMode.NONE,
                     trust=TrustMode.FLEET) as client:
        assert client.trust_resolved is TrustMode.FLEET
    # The attested default resolves to the fleet as before.
    with RaTlsClient("127.0.0.1", server.port, ca_cert=ca) as client:
        assert client.trust_resolved is TrustMode.FLEET
        assert client.attestation_tag == ("challenge" if rc.HAVE_PYOPENSSL else "deterministic")
    # Embedded anchors, no evidence: the test chain reaches neither the fleet nor a public root.
    with pytest.raises(ssl.SSLCertVerificationError, match="reaches neither a Privasys fleet anchor nor a public PKI root"):
        RaTlsClient("127.0.0.1", server.port, attestation=AttestationMode.NONE).connect()
    assert server.attest_calls == 1


def test_loopback_self_signed_is_refused(pki, self_signed_server):
    port = self_signed_server.port
    ca = str(pki["dir"] / "intermediate.pem")
    # Attested modes and trust fleet: the chain must reach a fleet anchor.
    for kwargs in (dict(), dict(ca_cert=ca), dict(attestation=AttestationMode.NONE, trust=TrustMode.FLEET),
                   dict(ca_cert=ca, attestation=AttestationMode.NONE, trust=TrustMode.FLEET)):
        with pytest.raises(ssl.SSLCertVerificationError):
            RaTlsClient("127.0.0.1", port, **kwargs).connect()
    # Auto without evidence: fleet fails, then the public verifier fails too.
    with pytest.raises(ssl.SSLCertVerificationError, match="reaches neither"):
        RaTlsClient("127.0.0.1", port, attestation=AttestationMode.NONE).connect()
    with pytest.raises(ssl.SSLCertVerificationError, match="reaches neither"):
        RaTlsClient("127.0.0.1", port, ca_cert=ca, attestation=AttestationMode.NONE).connect()
    # Public only: the system verifier alone.
    with pytest.raises(ssl.SSLCertVerificationError):
        RaTlsClient("127.0.0.1", port, attestation=AttestationMode.NONE, trust=TrustMode.PUBLIC).connect()
    assert self_signed_server.attest_calls == 0


# ---------------------------------------------------------------------------
#  Platform allow-list: the identity the attestation
#  server reads from the verified evidence, pinned by the relying party
# ---------------------------------------------------------------------------

PIID = "c055fc7b49bd4185dda796bf1795af32"
PPID = "414afbe506e8ac361add41f3133aab6f"


def test_platform_id_precedence_and_allow_list():
    r = rc.QuoteVerificationResult(status=rc.QuoteVerificationStatus.OK, platform_instance_id=PIID, ppid="aa", chip_id="cc")
    assert r.platform_id == PIID
    r.platform_instance_id = ""
    assert r.platform_id == "aa"
    r.ppid = ""
    assert r.platform_id == "cc"
    r = rc.QuoteVerificationResult(status=rc.QuoteVerificationStatus.OK, platform_instance_id=PIID, ppid=PPID)
    rc.platform_allowed(r, [])
    for ok in (PIID, PIID.upper(), "c055fc7b-49bd-4185-dda7-96bf1795af32"):
        rc.platform_allowed(r, ["deadbeef", ok])
    # The PPID does not stand in for a reported Platform Instance ID.
    with pytest.raises(ValueError, match="not in allowed_platform_ids"):
        rc.platform_allowed(r, [PPID])
    with pytest.raises(ValueError, match="reported no platform identity"):
        rc.platform_allowed(rc.QuoteVerificationResult(status=rc.QuoteVerificationStatus.OK), [PIID])


class FakeAttestationServer:
    """Answers like the Privasys attestation server: records the request,
    reports a platform identity (unless it plays an older server), and
    enforces the request's allow-list with PLATFORM_NOT_ALLOWED."""

    def __init__(self, reports_platform: bool = True):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        outer = self
        self.last_request: dict = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.last_request = req
                resp = {"success": True, "status": "OK", "teeType": "tdx", "tcbStatus": "UpToDate"}
                if reports_platform:
                    resp["platform"] = {"ppid": PPID, "platformInstanceId": PIID, "fmspc": "00806f050000"}
                    allowed = req.get("allowedPlatformIds") or []
                    if allowed and not any(a.lower() == PIID for a in allowed):
                        resp.update(success=False, status="PLATFORM_NOT_ALLOWED", error="platform not in the allow-list")
                if req.get("type") == "tdx-gpu":
                    resp["gpuAttestation"] = {"verified": True, "status": "OK"}
                body = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.httpd.server_port}/api/verify"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def test_verify_quote_reports_and_enforces_the_platform():
    srv = FakeAttestationServer()
    try:
        config = rc.QuoteVerificationConfig(endpoint=srv.endpoint)
        r = rc._verify_quote(b"quote", config)
        assert r.platform_id == PIID and r.ppid == PPID and r.fmspc == "00806f050000"
        assert "allowedPlatformIds" not in srv.last_request
        rc._verify_quote(b"quote", config, ["0000", PIID.upper()])
        assert srv.last_request["allowedPlatformIds"] == ["0000", PIID.upper()]
        with pytest.raises(ValueError, match="PLATFORM_NOT_ALLOWED"):
            rc._verify_quote(b"quote", config, ["0000"])
        r, gpu = rc._verify_tdx_gpu(b"quote", b"gpu", config, [PIID])
        assert r.platform_id == PIID and gpu.verified
        with pytest.raises(ValueError, match="PLATFORM_NOT_ALLOWED"):
            rc._verify_tdx_gpu(b"quote", b"gpu", config, ["0000"])
    finally:
        srv.close()
    # A list without a verifier is refused before anything is looked at.
    der = make_cert([der_ext(OID_IMAGE_PROFILE, b"production"), der_ext(OID_WORKLOAD_APP_ID, APP_ID)])
    ev = Evidence(mode=AttestationMode.DETERMINISTIC, tee="tdx", quote_time_raw=QUOTE_TIME)
    ev.quote = tdx_quote_with(expected_report_data(VECTOR_SPKI, ev))
    with pytest.raises(ValueError, match="allowed_platform_ids needs quote_verification"):
        verify_evidence(der, ev, VerificationPolicy(tee=TeeType.TDX, allowed_platform_ids=[PIID]))


def test_older_server_without_platform_identity_fails_closed_against_a_list():
    srv = FakeAttestationServer(reports_platform=False)
    try:
        config = rc.QuoteVerificationConfig(endpoint=srv.endpoint)
        assert rc._verify_quote(b"quote", config).platform_id == ""
        with pytest.raises(ValueError, match="reported no platform identity"):
            rc._verify_quote(b"quote", config, [PIID])
    finally:
        srv.close()
