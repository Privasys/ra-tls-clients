# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

"""RA-TLS v2 client for Privasys enclaves: evidence after the handshake.

Implements docs/ratls-v2.md. The server presents an ordinary X.509 leaf that
chains to the Privasys intermediate CA of its environment and carries the v2
Privasys extensions (oids_gen.py) but no attestation evidence. After the
handshake, and before any application data, the client asks for a DCAP quote
(plus GPU evidence on a GPU workload) on the same connection, either with
``POST /__privasys/attest`` (HTTP binding) or with one ``u32 big-endian length
|| JSON`` frame in each direction (raw binding). The quote's report_data must
equal a value the client predicts from the leaf SubjectPublicKeyInfo:

    deterministic: SHA-512( SHA-256(SPKI_DER) || quote_time )
    challenge:     SHA-512( SHA-256(SPKI_DER) || context || hctx )

with SHA-256(gpu_evidence) appended to the binding when GPU evidence is
present. A verifier never accepts a report_data it did not predict.

Attestation modes and the CPython limitation
--------------------------------------------
Challenge mode needs ``hctx = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2",
context, 32)`` (RFC 8446 section 7.5), keyed by the exporter_master_secret of
this very connection. CPython's ``ssl`` module (3.12, 3.13 and 3.14 checked)
exposes no ``SSL_export_keying_material`` binding on ``SSLSocket`` or
``SSLObject``, and there is no supported way to read the exporter secret from
a live connection. Without it the client cannot compute ``hctx``, so:

* ``AttestationMode.DETERMINISTIC`` is the default of this SDK (the "trust the
  TEE" tier: the leaf key was generated inside an enclave with the quoted
  measurements within the last 24 hours, no per-connection binding);
* ``AttestationMode.CHALLENGE`` raises ``NotImplementedError`` at construction;
* the mutual leg (a server answering ``client_evidence: "required"``) fails the
  connection for the same reason.

The exporter recipe itself is implemented in pure Python (``tls_exporter``,
``hkdf_expand_label``) so the step is checked against the shared vectors and
so that callers with another TLS stack can compute ``hctx`` themselves.

Chain check (``TrustMode``): an attested connection must chain to one of the
embedded Privasys intermediate CAs (production and development) or to the
certificates of a caller-supplied PEM file, without hostname verification:
peers are dialled by IP, the identity is measurement plus app id. With no
evidence requested the default trust mode AUTO also accepts the system's
public PKI roots with ordinary hostname verification, so a host that is not an
enclave (privasys.id, the identity provider) is reachable through the same
client. An attested mode is never downgraded to public PKI.

The module depends on the standard library only.

Usage::

    from ratls_client import RaTlsClient, VerificationPolicy, TeeType

    with RaTlsClient("10.0.0.7", 443, server_name="app.example") as client:
        info = client.verify_certificate(VerificationPolicy(tee=TeeType.TDX, mr_td=...))
        print(client.attestation_tag)      # "deterministic"
        body = client.send_data(b'{"command":"hello"}', auth_token="eyJ...")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import ssl
import struct
import urllib.request
from base64 import b64decode, b64encode, urlsafe_b64encode
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Optional

try:  # package layout (python/ as a package) or flat module next to oids_gen.py
    from .oids_gen import (  # type: ignore[import-not-found]
        OID_ATTESTED_DEPENDENCY_SET,
        OID_EVIDENCE_SEV_SNP_REPORT,
        OID_IMAGE_PROFILE,
        OID_PRIVASYS_ARC_PREFIX,
        OID_SGX_QUOTE,
        OID_TDX_QUOTE,
        OID_WORKLOAD_APP_ID,
        oid_label,
    )
except ImportError:
    from oids_gen import (  # type: ignore[no-redef]
        OID_ATTESTED_DEPENDENCY_SET,
        OID_EVIDENCE_SEV_SNP_REPORT,
        OID_IMAGE_PROFILE,
        OID_PRIVASYS_ARC_PREFIX,
        OID_SGX_QUOTE,
        OID_TDX_QUOTE,
        OID_WORKLOAD_APP_ID,
        oid_label,
    )

__all__ = [
    "ATTEST_PATH", "ATTESTATION_HEADER", "PROTOCOL_VERSION", "RATLS_ALPN_PROTO",
    "EXPORTER_LABEL_SERVER", "EXPORTER_LABEL_CLIENT", "CONTEXT_LEN", "HCTX_LEN", "MAX_FRAME",
    "OID_ATTESTED_DEPENDENCY_SET",
    "AttestationMode", "Framing", "TrustMode", "TeeType", "Evidence", "QuoteInfo", "OidExtension", "CertInfo",
    "ExpectedOid", "VerificationPolicy", "QuoteVerificationConfig", "QuoteVerificationResult",
    "QuoteVerificationStatus", "TCBStatus", "GPUAttestationResult",
    "DepTdxMeasurement", "DepMeasurement", "DependencyEntry", "DependencySet",
    "RaTlsClient", "PRIVASYS_TRUST_ANCHORS_PEM",
    "inspect_der_certificate", "print_cert_info", "verify_evidence", "verify_certificate_extensions",
    "expected_report_data", "client_report_data", "quote_report_data", "check_quote_time",
    "build_attest_request", "parse_attest_response", "encode_frame", "read_frame",
    "hkdf_expand_label", "tls_exporter",
    "encode_dependency_set", "decode_dependency_set", "fold_identity", "fold_identity_hex",
    "match_dependency", "verify_peer_is_dependency", "app_id_from_cert", "dependency_set_from_cert",
]


# ---------------------------------------------------------------------------
#  Protocol constants (docs/ratls-v2.md)
# ---------------------------------------------------------------------------

# Reserved path of the evidence endpoint on every RA-TLS v2 server (HTTP binding).
ATTEST_PATH = "/__privasys/attest"
# The "v" field of every attest message.
PROTOCOL_VERSION = 2
# Exporter labels: server evidence, and client evidence on the mutual leg.
EXPORTER_LABEL_SERVER = "EXPORTER-privasys-ratls-attest-v2"
EXPORTER_LABEL_CLIENT = "EXPORTER-privasys-ratls-attest-v2-client"
# quote_time is minute precision, ASCII "YYYY-MM-DDTHH:MMZ" (17 bytes).
QUOTE_TIME_LAYOUT = "%Y-%m-%dT%H:%MZ"
QUOTE_TIME_LEN = 17
CONTEXT_LEN = 32
HCTX_LEN = 32
# Largest raw-binding frame accepted, in bytes.
MAX_FRAME = 65536
# A deterministic quote is cached by the runtime for 24 hours; 5 minutes of
# skew are allowed on both sides.
QUOTE_MAX_AGE = timedelta(hours=24, minutes=5)
QUOTE_SKEW = timedelta(minutes=5)
# Request header under which the server exposes the connection tag to the
# workload: "none", "deterministic" or "challenge".
ATTESTATION_HEADER = "X-Privasys-Attestation"
# ALPN marker that routes the connection to the gateway splice path.
RATLS_ALPN_PROTO = "privasys-ratls/1"

CHALLENGE_UNSUPPORTED = (
    "AttestationMode.CHALLENGE is not available in the Python SDK: CPython's ssl "
    "module exposes no TLS exporter (RFC 8446 section 7.5), so hctx cannot be "
    "derived for this connection. Use AttestationMode.DETERMINISTIC (the default) "
    "or the Go or Rust SDK for a connection-bound attestation."
)

# ---------------------------------------------------------------------------
#  Privasys fleet trust anchors (go/ratls/anchors/*.pem)
# ---------------------------------------------------------------------------

# Every enclave enrolled on the platform serves a leaf issued by the Privasys
# Intermediate CA of its environment. Requiring the chain to reach one of these
# confines acceptance to enclaves Privasys provisioned; the evidence checks are
# layered on top of that fleet-membership check.
PRIVASYS_INTERMEDIATE_CA_PEM = """-----BEGIN CERTIFICATE-----
MIICXTCCAgSgAwIBAgIUGsQj8zdQMALqzHSJSJsxaKuTDuUwCgYIKoZIzj0EAwIw
dzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRv
bjEVMBMGA1UECgwMUHJpdmFzeXMgTHRkMRMwEQYDVQQLDApPcGVyYXRpb25zMRkw
FwYDVQQDDBBQcml2YXN5cyBSb290IENBMB4XDTI2MDMwMzA5NDcxN1oXDTMxMDMw
MjA5NDcxN1owfzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNV
BAcMBkxvbmRvbjEVMBMGA1UECgwMUHJpdmFzeXMgTHRkMRMwEQYDVQQLDApPcGVy
YXRpb25zMSEwHwYDVQQDDBhQcml2YXN5cyBJbnRlcm1lZGlhdGUgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATs+4bGevjmiUiepVQbr22WKGqR42SK8Z4qk9gs
LxiJbUhJEO0tY1UlsoSBTrsBwb1Mq+ngoeSotFyLz1RTk4Gpo2YwZDASBgNVHRMB
Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUPFvb0C4gBRiY
Cg2vQpP8MqpG9CswHwYDVR0jBBgwFoAUs86NsnKlGHspTjvFY6gglLqc/4IwCgYI
KoZIzj0EAwIDRwAwRAIgHsQ73+XHYbDrXtY/tGPfwnWxGYa7OyFvKPzM52uFGh8C
IDO6Kd6Oajs9XXnRz7OKtlCNrJ7phZNIYFN6zPOqMxgB
-----END CERTIFICATE-----
"""

PRIVASYS_INTERMEDIATE_CA_DEV_PEM = """-----BEGIN CERTIFICATE-----
MIICdTCCAhqgAwIBAgIUJ/m03RGr3dAeXDmZ1C4izRK0SGAwCgYIKoZIzj0EAwIw
gYExCzAJBgNVBAYTAlVLMRcwFQYDVQQIDA5Vbml0ZWQgS2luZ2RvbTEPMA0GA1UE
BwwGTG9uZG9uMRUwEwYDVQQKDAxQcml2YXN5cyBMdGQxDDAKBgNVBAsMA0RldjEj
MCEGA1UEAwwaUHJpdmFzeXMgTHRkIFJvb3QgQ0EgKERFVikwHhcNMjYwMjE4MTUx
NzA3WhcNMzEwMjE3MTUxNzA3WjCBiTELMAkGA1UEBhMCVUsxFzAVBgNVBAgMDlVu
aXRlZCBLaW5nZG9tMQ8wDQYDVQQHDAZMb25kb24xFTATBgNVBAoMDFByaXZhc3lz
IEx0ZDEMMAoGA1UECwwDRGV2MSswKQYDVQQDDCJQcml2YXN5cyBMdGQgSW50ZXJt
ZWRpYXRlIENBIChERVYpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzCEGY7ay
05+Ve/GUgdXgoVTl1qgaaKkuTUDQMERuyG3gbvGHiYizSQf8zJE+MI27oEjcotsG
xgx/90RgIGKwuaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFL/qhK4lcNDWws+Q9c/hpU2vMqu3MB8GA1UdIwQYMBaAFIPx
pxnvfgvw7iKj270kVlKeS2CBMAoGCCqGSM49BAMCA0kAMEYCIQDVhFpKwDBmgxrd
B2BlsOpVecxntcrFm4ltr8KQrtS5OwIhAMs7bI9w7HD2eYIaEpkxaxFyH4ENYbG4
D3EbYsQKbQUs
-----END CERTIFICATE-----
"""

PRIVASYS_TRUST_ANCHORS_PEM = PRIVASYS_INTERMEDIATE_CA_PEM + PRIVASYS_INTERMEDIATE_CA_DEV_PEM


# ---------------------------------------------------------------------------
#  Quote byte offsets
# ---------------------------------------------------------------------------

# SGX DCAP Quote v3: QuoteHeader(48) + ReportBody(384).
SGX_QUOTE_MIN_SIZE = 432
SGX_QUOTE_MRENCLAVE = slice(112, 144)
SGX_QUOTE_MRSIGNER = slice(176, 208)
SGX_QUOTE_REPORT_DATA = slice(368, 432)

# SGX raw Report (sgx_create_report): no QuoteHeader, just ReportBody(432).
SGX_REPORT_SIZE = 432
SGX_REPORT_MRENCLAVE = slice(64, 96)
SGX_REPORT_MRSIGNER = slice(128, 160)
SGX_REPORT_REPORT_DATA = slice(320, 384)

# TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584). MRTD alone (the TD
# firmware) does not identify the guest build; RTMR1 and RTMR2 carry the
# kernel, initrd and cmdline, so a full identity is MRTD + RTMR1 + RTMR2.
TDX_QUOTE_MIN_SIZE = 632
TDX_QUOTE_MRTD = slice(184, 232)
TDX_QUOTE_RTMR1 = slice(424, 472)
TDX_QUOTE_RTMR2 = slice(472, 520)
TDX_QUOTE_REPORT_DATA = slice(568, 632)

# AMD SEV-SNP attestation report (0x4A0 = 1184 bytes).
SEV_SNP_REPORT_MIN_SIZE = 0x4A0
SEV_SNP_REPORT_DATA = slice(0x050, 0x090)
SEV_SNP_MEASUREMENT = slice(0x090, 0x0C0)
SEV_SNP_HOST_DATA = slice(0x0C0, 0x0E0)


def detect_sgx_raw_report(raw: bytes) -> bool:
    """True for a raw SGX Report, False for a DCAP Quote v3 (2-byte LE version 3)."""
    return not (len(raw) >= 4 and int.from_bytes(raw[0:2], "little") == 3)


def _sgx_slices(raw: bytes) -> tuple[slice, slice, slice, int]:
    """(MRENCLAVE, MRSIGNER, report_data, minimum size) for the SGX blob format."""
    if detect_sgx_raw_report(raw):
        return SGX_REPORT_MRENCLAVE, SGX_REPORT_MRSIGNER, SGX_REPORT_REPORT_DATA, SGX_REPORT_SIZE
    return SGX_QUOTE_MRENCLAVE, SGX_QUOTE_MRSIGNER, SGX_QUOTE_REPORT_DATA, SGX_QUOTE_MIN_SIZE


# ---------------------------------------------------------------------------
#  Enumerations and records
# ---------------------------------------------------------------------------

class AttestationMode(Enum):
    """What the client asks the server for after the handshake."""
    # Quote bound to this connection through the TLS exporter (Level 3).
    # Not available in this SDK, see the module docstring.
    CHALLENGE = "challenge"
    # The runtime's cached quote, bound to the leaf key and a minute timestamp.
    DETERMINISTIC = "deterministic"
    # No request; the server tags the connection "none" and only the
    # certificate extensions are verified.
    NONE = "none"


class Framing(Enum):
    """Carrier of the attest messages."""
    HTTP = "http"   # POST /__privasys/attest as an HTTP/1.1 request
    RAW = "raw"     # one u32 big-endian length-prefixed JSON frame each way


class TrustMode(Enum):
    """Which verifier the server chain must satisfy at the handshake.

    AUTO (default): FLEET whenever evidence is requested (DETERMINISTIC or
    CHALLENGE); with ``AttestationMode.NONE`` the chain is accepted when it
    satisfies FLEET or PUBLIC. An attested mode is never downgraded to PUBLIC.

    FLEET: the Privasys fleet anchors, or the caller CA (``ca_cert``) when one
    is given, without hostname verification: peers are dialled by IP and the
    identity is the evidence plus the app identity in the certificate.

    PUBLIC: the system's public PKI roots with ordinary hostname verification,
    for a host that is not an enclave (the identity provider, for example).
    Only valid with ``AttestationMode.NONE`` and without ``ca_cert``.
    """
    AUTO = "auto"
    FLEET = "fleet"
    PUBLIC = "public"


class TeeType(Enum):
    SGX = "sgx"
    TDX = "tdx"
    SEV_SNP = "sev-snp"
    NVIDIA_GPU = "nvidia-gpu"


def tee_type_of(tee: str) -> Optional[TeeType]:
    """Map an evidence family string of the attest response to a TeeType."""
    return {"sgx": TeeType.SGX, "tdx": TeeType.TDX, "tdx-gpu": TeeType.TDX,
            "sev-snp": TeeType.SEV_SNP}.get(tee)


@dataclass
class Evidence:
    """The evidence a server returned for a connection (verified or not)."""
    mode: AttestationMode
    tee: str = ""                       # "sgx", "tdx", "tdx-gpu"
    quote: bytes = b""                  # raw DCAP quote
    gpu_evidence: Optional[bytes] = None
    quote_time: Optional[datetime] = None
    quote_time_raw: str = ""            # 17-byte ASCII, an input of report_data (deterministic)
    context: Optional[bytes] = None     # the client's 32-byte context (challenge)
    hctx: Optional[bytes] = None        # exporter output for context; never travels
    client_evidence_required: bool = False
    client_context: Optional[bytes] = None


@dataclass
class QuoteInfo:
    """The evidence body of a connection, as displayed. OID names the quote
    format (the Intel arc OIDs, as in v1 certificates); the quote never sits in
    the certificate in v2."""
    oid: str
    label: str
    raw: bytes
    critical: bool = False
    is_mock: bool = False
    version: Optional[int] = None
    report_data: Optional[bytes] = None


@dataclass
class OidExtension:
    """A Privasys-arc X.509 extension."""
    oid: str
    label: str
    value: bytes


@dataclass
class ExpectedOid:
    oid: str
    expected_value: bytes


class QuoteVerificationStatus(Enum):
    """Verdict of the attestation server."""
    OK = "OK"
    TCB_OUT_OF_DATE = "TCB_OUT_OF_DATE"
    CONFIGURATION_NEEDED = "CONFIGURATION_NEEDED"
    SW_HARDENING_NEEDED = "SW_HARDENING_NEEDED"
    CONFIGURATION_AND_SW_HARDENING_NEEDED = "CONFIGURATION_AND_SW_HARDENING_NEEDED"
    TCB_REVOKED = "TCB_REVOKED"
    TCB_EXPIRED = "TCB_EXPIRED"
    UNRECOGNIZED = "UNRECOGNIZED"

    @classmethod
    def from_str(cls, s: str) -> "QuoteVerificationStatus":
        try:
            return cls(s)
        except ValueError:
            return cls.UNRECOGNIZED


class TCBStatus(Enum):
    """Intel's platform TCB status (the server's tcbStatus field)."""
    UP_TO_DATE = "UpToDate"
    SW_HARDENING_NEEDED = "SWHardeningNeeded"
    CONFIGURATION_NEEDED = "ConfigurationNeeded"
    CONFIGURATION_AND_SW_HARDENING_NEEDED = "ConfigurationAndSWHardeningNeeded"
    OUT_OF_DATE = "OutOfDate"
    OUT_OF_DATE_CONFIGURATION_NEEDED = "OutOfDateConfigurationNeeded"
    REVOKED = "Revoked"


# Accepted without any relaxation; mirrors the attestation server's floor.
_SECURE_TCB_FLOOR = {TCBStatus.UP_TO_DATE, TCBStatus.SW_HARDENING_NEEDED}


def _tcb_status_acceptable(status: str, acceptable: list[TCBStatus]) -> None:
    """Revoked is never accepted; the floor always is; anything else only when
    listed. An empty status (server did not report one) is accepted."""
    if not status:
        return
    try:
        st = TCBStatus(status)
    except ValueError:
        raise ValueError(f"TCB status {status!r} not accepted: unknown value") from None
    if st is TCBStatus.REVOKED:
        raise ValueError("TCB status Revoked is never acceptable")
    if st in _SECURE_TCB_FLOOR or st in acceptable:
        return
    raise ValueError(f"TCB status {status!r} not accepted: not in the secure floor "
                     "and not in the configured acceptable set")


@dataclass
class QuoteVerificationConfig:
    """Remote quote verification through an attestation server (POST endpoint)."""
    endpoint: str
    token: Optional[str] = None
    accepted_statuses: list[QuoteVerificationStatus] = field(default_factory=list)
    # Opt-in client-side enforcement of the server's tcbStatus against the
    # secure floor plus acceptable_tcb_statuses. Revoked is never accepted.
    enforce_tcb_status: bool = False
    acceptable_tcb_statuses: list[TCBStatus] = field(default_factory=list)
    timeout_secs: int = 10


@dataclass
class QuoteVerificationResult:
    status: QuoteVerificationStatus
    tcb_date: Optional[str] = None
    advisory_ids: list[str] = field(default_factory=list)
    tcb_status: str = ""


@dataclass
class GPUAttestationResult:
    """The attestation server's NVIDIA GPU verdict for a tdx-gpu connection."""
    verified: bool = False
    status: str = ""
    message: str = ""
    error: str = ""
    gpu_uuid: str = ""
    driver: str = ""
    vbios: str = ""
    cc_environment: str = ""
    measurements_verified: bool = False


@dataclass
class VerificationPolicy:
    """What a connection must prove. None on a measurement means skip."""
    tee: TeeType
    mr_enclave: Optional[bytes] = None      # SGX, 32 bytes
    mr_signer: Optional[bytes] = None       # SGX, 32 bytes
    mr_td: Optional[bytes] = None           # TDX, 48 bytes
    rtmr1: Optional[bytes] = None           # TDX, 48 bytes (guest build)
    rtmr2: Optional[bytes] = None           # TDX, 48 bytes (guest build)
    measurement: Optional[bytes] = None     # SEV-SNP, 48 bytes
    host_data: Optional[bytes] = None       # SEV-SNP, 32 bytes
    expected_oids: list[ExpectedOid] = field(default_factory=list)
    quote_verification: Optional[QuoteVerificationConfig] = None
    # Accept a non-"production" Image Profile (OID 1.2), for example "dev"
    # images built with SSH and debug tooling. Fail-closed by default; a
    # certificate without the extension is accepted either way.
    allow_debug_images: bool = False


@dataclass
class CertInfo:
    """Summary of the peer's leaf certificate and of the connection's evidence."""
    subject: str = ""
    issuer: str = ""
    serial: int = 0
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    sig_algo: str = ""
    # SHA-256 of the full SPKI DER (91 bytes for P-256): the standard public
    # key fingerprint and the first input of report_data.
    pubkey_sha256: str = ""
    spki_der: bytes = b""
    extensions: list[str] = field(default_factory=list)
    # A v1 leaf carries evidence as a certificate extension; a v2 verifier
    # fails closed on it.
    v1_leaf: bool = False
    # Evidence of the attest response (never of the certificate). None until
    # evidence was attached; on a v1 leaf the unverified extension, for display.
    quote: Optional[QuoteInfo] = None
    gpu_evidence: Optional[bytes] = None
    attestation: AttestationMode = AttestationMode.NONE
    evidence: Optional[Evidence] = None
    custom_oids: list[OidExtension] = field(default_factory=list)
    quote_verification: Optional[QuoteVerificationResult] = None
    gpu_attestation: Optional[GPUAttestationResult] = None


# ---------------------------------------------------------------------------
#  Minimal DER reader (X.509 leaf: SPKI, names, validity, extensions)
# ---------------------------------------------------------------------------

def _der_tlv(data: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the TLV at off."""
    if off + 2 > len(data):
        raise ValueError("DER truncated")
    tag, first = data[off], data[off + 1]
    if first < 0x80:
        length, lh = first, 1
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or off + 2 + n > len(data):
            raise ValueError("DER length malformed")
        length, lh = int.from_bytes(data[off + 2:off + 2 + n], "big"), 1 + n
    start = off + 1 + lh
    end = start + length
    if end > len(data):
        raise ValueError("DER truncated")
    return tag, start, end


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """(tag, tlv_offset, content_start, content_end) of every child in [start, end)."""
    out = []
    off = start
    while off < end:
        tag, s, e = _der_tlv(data, off)
        out.append((tag, off, s, e))
        off = e
    return out


def _decode_oid(content: bytes) -> str:
    if not content:
        raise ValueError("empty OID")
    first = content[0]
    comps = [first // 40, first % 40] if first < 80 else [2, first - 80]
    val = 0
    for b in content[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            comps.append(val)
            val = 0
    return ".".join(str(c) for c in comps)


_NAME_ATTRS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress",
}

_SIG_ALGOS = {
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.3.101.112": "Ed25519",
}


def _der_name(data: bytes, start: int, end: int) -> str:
    """Render a Name in RFC 4514 order (last RDN first)."""
    parts = []
    for _tag, _o, rs, re_ in _der_children(data, start, end):        # RDN SET
        atvs = []
        for _t, _o2, as_, ae in _der_children(data, rs, re_):        # ATV SEQ
            kids = _der_children(data, as_, ae)
            if len(kids) != 2:
                continue
            oid = _decode_oid(data[kids[0][2]:kids[0][3]])
            value = data[kids[1][2]:kids[1][3]].decode("utf-8", errors="replace")
            atvs.append(f"{_NAME_ATTRS.get(oid, oid)}={value}")
        parts.append("+".join(atvs))
    return ",".join(reversed(parts))


def _der_time(tag: int, content: bytes) -> datetime:
    s = content.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        yy = int(s[:2])
        s = f"{2000 + yy if yy < 50 else 1900 + yy}{s[2:]}"
    return datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


@dataclass
class _ParsedCert:
    serial: int
    sig_algo: str
    issuer: str
    subject: str
    not_before: datetime
    not_after: datetime
    spki_der: bytes
    extensions: list[tuple[str, bool, bytes]]   # (oid, critical, extnValue content)


def _parse_certificate(der: bytes) -> _ParsedCert:
    """Parse the fields of an X.509 certificate this SDK needs. Signatures are
    not checked here: the chain is verified by the TLS handshake."""
    tag, cs, ce = _der_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("certificate is not a DER SEQUENCE")
    top = _der_children(der, cs, ce)
    if len(top) < 3 or top[0][0] != 0x30:
        raise ValueError("certificate structure malformed")
    tbs = _der_children(der, top[0][2], top[0][3])
    i = 0
    if tbs and tbs[0][0] == 0xA0:       # [0] EXPLICIT version
        i = 1
    if len(tbs) < i + 6:                # serial, sigalg, issuer, validity, subject, spki
        raise ValueError("tbsCertificate too short")
    serial = int.from_bytes(der[tbs[i][2]:tbs[i][3]], "big", signed=True)
    sig_kids = _der_children(der, tbs[i + 1][2], tbs[i + 1][3])
    sig_oid = _decode_oid(der[sig_kids[0][2]:sig_kids[0][3]]) if sig_kids else ""
    issuer = _der_name(der, tbs[i + 2][2], tbs[i + 2][3])
    times = _der_children(der, tbs[i + 3][2], tbs[i + 3][3])
    not_before = _der_time(times[0][0], der[times[0][2]:times[0][3]])
    not_after = _der_time(times[1][0], der[times[1][2]:times[1][3]])
    subject = _der_name(der, tbs[i + 4][2], tbs[i + 4][3])
    spki_der = der[tbs[i + 5][1]:tbs[i + 5][3]]
    extensions: list[tuple[str, bool, bytes]] = []
    for t, _o, s, e in tbs[i + 6:]:
        if t != 0xA3:                   # [3] EXPLICIT extensions
            continue
        seq = _der_children(der, s, e)
        if not seq:
            continue
        for _t, _o2, xs, xe in _der_children(der, seq[0][2], seq[0][3]):
            kids = _der_children(der, xs, xe)
            if len(kids) < 2:
                continue
            oid = _decode_oid(der[kids[0][2]:kids[0][3]])
            critical = False
            vi = 1
            if kids[1][0] == 0x01:
                critical = der[kids[1][2]] != 0
                vi = 2
            if vi >= len(kids) or kids[vi][0] != 0x04:
                continue
            extensions.append((oid, critical, der[kids[vi][2]:kids[vi][3]]))
    return _ParsedCert(serial, _SIG_ALGOS.get(sig_oid, sig_oid), issuer, subject,
                       not_before, not_after, spki_der, extensions)


def spki_der_of(der: bytes) -> bytes:
    """DER SubjectPublicKeyInfo of a DER certificate."""
    return _parse_certificate(der).spki_der


# ---------------------------------------------------------------------------
#  Certificate inspection
# ---------------------------------------------------------------------------

def inspect_der_certificate(der: bytes) -> CertInfo:
    """Inspect a DER X.509 certificate for the Privasys v2 extensions. A leaf
    carrying an Intel-arc quote extension is flagged v1 (parsed for display,
    never verified)."""
    p = _parse_certificate(der)
    info = CertInfo(
        subject=p.subject, issuer=p.issuer, serial=p.serial,
        not_before=p.not_before, not_after=p.not_after, sig_algo=p.sig_algo,
        pubkey_sha256=hashlib.sha256(p.spki_der).hexdigest(), spki_der=p.spki_der,
    )
    for oid, critical, value in p.extensions:
        info.extensions.append(oid)
        if oid in (OID_SGX_QUOTE, OID_TDX_QUOTE):
            info.v1_leaf = True
            info.quote = _quote_info(oid, value, critical)
        elif oid.startswith(OID_PRIVASYS_ARC_PREFIX):
            # Everything under the Privasys arc, including the open-ended
            # app-defined 5.4.* extensions: membership is by arc.
            info.custom_oids.append(OidExtension(oid=oid, label=oid_label(oid), value=value))
    return info


def _quote_info(oid: str, raw: bytes, critical: bool = False) -> QuoteInfo:
    q = QuoteInfo(oid=oid, label=oid_label(oid), raw=raw, critical=critical)
    if raw[:11] == b"MOCK_QUOTE:":
        q.is_mock = True
    if len(raw) >= 2:
        q.version = int.from_bytes(raw[0:2], "little")
    tee = {OID_SGX_QUOTE: "sgx", OID_TDX_QUOTE: "tdx", OID_EVIDENCE_SEV_SNP_REPORT: "sev-snp"}.get(oid)
    if tee and not q.is_mock:
        try:
            q.report_data = quote_report_data(tee, raw)
        except ValueError:
            pass
    return q


def quote_info_of(ev: Evidence) -> QuoteInfo:
    """QuoteInfo of an attest-response quote, keyed by the Intel-arc OID of its
    format so callers keep switching on it."""
    oid = {"tdx": OID_TDX_QUOTE, "tdx-gpu": OID_TDX_QUOTE,
           "sev-snp": OID_EVIDENCE_SEV_SNP_REPORT}.get(ev.tee, OID_SGX_QUOTE)
    return _quote_info(oid, ev.quote)


# ---------------------------------------------------------------------------
#  report_data, quote_time, exporter
# ---------------------------------------------------------------------------

def _report_data_hash(spki_der: bytes, binding: bytes) -> bytes:
    """SHA-512( SHA-256(SPKI_DER) || binding )."""
    return hashlib.sha512(hashlib.sha256(spki_der).digest() + binding).digest()


def expected_report_data(spki_der: bytes, ev: Evidence) -> bytes:
    """The report_data a quote must carry for the leaf with this SPKI:

        deterministic: SHA-512( SHA-256(SPKI_DER) || quote_time )
        challenge:     SHA-512( SHA-256(SPKI_DER) || context || hctx )

    with SHA-256(gpu_evidence) appended to the binding when GPU evidence is
    present. The verifier predicts this value; it never accepts one from the peer."""
    if ev.mode is AttestationMode.DETERMINISTIC:
        if len(ev.quote_time_raw) != QUOTE_TIME_LEN:
            raise ValueError("deterministic evidence needs a quote_time")
        binding = ev.quote_time_raw.encode("ascii")
    elif ev.mode is AttestationMode.CHALLENGE:
        if ev.context is None or ev.hctx is None or len(ev.context) != CONTEXT_LEN or len(ev.hctx) != HCTX_LEN:
            raise ValueError(f"challenge evidence needs a {CONTEXT_LEN}-byte context "
                             f"and a {HCTX_LEN}-byte exporter value")
        binding = ev.context + ev.hctx
    else:
        raise ValueError(f"no report_data for attestation mode {ev.mode.value}")
    if ev.gpu_evidence:
        binding += hashlib.sha256(ev.gpu_evidence).digest()
    return _report_data_hash(spki_der, binding)


def client_report_data(spki_der: bytes, client_context: bytes, hctx: bytes,
                       gpu_evidence: Optional[bytes] = None) -> bytes:
    """expected_report_data for the client evidence of a mutual leg:
    SHA-512( SHA-256(client SPKI) || client_context || hctx_c ), same GPU fold."""
    binding = client_context + hctx
    if gpu_evidence:
        binding += hashlib.sha256(gpu_evidence).digest()
    return _report_data_hash(spki_der, binding)


def quote_report_data(tee: str, quote: bytes) -> bytes:
    """The 64-byte report_data of a raw quote of the given evidence family."""
    if tee == "sgx":
        _, _, rd, _ = _sgx_slices(quote)
        if len(quote) < rd.stop:
            raise ValueError("SGX quote too small to contain report_data")
        return quote[rd]
    if tee in ("tdx", "tdx-gpu"):
        if len(quote) < TDX_QUOTE_REPORT_DATA.stop:
            raise ValueError("TDX quote too small to contain report_data")
        return quote[TDX_QUOTE_REPORT_DATA]
    if tee == "sev-snp":
        if len(quote) < SEV_SNP_REPORT_DATA.stop:
            raise ValueError("SEV-SNP report too small to contain report_data")
        return quote[SEV_SNP_REPORT_DATA]
    raise ValueError(f"unknown evidence family {tee!r}")


def check_quote_time(raw: str, now: Optional[datetime] = None) -> datetime:
    """Reject a quote_time older than the cache lifetime (24 h plus skew) or
    ahead of the clock beyond the allowed skew. Seconds are not part of the layout."""
    if now is None:
        now = datetime.now(timezone.utc)
    if len(raw) != QUOTE_TIME_LEN:
        raise ValueError(f"quote_time {raw!r} is not YYYY-MM-DDTHH:MMZ")
    try:
        t = datetime.strptime(raw, QUOTE_TIME_LAYOUT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"quote_time {raw!r}: {exc}") from None
    if t > now + QUOTE_SKEW:
        raise ValueError(f"quote_time {raw} is in the future")
    if now - t > QUOTE_MAX_AGE:
        raise ValueError(f"quote_time {raw} is older than 24 hours")
    return t


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int,
                      hash_name: str = "sha256") -> bytes:
    """HKDF-Expand-Label of RFC 8446 section 7.1 (HkdfLabel = length ||
    "tls13 " + label || context), over HMAC with the named hash."""
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hash_name).digest()
        out += block
        counter += 1
    return out[:length]


def tls_exporter(exporter_master_secret: bytes, label: str, context: bytes,
                 length: int = HCTX_LEN, hash_name: str = "sha256") -> bytes:
    """RFC 8446 section 7.5:

        TLS-Exporter(label, context, length) =
            HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter",
                              Hash(context), length)

    where Secret is the exporter_master_secret and the hash is the one of the
    negotiated cipher suite. This is the recipe of hctx; the Python client
    cannot obtain the secret from ssl, see the module docstring."""
    digest_size = hashlib.new(hash_name).digest_size
    derived = hkdf_expand_label(exporter_master_secret, label.encode("ascii"),
                                hashlib.new(hash_name, b"").digest(), digest_size, hash_name)
    return hkdf_expand_label(derived, b"exporter", hashlib.new(hash_name, context).digest(),
                             length, hash_name)


# ---------------------------------------------------------------------------
#  Attest messages and framing
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(s: str) -> bytes:
    """Strict base64url, padding tolerated (the protocol sends none)."""
    s = s.rstrip("=")
    return b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)


def leaf_id(spki_der: bytes) -> str:
    """The "leaf" field: base64url SHA-256 of the SPKI DER of the received leaf."""
    return _b64(hashlib.sha256(spki_der).digest())


def build_attest_request(mode: AttestationMode, spki_der: bytes,
                         context: Optional[bytes] = None) -> bytes:
    """JSON body of the request of docs/ratls-v2.md section 3.3."""
    if mode is AttestationMode.NONE:
        raise ValueError("no attest request in mode none")
    req = {"v": PROTOCOL_VERSION, "mode": mode.value, "leaf": leaf_id(spki_der)}
    if mode is AttestationMode.CHALLENGE:
        if context is None or len(context) != CONTEXT_LEN:
            raise ValueError(f"challenge request needs a {CONTEXT_LEN}-byte context")
        req["context"] = _b64(context)
    return json.dumps(req, separators=(",", ":")).encode("utf-8")


def parse_attest_response(body: bytes, mode: AttestationMode, status: int = 200,
                          now: Optional[datetime] = None) -> Evidence:
    """Parse and sanity-check the response of section 3.4 for a request sent
    in mode. Checks well-formedness only (version, mode echo, tee, encodings,
    quote_time freshness, client_context length); policy verification is
    verify_evidence. Raises ValueError with the reason."""
    try:
        resp = json.loads(body)
        if not isinstance(resp, dict):
            raise ValueError("not an object")
    except ValueError as exc:
        resp = None
        if status == 200:
            raise ValueError(f"attest response: {exc}") from None
    if resp is None or status != 200 or resp.get("error"):
        err = (resp or {}).get("error") or body.decode("utf-8", "replace").strip()
        if status == 404:
            raise ValueError(f"server has no RA-TLS v2 evidence endpoint ({ATTEST_PATH}): {err}")
        raise ValueError(f"attest failed ({status}): {err}")
    if resp.get("v") != PROTOCOL_VERSION:
        raise ValueError(f"attest response version {resp.get('v')!r}, want {PROTOCOL_VERSION}")
    if resp.get("mode") != mode.value:
        raise ValueError(f"attest response mode {resp.get('mode')!r}, requested {mode.value!r}")
    tee = resp.get("tee")
    if not isinstance(tee, str) or tee_type_of(tee) is None:
        raise ValueError(f"attest response: unknown tee {tee!r}")
    ev = Evidence(mode=mode, tee=tee)
    try:
        ev.quote = _b64_decode(resp.get("quote") or "")
    except (ValueError, TypeError):
        ev.quote = b""
    if not ev.quote:
        raise ValueError("attest response: quote is not base64url")
    gpu = resp.get("gpu_evidence")
    if gpu:
        try:
            ev.gpu_evidence = _b64_decode(gpu)
        except (ValueError, TypeError):
            ev.gpu_evidence = None
        if not ev.gpu_evidence:
            raise ValueError("attest response: gpu_evidence is not base64url")
    qt = resp.get("quote_time")
    if not isinstance(qt, str):
        raise ValueError("attest response: quote_time missing")
    ev.quote_time_raw = qt
    ev.quote_time = check_quote_time(qt, now)
    ce = resp.get("client_evidence") or "none"
    if ce == "required":
        ev.client_evidence_required = True
        cc = resp.get("client_context")
        if cc is None:
            raise ValueError("server requires client evidence without a client_context")
        try:
            ev.client_context = _b64_decode(cc)
        except (ValueError, TypeError):
            ev.client_context = b""
        if len(ev.client_context) != CONTEXT_LEN:
            raise ValueError(f"client_context is not a {CONTEXT_LEN}-byte base64url value")
    elif ce != "none":
        raise ValueError(f"attest response: unknown client_evidence {ce!r}")
    return ev


def encode_frame(payload: bytes) -> bytes:
    """One raw-binding frame: u32 big-endian length || payload."""
    if len(payload) > MAX_FRAME:
        raise ValueError(f"frame too large: {len(payload)}")
    return struct.pack(">I", len(payload)) + payload


def read_frame(recv: Callable[[int], bytes]) -> bytes:
    """Read one raw-binding frame with recv(n), which returns at most n bytes
    and b"" at end of stream."""
    def exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed inside an attest frame")
            buf += chunk
        return buf
    (length,) = struct.unpack(">I", exact(4))
    if length > MAX_FRAME:
        raise ValueError(f"frame too large: {length}")
    return exact(length)


# ---------------------------------------------------------------------------
#  Verification
# ---------------------------------------------------------------------------

def verify_certificate_extensions(der: bytes, policy: VerificationPolicy) -> CertInfo:
    """Verify a v2 leaf against the certificate part of a policy only: v2
    shape, image profile, expected OIDs. Proves nothing about the TEE."""
    info = inspect_der_certificate(der)
    if info.v1_leaf:
        raise ValueError("v1 RA-TLS certificate (evidence inside the certificate) "
                         "is not accepted by a v2 verifier")
    _verify_image_profile(info.custom_oids, policy)
    _verify_expected_oids(info.custom_oids, policy.expected_oids)
    return info


def verify_evidence(der: bytes, ev: Optional[Evidence], policy: VerificationPolicy) -> CertInfo:
    """Verify the evidence obtained for the connection whose leaf is der, in
    this order: v2 leaf shape, evidence family against policy.tee, measurement
    registers, report_data (predicted from the leaf SPKI and ev), image
    profile, expected OIDs, then the attestation server (quote signature and
    TCB, GPU verdict). Returns the CertInfo with quote, evidence and
    attestation filled. Raises ValueError naming the failed step."""
    info = inspect_der_certificate(der)
    if info.v1_leaf:
        raise ValueError("v1 RA-TLS certificate (evidence inside the certificate) "
                         "is not accepted by a v2 verifier")
    if ev is None:
        raise ValueError("no attestation evidence for this connection (attestation mode none)")
    if ev.quote[:11] == b"MOCK_QUOTE:":
        raise ValueError("evidence is a MOCK quote")

    # 1. Evidence family against the policy.
    tee = tee_type_of(ev.tee)
    if tee is None:
        raise ValueError(f"unknown evidence family {ev.tee!r}")
    if policy.tee is TeeType.NVIDIA_GPU:
        raise ValueError("TeeType.NVIDIA_GPU is not a primary evidence family in RA-TLS v2; "
                         "verify a tdx-gpu connection with TeeType.TDX")
    if tee is not policy.tee:
        raise ValueError(f"expected {policy.tee.value} evidence, got {ev.tee}")
    if ev.tee == "tdx-gpu" and not ev.gpu_evidence:
        raise ValueError("tdx-gpu evidence without gpu_evidence")

    # 2. Measurement registers.
    _verify_measurements(ev.quote, policy)

    # 3. report_data, predicted from the leaf and the evidence.
    expected = expected_report_data(info.spki_der, ev)
    actual = quote_report_data(ev.tee, ev.quote)
    if not hmac.compare_digest(actual, expected):
        raise ValueError(f"report_data mismatch ({ev.mode.value} mode):\n"
                         f"  got:      {actual.hex()}\n  expected: {expected.hex()}")

    # 4. Certificate extensions.
    _verify_image_profile(info.custom_oids, policy)
    _verify_expected_oids(info.custom_oids, policy.expected_oids)

    info.quote = quote_info_of(ev)
    info.gpu_evidence = ev.gpu_evidence
    info.attestation = ev.mode
    info.evidence = ev

    # 5. Attestation server: quote signature, collateral, TCB; GPU verdict.
    if policy.quote_verification is not None:
        if ev.gpu_evidence:
            info.quote_verification, info.gpu_attestation = _verify_tdx_gpu(
                ev.quote, ev.gpu_evidence, policy.quote_verification)
        else:
            info.quote_verification = _verify_quote(ev.quote, policy.quote_verification)
    return info


def _verify_image_profile(exts: list[OidExtension], policy: VerificationPolicy) -> None:
    """Reject non-production images unless the policy allows them. Any value
    other than "production" counts as a debug image; a certificate without the
    extension is accepted."""
    for ext in exts:
        if ext.oid != OID_IMAGE_PROFILE:
            continue
        profile = ext.value.decode("utf-8", errors="replace").strip()
        if profile != "production" and not policy.allow_debug_images:
            raise ValueError(f"server runs a {profile!r} image (OID {OID_IMAGE_PROFILE}): debug/dev "
                             "images are rejected unless VerificationPolicy.allow_debug_images is set")
        return


def _check_register(raw: bytes, sl: slice, expected: Optional[bytes], name: str) -> None:
    if expected is not None and raw[sl] != expected:
        raise ValueError(f"{name} mismatch: got {raw[sl].hex()}, expected {expected.hex()}")


def _verify_measurements(raw: bytes, policy: VerificationPolicy) -> None:
    if policy.tee is TeeType.SGX:
        mre, mrs, _, min_size = _sgx_slices(raw)
        if len(raw) < min_size:
            raise ValueError(f"SGX attestation blob too small: {len(raw)} < {min_size}")
        _check_register(raw, mre, policy.mr_enclave, "MRENCLAVE")
        _check_register(raw, mrs, policy.mr_signer, "MRSIGNER")
    elif policy.tee is TeeType.TDX:
        if len(raw) < TDX_QUOTE_MIN_SIZE:
            raise ValueError(f"TDX quote too small: {len(raw)} < {TDX_QUOTE_MIN_SIZE}")
        _check_register(raw, TDX_QUOTE_MRTD, policy.mr_td, "MRTD")
        _check_register(raw, TDX_QUOTE_RTMR1, policy.rtmr1, "RTMR1")
        _check_register(raw, TDX_QUOTE_RTMR2, policy.rtmr2, "RTMR2")
    elif policy.tee is TeeType.SEV_SNP:
        if len(raw) < SEV_SNP_REPORT_MIN_SIZE:
            raise ValueError(f"SEV-SNP report too small: {len(raw)} < {SEV_SNP_REPORT_MIN_SIZE}")
        _check_register(raw, SEV_SNP_MEASUREMENT, policy.measurement, "MEASUREMENT")
        _check_register(raw, SEV_SNP_HOST_DATA, policy.host_data, "HOST_DATA")
    # NVIDIA GPU evidence is verified remotely; no local measurement check.


def _verify_expected_oids(actual: list[OidExtension], expected: list[ExpectedOid]) -> None:
    present = {e.oid: e.value for e in actual}
    for exp in expected:
        if exp.oid not in present:
            raise ValueError(f"expected OID {exp.oid} ({oid_label(exp.oid)}) not found in certificate")
        if present[exp.oid] != exp.expected_value:
            raise ValueError(f"{oid_label(exp.oid)} ({exp.oid}) mismatch: got "
                             f"{present[exp.oid].hex()}, expected {exp.expected_value.hex()}")


def _post_json(config: QuoteVerificationConfig, payload: dict, what: str) -> dict:
    req = urllib.request.Request(config.endpoint, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    if config.token:
        req.add_header("Authorization", f"Bearer {config.token}")
    try:
        with urllib.request.urlopen(req, timeout=config.timeout_secs or 10) as resp:
            body = resp.read()
    except Exception as exc:
        raise ValueError(f"{what} request failed: {exc}") from exc
    try:
        return json.loads(body)
    except ValueError as exc:
        raise ValueError(f"failed to parse {what} response: {exc} (body: {body!r})") from None


def _quote_verdict(parsed: dict, config: QuoteVerificationConfig, what: str) -> QuoteVerificationResult:
    result = QuoteVerificationResult(
        status=QuoteVerificationStatus.from_str(parsed.get("status", "")),
        tcb_date=parsed.get("tcbDate"), advisory_ids=parsed.get("advisoryIds") or [],
        tcb_status=parsed.get("tcbStatus") or "")
    if result.status is not QuoteVerificationStatus.OK and result.status not in config.accepted_statuses:
        raise ValueError(f"{what} failed: status={result.status.value}, advisories={result.advisory_ids}")
    if config.enforce_tcb_status:
        try:
            _tcb_status_acceptable(result.tcb_status, config.acceptable_tcb_statuses)
        except ValueError as exc:
            raise ValueError(f"{what} failed: {exc} (tcbDate={result.tcb_date}, "
                             f"advisories={result.advisory_ids})") from None
    return result


def _verify_quote(quote: bytes, config: QuoteVerificationConfig) -> QuoteVerificationResult:
    parsed = _post_json(config, {"quote": b64encode(quote).decode("ascii")}, "quote verification")
    return _quote_verdict(parsed, config, "quote verification")


def _verify_tdx_gpu(quote: bytes, gpu_evidence: bytes, config: QuoteVerificationConfig,
                    ) -> tuple[QuoteVerificationResult, GPUAttestationResult]:
    """Combined CPU quote plus NVIDIA GPU evidence ("tdx-gpu" request). The GPU
    evidence is already bound to the leaf through report_data; this establishes
    a genuine NVIDIA device in CC mode with an authentic, nonce-bound report."""
    parsed = _post_json(config, {"quote": b64encode(quote).decode("ascii"), "type": "tdx-gpu",
                                 "gpuQuote": b64encode(gpu_evidence).decode("ascii")}, "tdx-gpu verification")
    result = _quote_verdict(parsed, config, "tdx-gpu verification")
    g = parsed.get("gpuAttestation")
    if not isinstance(g, dict):
        raise ValueError("tdx-gpu verification: server returned no GPU attestation result")
    gpu = GPUAttestationResult(
        verified=bool(g.get("verified")), status=g.get("status", ""), message=g.get("message", ""),
        error=g.get("error", ""), gpu_uuid=g.get("gpuUuid", ""), driver=g.get("driver", ""),
        vbios=g.get("vbios", ""), cc_environment=g.get("ccEnvironment", ""),
        measurements_verified=bool(g.get("measurementsVerified")))
    if not gpu.verified:
        raise ValueError(f"GPU attestation failed: status={gpu.status} error={gpu.error}")
    return result, gpu


# ---------------------------------------------------------------------------
#  Attested cross-enclave dependencies (OID 7.1)
# ---------------------------------------------------------------------------

# A workload that depends on other enclaves is pinned to a fixed set of
# dependency identities, carried by the runtime in OID_ATTESTED_DEPENDENCY_SET.
# A dependency identity is the same tuple used to verify any app (measurement
# registers plus required OID values), and a dependency entry commits to the
# dependency's own subtree through folded_identity, so enforcement is a single
# direct-edge check at every hop. The canonical byte encoding below is
# reproduced byte-for-byte in every SDK.

_DOMAIN_FOLD_IDENTITY = "privasys-app-identity-v1"


@dataclass
class DepTdxMeasurement:
    mrtd: str
    rtmr1: str
    rtmr2: str


@dataclass
class DepMeasurement:
    """One allowed measurement: an SGX MRENCLAVE (hex) or a TDX triple."""
    sgx: str = ""
    tdx: Optional[DepTdxMeasurement] = None

    def canonical(self) -> str:
        if self.tdx is not None:
            return f"tdx:{self.tdx.mrtd.lower()}:{self.tdx.rtmr1.lower()}:{self.tdx.rtmr2.lower()}"
        return f"sgx:{self.sgx.lower()}"


@dataclass
class DependencyEntry:
    app_id: str                                     # lowercase hex of the peer's OID 4.1
    measurements: list[DepMeasurement] = field(default_factory=list)
    required_oids: list[ExpectedOid] = field(default_factory=list)
    folded_identity: str = ""                       # fold_identity_hex of the dependency's own subtree


@dataclass
class DependencySet:
    entries: list[DependencyEntry] = field(default_factory=list)


def _w_u32(w: bytearray, n: int) -> None:
    w += struct.pack(">I", n)


def _w_bytes(w: bytearray, b: bytes) -> None:
    _w_u32(w, len(b))
    w += b


def _w_str(w: bytearray, s: str) -> None:
    _w_bytes(w, s.encode("utf-8"))


def _sorted_oids(oids: list[ExpectedOid]) -> list[ExpectedOid]:
    return sorted(oids, key=lambda o: (o.oid, o.expected_value))


def _write_dependency_set(w: bytearray, s: DependencySet) -> None:
    """Length-prefixed canonical grammar over the normalised set: entries by
    app id, measurements by canonical form, required OIDs by (oid, value)."""
    entries = sorted(s.entries, key=lambda e: e.app_id)
    _w_u32(w, len(entries))
    for e in entries:
        _w_str(w, e.app_id)
        ms = sorted(e.measurements, key=lambda m: m.canonical())
        _w_u32(w, len(ms))
        for m in ms:
            _w_str(w, m.canonical())
        oids = _sorted_oids(e.required_oids)
        _w_u32(w, len(oids))
        for o in oids:
            _w_str(w, o.oid)
            _w_bytes(w, o.expected_value)
        _w_str(w, e.folded_identity.lower())


def encode_dependency_set(s: DependencySet) -> bytes:
    """Canonical encoding of the OID_ATTESTED_DEPENDENCY_SET extension value,
    independent of declaration order."""
    w = bytearray()
    _write_dependency_set(w, s)
    return bytes(w)


class _Reader:
    def __init__(self, buf: bytes):
        self.buf, self.off = buf, 0

    def u32(self) -> int:
        if self.off + 4 > len(self.buf):
            raise ValueError("dependency-set encoding truncated")
        (n,) = struct.unpack(">I", self.buf[self.off:self.off + 4])
        self.off += 4
        return n

    def bytes(self) -> bytes:
        n = self.u32()
        if self.off + n > len(self.buf):
            raise ValueError("dependency-set encoding truncated")
        b = self.buf[self.off:self.off + n]
        self.off += n
        return b

    def str(self) -> str:
        return self.bytes().decode("utf-8")


def decode_dependency_set(b: bytes) -> DependencySet:
    """Parse the canonical encoding, for inspection and round-trip checks."""
    r = _Reader(b)
    out = DependencySet()
    for _ in range(r.u32()):
        e = DependencyEntry(app_id=r.str())
        for _ in range(r.u32()):
            s = r.str()
            if s.startswith("tdx:"):
                parts = (s[4:].split(":") + ["", "", ""])[:3]
                e.measurements.append(DepMeasurement(tdx=DepTdxMeasurement(*parts)))
            else:
                e.measurements.append(DepMeasurement(sgx=s[4:] if s.startswith("sgx:") else s))
        for _ in range(r.u32()):
            oid = r.str()
            e.required_oids.append(ExpectedOid(oid, r.bytes()))
        e.folded_identity = r.str()
        out.entries.append(e)
    if r.off != len(b):
        raise ValueError("trailing bytes in dependency-set encoding")
    return out


def fold_identity(own_measurements: list[str], own_required_oids: list[ExpectedOid],
                  deps: DependencySet) -> bytes:
    """identity(X) = SHA-256( domain || measurements(X) || requiredOids(X) || encode(deps(X)) ),
    a commitment to the whole dependency subtree of X."""
    w = bytearray()
    _w_str(w, _DOMAIN_FOLD_IDENTITY)
    ms = sorted(m.lower() for m in own_measurements)
    _w_u32(w, len(ms))
    for m in ms:
        _w_str(w, m)
    oids = _sorted_oids(own_required_oids)
    _w_u32(w, len(oids))
    for o in oids:
        _w_str(w, o.oid)
        _w_bytes(w, o.expected_value)
    _write_dependency_set(w, deps)
    return hashlib.sha256(bytes(w)).digest()


def fold_identity_hex(own_measurements: list[str], own_required_oids: list[ExpectedOid],
                      deps: DependencySet) -> str:
    return fold_identity(own_measurements, own_required_oids, deps).hex()


def _measurement_policy(tee: TeeType, m: DepMeasurement) -> VerificationPolicy:
    pol = VerificationPolicy(tee=tee)
    if tee is TeeType.SGX:
        b = bytes.fromhex(m.sgx) if m.sgx else b""
        if len(b) != 32:
            raise ValueError(f"invalid SGX MRENCLAVE {m.sgx!r}")
        pol.mr_enclave = b
    elif tee is TeeType.TDX:
        if m.tdx is None:
            raise ValueError("TDX measurement missing MRTD triple")
        regs = []
        for name, hx in (("MRTD", m.tdx.mrtd), ("RTMR1", m.tdx.rtmr1), ("RTMR2", m.tdx.rtmr2)):
            b = bytes.fromhex(hx) if hx else b""
            if len(b) != 48:
                raise ValueError(f"invalid TDX {name} {hx!r}")
            regs.append(b)
        pol.mr_td, pol.rtmr1, pol.rtmr2 = regs
    else:
        raise ValueError("unsupported TEE type for dependency measurement")
    return pol


def match_dependency(peer: CertInfo, tee: TeeType, entry: DependencyEntry) -> None:
    """Fail-closed check of a verified peer (CertInfo of verify_evidence)
    against one entry: at least one pinned measurement matches and every
    required OID is present verbatim. Raises ValueError otherwise."""
    if peer.quote is None or not peer.quote.raw:
        raise ValueError(f"dependency {entry.app_id}: peer carries no quote (fail closed)")
    if not entry.measurements:
        raise ValueError(f"dependency {entry.app_id}: entry pins no measurement (fail closed)")
    last = "no measurement"
    for m in entry.measurements:
        try:
            _verify_measurements(peer.quote.raw, _measurement_policy(tee, m))
            break
        except ValueError as exc:
            last = str(exc)
    else:
        raise ValueError(f"dependency {entry.app_id}: peer matches no pinned measurement (fail closed): {last}")
    try:
        _verify_expected_oids(peer.custom_oids, entry.required_oids)
    except ValueError as exc:
        raise ValueError(f"dependency {entry.app_id}: {exc}") from None


def app_id_from_cert(peer: CertInfo) -> str:
    """The peer's management app id (OID 4.1) as lowercase hex, "" when absent."""
    for o in peer.custom_oids:
        if o.oid == OID_WORKLOAD_APP_ID:
            return o.value.hex()
    return ""


def dependency_set_from_cert(peer: CertInfo) -> Optional[DependencySet]:
    """The dependency set a peer's runtime stamped in OID 7.1, None when absent."""
    for o in peer.custom_oids:
        if o.oid == OID_ATTESTED_DEPENDENCY_SET:
            return decode_dependency_set(o.value)
    return None


def verify_peer_is_dependency(peer: CertInfo, tee: TeeType, dep_set: DependencySet) -> None:
    """Top-level gate: the peer's app id must be a declared dependency and the
    peer must match that entry."""
    app_id = app_id_from_cert(peer)
    if not app_id:
        raise ValueError(f"peer certificate carries no app-id (OID {OID_WORKLOAD_APP_ID}); "
                         "cannot match a declared dependency (fail closed)")
    for e in dep_set.entries:
        if e.app_id == app_id:
            return match_dependency(peer, tee, e)
    raise ValueError(f"peer app-id {app_id} is not a declared dependency (fail closed)")


# ---------------------------------------------------------------------------
#  Client
# ---------------------------------------------------------------------------

class RaTlsClient:
    """An RA-TLS v2 connection: TLS 1.3 handshake with the chain check of the
    trust mode, then the evidence exchange, before any application data.

    Parameters
    ----------
    host, port : the peer, usually dialled by IP.
    ca_cert : path to a PEM file whose certificates replace the embedded
        Privasys intermediates as fleet trust anchors. Always used fleet-style
        (no hostname verification); never combined with ``TrustMode.PUBLIC``.
    timeout : socket timeout in seconds.
    attestation : DETERMINISTIC (default) or NONE. CHALLENGE raises
        NotImplementedError, see the module docstring.
    framing : HTTP (default) or RAW for legs that do not speak HTTP.
    server_name : TLS SNI for per-workload certificates; also the Host header
        and the identity checked by the public verifier.
    trust : AUTO (default), FLEET or PUBLIC, see ``TrustMode``. PUBLIC with an
        attested mode, or with ``ca_cert``, raises ValueError here.

    AUTO without evidence and the second connection
    -----------------------------------------------
    CPython's ``ssl`` module verifies a chain only inside a handshake: there
    is no API to verify a captured chain out of band, and no verify callback.
    So in AUTO with ``AttestationMode.NONE`` the fleet handshake runs first
    and, when it fails on the chain, the client connects a second time with
    ``ssl.create_default_context()`` (system roots, hostname checked). A host
    that is an enclave costs one handshake; a host that is not costs two. A
    caller that knows the host is not an enclave passes
    ``trust=TrustMode.PUBLIC`` and skips the first attempt.
    """

    def __init__(self, host: str, port: int = 443, ca_cert: Optional[str] = None,
                 timeout: float = 10.0, attestation: AttestationMode = AttestationMode.DETERMINISTIC,
                 framing: Framing = Framing.HTTP, server_name: Optional[str] = None,
                 trust: TrustMode = TrustMode.AUTO):
        if attestation is AttestationMode.CHALLENGE:
            raise NotImplementedError(CHALLENGE_UNSUPPORTED)
        if not isinstance(trust, TrustMode):
            raise ValueError(f"unknown trust mode {trust!r}")
        if trust is TrustMode.PUBLIC:
            # Never downgrade an attested connection to public PKI.
            if attestation is not AttestationMode.NONE:
                raise ValueError(f'trust "public" cannot be combined with attestation mode '
                                 f'"{attestation.value}": an attested connection must chain to '
                                 f'the fleet anchors')
            if ca_cert is not None:
                raise ValueError('ca_cert is a fleet anchor and cannot be combined with trust "public"')
        self.host, self.port, self.ca_cert, self.timeout = host, port, ca_cert, timeout
        self.attestation, self.framing, self.server_name = attestation, framing, server_name
        self.trust = trust
        self._trust_resolved: Optional[TrustMode] = None
        self._tls: Optional[ssl.SSLSocket] = None
        self._peer_der: bytes = b""
        self._peer_chain_der: list[bytes] = []
        self._evidence: Optional[Evidence] = None
        self._last_policy: Optional[VerificationPolicy] = None

    def __enter__(self) -> "RaTlsClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- lifecycle -------------------------------------------------------------

    @staticmethod
    def _common_context(ctx: ssl.SSLContext) -> ssl.SSLContext:
        # TLS 1.3 only: the Privasys runtimes offer nothing lower.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # The marker routes the connection to the gateway splice path; http/1.1
        # lets the enclave's HTTP server negotiate a protocol. h2 is deliberately
        # not offered: this client speaks HTTP/1.1 over the socket.
        ctx.set_alpn_protocols([RATLS_ALPN_PROTO, "http/1.1"])
        return ctx

    def _fleet_context(self) -> ssl.SSLContext:
        """The fleet anchors (or ``ca_cert``), partial chains allowed, no hostname check."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        # The anchors are intermediates, not self-signed roots.
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        if self.ca_cert:
            ctx.load_verify_locations(cafile=self.ca_cert)
        else:
            ctx.load_verify_locations(cadata=PRIVASYS_TRUST_ANCHORS_PEM)
        return self._common_context(ctx)

    def _public_context(self) -> ssl.SSLContext:
        """The system's public PKI roots with hostname verification (the ordinary HTTPS check)."""
        return self._common_context(ssl.create_default_context())

    def _handshake(self, ctx: ssl.SSLContext) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            self._tls = ctx.wrap_socket(raw, server_hostname=self.server_name or self.host)
            self._peer_der = self._tls.getpeercert(binary_form=True) or b""
            if not self._peer_der:
                raise ValueError("no peer certificate")
            self._peer_chain_der = self._verified_chain()
        except BaseException:
            self.close()
            raw.close()
            raise

    def connect(self) -> None:
        public_only = self.trust is TrustMode.PUBLIC
        fleet_only = self.trust is TrustMode.FLEET or self.attestation is not AttestationMode.NONE
        if public_only:
            self._handshake(self._public_context())
            self._trust_resolved = TrustMode.PUBLIC
        else:
            try:
                self._handshake(self._fleet_context())
                self._trust_resolved = TrustMode.FLEET
            except ssl.SSLCertVerificationError as fleet_err:
                if fleet_only:
                    raise
                # AUTO without evidence: the second chance is the public verifier
                # on a second connection (see the class docstring).
                identity = self.server_name or self.host
                try:
                    self._handshake(self._public_context())
                except ssl.SSLCertVerificationError as public_err:
                    raise ssl.SSLCertVerificationError(
                        f'certificate chain reaches neither a Privasys fleet anchor nor a public '
                        f'PKI root for "{identity}" (trust auto, no evidence requested): '
                        f'fleet: {fleet_err}; public: {public_err}') from public_err
                self._trust_resolved = TrustMode.PUBLIC
        try:
            # Evidence exchange, before any application data. A failure closes
            # the connection: a caller never gets a client whose evidence is
            # missing in a mode that asked for it.
            self._attest(self.attestation)
        except BaseException:
            self.close()
            raise

    def _verified_chain(self) -> list[bytes]:
        get = getattr(self._tls, "get_verified_chain", None)      # CPython 3.13+
        if get is None:
            return [self._peer_der]
        try:
            return [c if isinstance(c, bytes) else c.public_bytes(ssl.ENCODING_DER) for c in get()]
        except Exception:
            return [self._peer_der]

    def close(self) -> None:
        if self._tls is not None:
            try:
                self._tls.close()
            except Exception:
                pass
        self._tls = None

    # -- evidence exchange -----------------------------------------------------

    def _attest(self, mode: AttestationMode) -> None:
        if mode is AttestationMode.NONE:
            self._evidence = None
            return
        if mode is AttestationMode.CHALLENGE:
            raise NotImplementedError(CHALLENGE_UNSUPPORTED)
        spki = spki_der_of(self._peer_der)
        status, body = self._attest_round_trip(build_attest_request(mode, spki))
        ev = parse_attest_response(body, mode, status)
        if ev.client_evidence_required:
            raise NotImplementedError(
                "server requires client evidence (mutual leg); the Python SDK cannot "
                "present it because CPython's ssl module exposes no TLS exporter")
        self._evidence = ev

    def _attest_round_trip(self, body: bytes) -> tuple[int, bytes]:
        assert self._tls is not None
        if self.framing is Framing.RAW:
            self._tls.sendall(encode_frame(body))
            return 200, read_frame(self._tls.recv)
        self._send_http_request("POST", ATTEST_PATH, body=body)
        return self._recv_http_response()

    def reattest(self) -> None:
        """Repeat the evidence exchange on the same connection and, when a
        policy was verified before, verify the new evidence against it.
        Long-lived connections call it every few minutes and drop the
        connection on error."""
        if self.attestation is AttestationMode.NONE:
            raise ValueError("connection was opened with AttestationMode.NONE")
        if self.framing is Framing.RAW:
            raise ValueError("re-attestation is not possible on the raw binding; reconnect instead")
        self._attest(self.attestation)
        if self._last_policy is not None:
            self.verify_certificate(self._last_policy)

    # -- state -----------------------------------------------------------------

    @property
    def evidence(self) -> Optional[Evidence]:
        """Evidence obtained for this connection, None in mode NONE. Verified
        only once verify_certificate returned."""
        return self._evidence

    @property
    def attestation_tag(self) -> str:
        """The connection tag the server records and exposes to the workload as
        X-Privasys-Attestation: "none", "deterministic" or "challenge"."""
        return self._evidence.mode.value if self._evidence is not None else AttestationMode.NONE.value

    @property
    def trust_resolved(self) -> Optional[TrustMode]:
        """The verifier the server chain satisfied, FLEET or PUBLIC; None before
        connect. PUBLIC only ever appears with ``AttestationMode.NONE``."""
        return self._trust_resolved

    @property
    def tls_version(self) -> str:
        return (self._tls.version() or "") if self._tls else ""

    @property
    def cipher(self) -> tuple:
        return self._tls.cipher() if self._tls else ("", "", 0)

    @property
    def peer_certificate_der(self) -> bytes:
        return self._peer_der

    @property
    def peer_certificates_der(self) -> list[bytes]:
        """The verified chain, leaf first (leaf only before CPython 3.13)."""
        return list(self._peer_chain_der)

    def inspect_certificate(self) -> CertInfo:
        """CertInfo of the leaf with the connection's evidence attached
        UNVERIFIED, so measurements can be displayed. verify_certificate verifies."""
        info = inspect_der_certificate(self._peer_der)
        if self._evidence is not None:
            info.quote = quote_info_of(self._evidence)
            info.gpu_evidence = self._evidence.gpu_evidence
            info.attestation = self._evidence.mode
            info.evidence = self._evidence
        return info

    def verify_certificate(self, policy: VerificationPolicy) -> CertInfo:
        """Verify the leaf and the evidence of this connection against policy
        (verify_evidence); in mode NONE only the certificate extensions.
        Raises ValueError on failure."""
        if not self._peer_der:
            raise ValueError("no peer certificate")
        self._last_policy = policy
        if self.attestation is AttestationMode.NONE:
            return verify_certificate_extensions(self._peer_der, policy)
        return verify_evidence(self._peer_der, self._evidence, policy)

    # -- HTTP/1.1 over the verified connection ---------------------------------

    def _send_http_request(self, method: str, path: str, body: bytes = b"",
                           auth_token: Optional[str] = None, connection_close: bool = False,
                           headers: Optional[dict[str, str]] = None) -> None:
        assert self._tls is not None
        hdrs = {"Host": self.server_name or self.host}
        if body:
            hdrs["Content-Length"] = str(len(body))
            hdrs["Content-Type"] = "application/json"
        if auth_token:
            hdrs["Authorization"] = f"Bearer {auth_token}"
        if connection_close:
            hdrs["Connection"] = "close"
        for k, v in (headers or {}).items():
            hdrs[k] = v
        head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        self._tls.sendall(head.encode("latin-1") + body)

    def _recv_http_response(self) -> tuple[int, bytes]:
        """Read one HTTP/1.1 response: (status, body). Content-Length, chunked
        and close-delimited bodies are all handled (Go's http server chunks
        anything over its 2 KiB buffer)."""
        assert self._tls is not None
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._tls.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed before HTTP headers")
            buf += chunk
        head_end = buf.index(b"\r\n\r\n")
        lines = buf[:head_end].decode("ascii", errors="replace").split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise RuntimeError(f"malformed HTTP status line: {lines[0]!r}")
        status = int(parts[1])
        content_length: Optional[int] = None
        chunked = close = False
        for line in lines[1:]:
            name, _, value = line.partition(":")
            name, value = name.strip().lower(), value.strip().lower()
            if name == "content-length":
                content_length = int(value)
            elif name == "transfer-encoding":
                chunked = "chunked" in value
            elif name == "connection":
                close = value == "close"
        rest = buf[head_end + 4:]
        if chunked:
            return status, self._decode_chunked(rest)
        if content_length is not None:
            while len(rest) < content_length:
                chunk = self._tls.recv(4096)
                if not chunk:
                    break
                rest += chunk
            return status, rest[:content_length]
        if close:
            while True:
                try:
                    chunk = self._tls.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                rest += chunk
            return status, rest
        return status, b""

    def _decode_chunked(self, rest: bytes) -> bytes:
        assert self._tls is not None
        body, pos = b"", 0
        while True:
            while b"\r\n" not in rest[pos:]:
                chunk = self._tls.recv(4096)
                if not chunk:
                    raise ConnectionError("connection closed inside chunked body")
                rest += chunk
            line_end = rest.index(b"\r\n", pos)
            size = int(rest[pos:line_end].split(b";")[0].strip(), 16)
            pos = line_end + 2
            while len(rest) < pos + size + 2:
                chunk = self._tls.recv(4096)
                if not chunk:
                    raise ConnectionError("connection closed inside chunked body")
                rest += chunk
            if size == 0:
                return body
            body += rest[pos:pos + size]
            pos += size + 2

    def http_do(self, method: str, path: str, body: bytes = b"", auth_token: Optional[str] = None,
                headers: Optional[dict[str, str]] = None) -> tuple[int, bytes]:
        """One HTTP/1.1 request over the attested connection with the caller's
        full header set; returns (status, body)."""
        self._send_http_request(method, path, body=body, auth_token=auth_token, headers=headers)
        return self._recv_http_response()

    def _json_call(self, method: str, path: str, body: bytes = b"",
                   auth_token: Optional[str] = None, connection_close: bool = False):
        self._send_http_request(method, path, body=body, auth_token=auth_token,
                                connection_close=connection_close)
        status, resp = self._recv_http_response()
        if status != 200:
            raise RuntimeError(f"{method} {path} failed ({status}): {resp.decode('utf-8', 'replace')}")
        return json.loads(resp) if resp else {}

    def healthz(self) -> dict:
        """GET /healthz, liveness probe (no auth)."""
        return self._json_call("GET", "/healthz")

    def readyz(self, auth_token: Optional[str] = None) -> dict:
        """GET /readyz (monitoring+ role)."""
        return self._json_call("GET", "/readyz", auth_token=auth_token)

    def status(self, auth_token: Optional[str] = None) -> list:
        """GET /status (monitoring+ role)."""
        return self._json_call("GET", "/status", auth_token=auth_token)

    def metrics(self, auth_token: Optional[str] = None) -> dict:
        """GET /metrics (monitoring+ role)."""
        return self._json_call("GET", "/metrics", auth_token=auth_token)

    def send_data(self, data: bytes, auth_token: Optional[str] = None) -> bytes:
        """POST /data with a module command; returns the response bytes."""
        status, body = self.http_do("POST", "/data", body=data, auth_token=auth_token)
        if status != 200:
            raise RuntimeError(f"send_data failed ({status}): {body.decode('utf-8', 'replace')}")
        return body

    def set_attestation_servers(self, servers: list[dict], auth_token: Optional[str] = None) -> dict:
        """PUT /attestation-servers."""
        payload = json.dumps({"servers": servers}).encode("utf-8")
        return self._json_call("PUT", "/attestation-servers", body=payload, auth_token=auth_token)

    def shutdown(self, auth_token: Optional[str] = None) -> None:
        """POST /shutdown (manager role)."""
        self._json_call("POST", "/shutdown", auth_token=auth_token, connection_close=True)


# ---------------------------------------------------------------------------
#  Pretty-print
# ---------------------------------------------------------------------------

def _fmt_time(t: Optional[datetime]) -> str:
    return t.isoformat() if t else ""


def print_cert_info(info: CertInfo) -> None:
    """Human-readable certificate, evidence and verification summary."""
    print(f"  Subject      : {info.subject}")
    print(f"  Issuer       : {info.issuer}")
    print(f"  Serial       : {info.serial}")
    print(f"  Not Before   : {_fmt_time(info.not_before)}")
    print(f"  Not After    : {_fmt_time(info.not_after)}")
    print(f"  Sig Algo     : {info.sig_algo}")
    print(f"  PubKey SHA256: {info.pubkey_sha256}")
    print(f"  Attestation  : {info.attestation.value}")
    if info.v1_leaf:
        print("  ** v1 leaf: evidence inside the certificate, rejected by a v2 verifier **")

    q = info.quote
    if q is not None:
        print("\n  ** Evidence **")
        print(f"    Format    : {q.oid}  ({q.label})")
        if info.evidence is not None:
            print(f"    TEE       : {info.evidence.tee}")
            if info.evidence.quote_time_raw:
                print(f"    QuoteTime : {info.evidence.quote_time_raw}")
        print(f"    Size      : {len(q.raw)} bytes")
        if q.is_mock:
            print("    ** MOCK QUOTE **")
        if q.version is not None:
            print(f"    Version   : {q.version}")
        if q.report_data:
            print(f"    ReportData: {q.report_data.hex()}")
        if q.oid == OID_SGX_QUOTE:
            mre, mrs, _, min_size = _sgx_slices(q.raw)
            if len(q.raw) >= min_size:
                print(f"    Blob      : {'RawReport' if detect_sgx_raw_report(q.raw) else 'DcapV3'}")
                print(f"    MRENCLAVE : {q.raw[mre].hex()}")
                print(f"    MRSIGNER  : {q.raw[mrs].hex()}")
        elif q.oid == OID_TDX_QUOTE and len(q.raw) >= TDX_QUOTE_MIN_SIZE:
            print(f"    MRTD      : {q.raw[TDX_QUOTE_MRTD].hex()}")
            print(f"    RTMR1     : {q.raw[TDX_QUOTE_RTMR1].hex()}")
            print(f"    RTMR2     : {q.raw[TDX_QUOTE_RTMR2].hex()}")
        elif q.oid == OID_EVIDENCE_SEV_SNP_REPORT and len(q.raw) >= SEV_SNP_REPORT_MIN_SIZE:
            print(f"    Measurement: {q.raw[SEV_SNP_MEASUREMENT].hex()}")
            print(f"    HostData   : {q.raw[SEV_SNP_HOST_DATA].hex()}")
        if info.gpu_evidence:
            print(f"    GPU evid. : {len(info.gpu_evidence)} bytes, "
                  f"SHA-256 {hashlib.sha256(info.gpu_evidence).hexdigest()}")
        print(f"    Preview   : {q.raw[:32].hex()}...")
    else:
        print("\n  No evidence attached (attestation mode none, or not yet requested).")

    if info.custom_oids:
        print("\n  ** Privasys extensions **")
        for ext in info.custom_oids:
            print(f"    {ext.label} ({ext.oid}): {ext.value.hex()}")
    elif info.extensions:
        print(f"\n  Extensions   : {', '.join(info.extensions)}")

    if info.quote_verification is not None:
        qv = info.quote_verification
        print("\n  ** Quote Verification **")
        print(f"    Status    : {qv.status.value}")
        if qv.tcb_status:
            print(f"    TCB Status: {qv.tcb_status}")
        if qv.tcb_date:
            print(f"    TCB Date  : {qv.tcb_date}")
        if qv.advisory_ids:
            print(f"    Advisories: {', '.join(qv.advisory_ids)}")
    if info.gpu_attestation is not None:
        g = info.gpu_attestation
        print("\n  ** GPU Attestation **")
        print(f"    Verified  : {g.verified} ({g.status})")
        if g.gpu_uuid:
            print(f"    GPU       : {g.gpu_uuid}, driver {g.driver}, vbios {g.vbios}")
