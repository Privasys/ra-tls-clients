# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

"""RA-TLS client connector for enclave-os-mini.

Provides:
  - TLS connection with optional CA certificate verification
  - RA-TLS certificate inspection (SGX / TDX quote extraction)
  - Length-delimited framing (4-byte big-endian prefix)
  - Typed request/response helpers matching the Rust protocol

Usage as library:
    from ratls_client import RaTlsClient

    with RaTlsClient("141.94.219.130", 443, ca_cert="ca.pem") as client:
        info = client.inspect_certificate()
        resp = client.send_data(b"hello")
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import struct
import sys
import urllib.request
from base64 import b64encode
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
#  RA-TLS OIDs
# ---------------------------------------------------------------------------

RATLS_OIDS: dict[str, str] = {
    "1.2.840.113741.1.13.1.0": "SGX Quote",
    "1.2.840.113741.1.5.5.1.6": "TDX Quote",
}

# Privasys configuration OIDs
OID_CONFIG_MERKLE_ROOT = "1.3.6.1.4.1.65230.1.1"
OID_EGRESS_CA_HASH = "1.3.6.1.4.1.65230.2.1"
OID_WASM_APPS_HASH = "1.3.6.1.4.1.65230.2.3"

PRIVASYS_OIDS: dict[str, str] = {
    OID_CONFIG_MERKLE_ROOT: "Config Merkle Root",
    OID_EGRESS_CA_HASH: "Egress CA Hash",
    OID_WASM_APPS_HASH: "WASM Apps Hash",
}

# Combined label map
ALL_OIDS: dict[str, str] = {**RATLS_OIDS, **PRIVASYS_OIDS}


# ---------------------------------------------------------------------------
#  DCAP quote byte-offset constants
# ---------------------------------------------------------------------------

# SGX DCAP Quote v3: QuoteHeader(48) + ReportBody(384)
SGX_QUOTE_MIN_SIZE = 432
SGX_QUOTE_MRENCLAVE = slice(112, 144)
SGX_QUOTE_MRSIGNER = slice(176, 208)
SGX_QUOTE_REPORT_DATA = slice(368, 432)

# TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584)
TDX_QUOTE_MIN_SIZE = 632
TDX_QUOTE_MRTD = slice(184, 232)
TDX_QUOTE_REPORT_DATA = slice(568, 632)


# ---------------------------------------------------------------------------
#  Certificate inspection result
# ---------------------------------------------------------------------------

@dataclass
class QuoteInfo:
    """Parsed attestation quote embedded in the certificate."""
    oid: str
    label: str
    critical: bool
    raw: bytes
    is_mock: bool = False
    version: Optional[int] = None
    report_data: Optional[bytes] = None


@dataclass
class OidExtension:
    """A custom X.509 extension (e.g. Privasys configuration OID)."""
    oid: str
    label: str
    value: bytes


@dataclass
class CertInfo:
    """Summary of the RA-TLS server certificate."""
    subject: str = ""
    issuer: str = ""
    serial: int = 0
    not_before: str = ""
    not_after: str = ""
    sig_algo: str = ""
    pubkey_sha256: str = ""
    extensions: list[str] = field(default_factory=list)
    quote: Optional[QuoteInfo] = None
    custom_oids: list[OidExtension] = field(default_factory=list)
    quote_verification: Optional["QuoteVerificationResult"] = None


# ---------------------------------------------------------------------------
#  Framing helpers
# ---------------------------------------------------------------------------

def encode_frame(payload: bytes) -> bytes:
    """Length-delimited frame: [4-byte big-endian length][payload]."""
    return struct.pack(">I", len(payload)) + payload


def decode_frame(data: bytes) -> tuple[Optional[bytes], bytes]:
    """Decode one frame from the beginning of *data*.

    Returns (payload, remaining) or (None, data) if incomplete.
    """
    if len(data) < 4:
        return None, data
    length = struct.unpack(">I", data[:4])[0]
    if len(data) < 4 + length:
        return None, data
    return data[4 : 4 + length], data[4 + length :]


# ---------------------------------------------------------------------------
#  Protocol helpers
# ---------------------------------------------------------------------------

def _make_request(variant: str, value=None) -> bytes:
    """Serialise a Request enum the same way serde_json does for Rust enums."""
    if value is None:
        obj = variant          # unit variant: "Ping"
    else:
        obj = {variant: value}  # newtype variant: {"Data": [...]}
    return json.dumps(obj).encode("utf-8")


# ---------------------------------------------------------------------------
#  ASN.1 / OID utilities  (zero-dependency fallback)
# ---------------------------------------------------------------------------

def _encode_oid_bytes(components: list[int]) -> bytes:
    """DER-encode an OID's content bytes (without tag+length)."""
    result = bytearray()
    result.append(40 * components[0] + components[1])
    for c in components[2:]:
        if c < 128:
            result.append(c)
        else:
            parts: list[int] = []
            val = c
            while val > 0:
                parts.append(val & 0x7F)
                val >>= 7
            parts.reverse()
            for i, p in enumerate(parts):
                result.append(p | 0x80 if i < len(parts) - 1 else p)
    return bytes(result)


def _decode_asn1_length(data: bytes, offset: int) -> tuple[Optional[int], int]:
    if offset >= len(data):
        return None, 0
    first = data[offset]
    if first < 0x80:
        return first, 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        return None, 0
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, 1 + num_bytes


def _try_extract_octet_string(data: bytes, offset: int) -> Optional[bytes]:
    for i in range(offset, min(offset + 20, len(data))):
        if data[i] == 0x04:
            length, consumed = _decode_asn1_length(data, i + 1)
            if length and (i + 1 + consumed + length) <= len(data):
                start = i + 1 + consumed
                return data[start : start + length]
    return None


# ---------------------------------------------------------------------------
#  Certificate inspection
# ---------------------------------------------------------------------------

def inspect_der_certificate(der_bytes: bytes) -> CertInfo:
    """Inspect a DER-encoded X.509 certificate for RA-TLS extensions."""
    # Try the rich path first
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import serialization
        cert = cx509.load_der_x509_certificate(der_bytes)
        return _inspect_crypto(cert)
    except ImportError:
        pass
    return _inspect_manual(der_bytes)


def _inspect_crypto(cert) -> CertInfo:
    from cryptography.hazmat.primitives import serialization

    pub_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    info = CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=cert.serial_number,
        not_before=str(cert.not_valid_before_utc),
        not_after=str(cert.not_valid_after_utc),
        sig_algo=cert.signature_algorithm_oid.dotted_string,
        pubkey_sha256=hashlib.sha256(pub_der).hexdigest(),
    )

    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        info.extensions.append(oid)
        if oid in RATLS_OIDS:
            try:
                raw_value = ext.value.value
            except AttributeError:
                raw_value = ext.value.public_bytes()
            info.quote = _parse_quote(oid, ext.critical, raw_value)
        elif oid in PRIVASYS_OIDS:
            try:
                raw_value = ext.value.value
            except AttributeError:
                raw_value = ext.value.public_bytes()
            info.custom_oids.append(OidExtension(
                oid=oid,
                label=PRIVASYS_OIDS[oid],
                value=raw_value,
            ))

    return info


def _inspect_manual(der_bytes: bytes) -> CertInfo:
    info = CertInfo()
    oid_map = {
        "SGX Quote": (_encode_oid_bytes([1, 2, 840, 113741, 1, 13, 1, 0]),
                      "1.2.840.113741.1.13.1.0"),
        "TDX Quote": (_encode_oid_bytes([1, 2, 840, 113741, 1, 5, 5, 1, 6]),
                      "1.2.840.113741.1.5.5.1.6"),
    }
    for _label, (oid_bytes, oid_str) in oid_map.items():
        idx = der_bytes.find(oid_bytes)
        if idx >= 0:
            after = idx + len(oid_bytes)
            raw = _try_extract_octet_string(der_bytes, after)
            if raw:
                info.quote = _parse_quote(oid_str, False, raw)
    return info


def _parse_quote(oid: str, critical: bool, raw: bytes) -> QuoteInfo:
    label = RATLS_OIDS.get(oid, "Unknown")
    q = QuoteInfo(oid=oid, label=label, critical=critical, raw=raw)

    if raw[:11] == b"MOCK_QUOTE:":
        q.is_mock = True
        q.report_data = raw[11:75] if len(raw) >= 75 else raw[11:]
    elif label == "SGX Quote" and len(raw) >= 4:
        q.version = int.from_bytes(raw[0:2], "little")
        if len(raw) >= 432:
            q.report_data = raw[368:432]
    elif label == "TDX Quote" and len(raw) >= 4:
        q.version = int.from_bytes(raw[0:2], "little")
        if len(raw) >= TDX_QUOTE_MIN_SIZE:
            q.report_data = raw[TDX_QUOTE_REPORT_DATA]

    return q


# ---------------------------------------------------------------------------
#  RA-TLS verification types
# ---------------------------------------------------------------------------

from enum import Enum, auto


class TeeType(Enum):
    SGX = auto()
    TDX = auto()


class ReportDataMode(Enum):
    SKIP = auto()
    DETERMINISTIC = auto()
    CHALLENGE_RESPONSE = auto()


@dataclass
class ExpectedOid:
    oid: str
    expected_value: bytes


# ---------------------------------------------------------------------------
#  DCAP / QVL quote verification types
# ---------------------------------------------------------------------------

class QuoteVerificationStatus(Enum):
    """TCB status from the DCAP / QVL verification service."""
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
        for member in cls:
            if member.value == s:
                return member
        return cls.UNRECOGNIZED


@dataclass
class QuoteVerificationConfig:
    """Configuration for DCAP / QVL quote verification via an HTTP service.

    For SGX enclaves, point *endpoint* at a DCAP Quote Verification Service
    (QVS / PCCS). For TDX VMs, use a service wrapping the Intel Quote
    Verification Library (QVL).
    """
    endpoint: str
    api_key: Optional[str] = None
    accepted_statuses: list[QuoteVerificationStatus] = field(default_factory=list)
    timeout_secs: int = 10


@dataclass
class QuoteVerificationResult:
    """Result of DCAP / QVL quote verification."""
    status: QuoteVerificationStatus
    tcb_date: Optional[str] = None
    advisory_ids: list[str] = field(default_factory=list)


@dataclass
class VerificationPolicy:
    """RA-TLS verification policy."""
    tee: TeeType
    mr_enclave: Optional[bytes] = None
    mr_signer: Optional[bytes] = None
    mr_td: Optional[bytes] = None
    report_data: ReportDataMode = ReportDataMode.SKIP
    nonce: Optional[bytes] = None
    expected_oids: list[ExpectedOid] = field(default_factory=list)
    quote_verification: Optional[QuoteVerificationConfig] = None


# ---------------------------------------------------------------------------
#  RA-TLS verification
# ---------------------------------------------------------------------------

def verify_ratls_cert(der_bytes: bytes, policy: VerificationPolicy) -> CertInfo:
    """Verify an RA-TLS certificate against a policy.

    Returns the CertInfo on success.
    Raises ValueError on any verification failure.
    """
    info = inspect_der_certificate(der_bytes)

    # 1. Quote must be present
    if info.quote is None:
        raise ValueError("no RA-TLS attestation quote in certificate")
    if info.quote.is_mock:
        raise ValueError("certificate contains a MOCK quote")

    # 2. Correct TEE type
    if policy.tee == TeeType.SGX:
        if info.quote.oid != "1.2.840.113741.1.13.1.0":
            raise ValueError(
                f"expected SGX quote (1.2.840.113741.1.13.1.0), "
                f"found {info.quote.oid}"
            )
    elif policy.tee == TeeType.TDX:
        if info.quote.oid != "1.2.840.113741.1.5.5.1.6":
            raise ValueError(
                f"expected TDX quote (1.2.840.113741.1.5.5.1.6), "
                f"found {info.quote.oid}"
            )

    # 3. Measurement registers
    _verify_measurements(info.quote.raw, policy)

    # 4. ReportData
    _verify_report_data(der_bytes, info.quote.raw, policy)

    # 5. Custom OID values
    _verify_expected_oids(info.custom_oids, policy.expected_oids)

    # 6. DCAP / QVL quote verification
    if policy.quote_verification is not None:
        info.quote_verification = _verify_quote(
            info.quote.raw, policy.quote_verification
        )

    return info


def _verify_measurements(raw: bytes, policy: VerificationPolicy):
    if policy.tee == TeeType.SGX:
        if len(raw) < SGX_QUOTE_MIN_SIZE:
            raise ValueError(
                f"SGX quote too small: {len(raw)} < {SGX_QUOTE_MIN_SIZE}"
            )
        if policy.mr_enclave is not None:
            actual = raw[SGX_QUOTE_MRENCLAVE]
            if actual != policy.mr_enclave:
                raise ValueError(
                    f"MRENCLAVE mismatch: got {actual.hex()}, "
                    f"expected {policy.mr_enclave.hex()}"
                )
        if policy.mr_signer is not None:
            actual = raw[SGX_QUOTE_MRSIGNER]
            if actual != policy.mr_signer:
                raise ValueError(
                    f"MRSIGNER mismatch: got {actual.hex()}, "
                    f"expected {policy.mr_signer.hex()}"
                )
    elif policy.tee == TeeType.TDX:
        if len(raw) < TDX_QUOTE_MIN_SIZE:
            raise ValueError(
                f"TDX quote too small: {len(raw)} < {TDX_QUOTE_MIN_SIZE}"
            )
        if policy.mr_td is not None:
            actual = raw[TDX_QUOTE_MRTD]
            if actual != policy.mr_td:
                raise ValueError(
                    f"MRTD mismatch: got {actual.hex()}, "
                    f"expected {policy.mr_td.hex()}"
                )


def _verify_report_data(der_bytes: bytes, raw: bytes, policy: VerificationPolicy):
    if policy.report_data == ReportDataMode.SKIP:
        return

    if policy.report_data == ReportDataMode.DETERMINISTIC:
        if policy.tee == TeeType.SGX:
            # Deterministic mode not applicable for SGX.
            return
        # TDX: binding is NotBefore as "YYYY-MM-DDTHH:MMZ"
        binding = _get_not_before_binding(der_bytes)
    elif policy.report_data == ReportDataMode.CHALLENGE_RESPONSE:
        if policy.nonce is None:
            raise ValueError("ChallengeResponse mode requires a nonce")
        binding = policy.nonce
    else:
        return

    # Build pubkey input
    pubkey_input = _get_pubkey_input(der_bytes, policy.tee)
    expected = _compute_report_data_hash(pubkey_input, binding)

    # Get actual ReportData
    if policy.tee == TeeType.SGX:
        if len(raw) < SGX_QUOTE_REPORT_DATA.stop:
            raise ValueError("quote too small to contain ReportData")
        actual = raw[SGX_QUOTE_REPORT_DATA]
    else:
        if len(raw) < TDX_QUOTE_REPORT_DATA.stop:
            raise ValueError("quote too small to contain ReportData")
        actual = raw[TDX_QUOTE_REPORT_DATA]

    if actual != expected:
        raise ValueError(
            f"ReportData mismatch:\n"
            f"  got:      {actual.hex()}\n"
            f"  expected: {expected.hex()}"
        )


def _verify_expected_oids(
    actual: list[OidExtension],
    expected: list[ExpectedOid],
):
    actual_map = {e.oid: e.value for e in actual}
    for exp in expected:
        if exp.oid not in actual_map:
            label = ALL_OIDS.get(exp.oid, "Unknown")
            raise ValueError(
                f"expected OID {exp.oid} ({label}) not found in certificate"
            )
        if actual_map[exp.oid] != exp.expected_value:
            label = ALL_OIDS.get(exp.oid, "Unknown")
            raise ValueError(
                f"{label} ({exp.oid}) mismatch: "
                f"got {actual_map[exp.oid].hex()}, "
                f"expected {exp.expected_value.hex()}"
            )


def _verify_quote(
    quote_raw: bytes,
    config: QuoteVerificationConfig,
) -> QuoteVerificationResult:
    """Verify the raw quote against a DCAP / QVL verification service."""
    body = json.dumps({"quote": b64encode(quote_raw).decode("ascii")}).encode("utf-8")

    req = urllib.request.Request(
        config.endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if config.api_key:
        req.add_header("Authorization", f"Bearer {config.api_key}")

    try:
        with urllib.request.urlopen(req, timeout=config.timeout_secs) as resp:
            resp_body = json.loads(resp.read())
    except Exception as exc:
        raise ValueError(f"DCAP verification request failed: {exc}") from exc

    status = QuoteVerificationStatus.from_str(resp_body.get("status", ""))
    tcb_date = resp_body.get("tcbDate")
    advisory_ids = resp_body.get("advisoryIds", [])

    result = QuoteVerificationResult(
        status=status,
        tcb_date=tcb_date,
        advisory_ids=advisory_ids,
    )

    if result.status != QuoteVerificationStatus.OK:
        if result.status not in config.accepted_statuses:
            raise ValueError(
                f"DCAP quote verification failed: status={result.status.value}, "
                f"advisories={result.advisory_ids}"
            )

    return result


def _get_not_before_binding(der_bytes: bytes) -> bytes:
    """Extract NotBefore from certificate as 'YYYY-MM-DDTHH:MMZ' bytes."""
    try:
        from cryptography import x509 as cx509
        cert = cx509.load_der_x509_certificate(der_bytes)
        nb = cert.not_valid_before_utc
        return f"{nb.year:04d}-{nb.month:02d}-{nb.day:02d}T{nb.hour:02d}:{nb.minute:02d}Z".encode()
    except ImportError:
        raise ValueError("'cryptography' package required for deterministic ReportData verification")


def _get_pubkey_input(der_bytes: bytes, tee: TeeType) -> bytes:
    """Extract the public key bytes for ReportData computation."""
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import serialization
        cert = cx509.load_der_x509_certificate(der_bytes)
        spki_der = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if tee == TeeType.SGX:
            # SGX: raw EC point (last 65 bytes of SPKI)
            return spki_der[-65:] if len(spki_der) >= 65 else spki_der
        else:
            # TDX: full SPKI DER
            return spki_der
    except ImportError:
        raise ValueError("'cryptography' package required for ReportData verification")


def _compute_report_data_hash(pubkey_input: bytes, binding: bytes) -> bytes:
    """Compute SHA-512( SHA-256(pubkey) || binding )."""
    pk_hash = hashlib.sha256(pubkey_input).digest()
    return hashlib.sha512(pk_hash + binding).digest()


# ---------------------------------------------------------------------------
#  RA-TLS Client
# ---------------------------------------------------------------------------

class RaTlsClient:
    """Context-manager client for enclave-os-mini RA-TLS servers.

    Parameters
    ----------
    host : str
        Server hostname or IP.
    port : int
        Server port (default 443).
    ca_cert : str | None
        Path to a PEM CA certificate for chain verification.
        If *None*, verification is disabled (self-signed / dev mode).
    timeout : float
        Socket timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        port: int = 443,
        ca_cert: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.host = host
        self.port = port
        self.ca_cert = ca_cert
        self.timeout = timeout
        self._raw: Optional[socket.socket] = None
        self._tls: Optional[ssl.SSLSocket] = None

    # -- Context manager ---------------------------------------------------

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- Lifecycle ---------------------------------------------------------

    def connect(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.ca_cert:
            ctx.load_verify_locations(self.ca_cert)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False  # RA-TLS certs use CN, not SAN
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        self._raw = socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        )
        self._tls = ctx.wrap_socket(self._raw, server_hostname=self.host)

    def close(self):
        if self._tls:
            try:
                self._tls.close()
            except Exception:
                pass
        self._tls = None
        self._raw = None

    # -- Certificate -------------------------------------------------------

    @property
    def tls_version(self) -> str:
        return self._tls.version() if self._tls else ""

    @property
    def cipher(self) -> tuple:
        return self._tls.cipher() if self._tls else ("", "", 0)

    def inspect_certificate(self) -> CertInfo:
        """Retrieve and inspect the server's RA-TLS certificate."""
        assert self._tls, "Not connected"
        der = self._tls.getpeercert(binary_form=True)
        if not der:
            return CertInfo()
        return inspect_der_certificate(der)

    def verify_certificate(self, policy: VerificationPolicy) -> CertInfo:
        """Verify the server's RA-TLS certificate against a policy.

        Returns CertInfo on success, raises ValueError on failure.
        """
        assert self._tls, "Not connected"
        der = self._tls.getpeercert(binary_form=True)
        if not der:
            raise ValueError("no peer certificate")
        return verify_ratls_cert(der, policy)

    # -- Protocol ----------------------------------------------------------

    def _send_frame(self, payload: bytes):
        assert self._tls
        self._tls.sendall(encode_frame(payload))

    def _recv_frame(self) -> bytes:
        assert self._tls
        buf = b""
        while True:
            chunk = self._tls.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed before frame received")
            buf += chunk
            payload, _ = decode_frame(buf)
            if payload is not None:
                return payload

    def ping(self) -> bool:
        """Send Ping and expect Pong."""
        self._send_frame(_make_request("Ping"))
        resp = json.loads(self._recv_frame())
        return resp == "Pong"

    def send_data(self, data: bytes) -> bytes:
        """Send Data(payload) and return the response bytes."""
        self._send_frame(_make_request("Data", list(data)))
        resp = json.loads(self._recv_frame())
        if "Data" in resp:
            return bytes(resp["Data"])
        if "Error" in resp:
            raise RuntimeError(bytes(resp["Error"]).decode("utf-8", errors="replace"))
        raise RuntimeError(f"Unexpected response: {resp}")


# ---------------------------------------------------------------------------
#  Pretty-print helpers
# ---------------------------------------------------------------------------

def print_cert_info(info: CertInfo):
    """Human-friendly output of certificate + quote info."""
    print(f"  Subject      : {info.subject}")
    print(f"  Issuer       : {info.issuer}")
    print(f"  Serial       : {info.serial}")
    print(f"  Not Before   : {info.not_before}")
    print(f"  Not After    : {info.not_after}")
    print(f"  Sig Algo     : {info.sig_algo}")
    print(f"  PubKey SHA256: {info.pubkey_sha256}")

    if info.quote:
        q = info.quote
        print(f"\n  ** RA-TLS Extension found! **")
        print(f"    OID       : {q.oid}  ({q.label})")
        print(f"    Critical  : {q.critical}")
        print(f"    Size      : {len(q.raw)} bytes")
        if q.is_mock:
            print(f"    ** MOCK QUOTE ** (no real hardware attestation)")
        if q.version is not None:
            print(f"    Version   : {q.version}")
        if q.report_data:
            print(f"    ReportData: {q.report_data.hex()}")

        # Display measurement registers
        if q.oid == "1.2.840.113741.1.13.1.0" and len(q.raw) >= SGX_QUOTE_MIN_SIZE:
            print(f"    MRENCLAVE : {q.raw[SGX_QUOTE_MRENCLAVE].hex()}")
            print(f"    MRSIGNER  : {q.raw[SGX_QUOTE_MRSIGNER].hex()}")
        elif q.oid == "1.2.840.113741.1.5.5.1.6" and len(q.raw) >= TDX_QUOTE_MIN_SIZE:
            print(f"    MRTD      : {q.raw[TDX_QUOTE_MRTD].hex()}")

        print(f"    Preview   : {q.raw[:32].hex()}...")
    else:
        print(f"\n  No RA-TLS extension found.")
        if info.extensions:
            print(f"  Extensions  : {', '.join(info.extensions)}")

    if info.custom_oids:
        print(f"\n  ** Privasys Configuration OIDs **")
        for ext in info.custom_oids:
            print(f"    {ext.label} ({ext.oid}): {ext.value.hex()}")

    if info.quote_verification is not None:
        qv = info.quote_verification
        print(f"\n  ** DCAP Quote Verification **")
        print(f"    Status    : {qv.status.value}")
        if qv.tcb_date:
            print(f"    TCB Date  : {qv.tcb_date}")
        if qv.advisory_ids:
            print(f"    Advisories: {', '.join(qv.advisory_ids)}")
