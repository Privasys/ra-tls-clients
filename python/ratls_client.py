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

    with RaTlsClient("141.94.219.130", 8443, ca_cert="ca.pem") as client:
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
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
#  RA-TLS OIDs
# ---------------------------------------------------------------------------

RATLS_OIDS: dict[str, str] = {
    "1.2.840.113741.1.13.1.0": "SGX Quote",
    "1.2.840.113741.1.5.5.1.6": "TDX Quote",
}


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

    return q


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
        Server port (default 8443).
    ca_cert : str | None
        Path to a PEM CA certificate for chain verification.
        If *None*, verification is disabled (self-signed / dev mode).
    timeout : float
        Socket timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        port: int = 8443,
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
        print(f"    Preview   : {q.raw[:32].hex()}...")
    else:
        print(f"\n  No RA-TLS extension found.")
        if info.extensions:
            print(f"  Extensions  : {', '.join(info.extensions)}")
