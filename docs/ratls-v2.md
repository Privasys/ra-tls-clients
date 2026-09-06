# Privasys RA-TLS v2: evidence after the handshake

Status: normative draft, 2026-09-04. Implemented by the enclave runtimes (SGX "mini",
TDX/GPU "virtual") and by the `ra-tls-clients` SDKs from v0.9.0. Replaces v1 (evidence
inside the certificate, `0xFFBB` challenge extension, handshake-secret binder) outright:
there is no dual-shape transition, a v1 peer and a v2 peer fail closed against each other.

## 1. Summary

An RA-TLS v2 server presents an ordinary X.509 leaf certificate over an ordinary TLS 1.3
handshake. The certificate identifies the enclave: leaf key, chain to the Privasys
intermediate of its environment, and the Privasys extensions (measurement roots, app id,
instance id, configuration roots, see `oids.md`). It carries no attestation evidence.

A client that wants evidence asks for it after the handshake, on the same connection,
and before sending any application data. The server answers with a DCAP quote (and GPU
evidence when the workload has a GPU) whose `report_data` commits to the leaf key and,
in challenge mode, to a value that only the two ends of this TLS connection can derive.
A client that never asks gets a normal-sized certificate and a working connection; the
server records that connection as `attestation: none`.

Why after the handshake: the evidence can then commit to `exporter_master_secret`, which
exists only once the server Finished has been sent, so it commits to the application keys
themselves (Level 3 in the Sardar, Dubeyko, Jacquet hierarchy). This needs nothing from
the TLS stack beyond the RFC 8446 section 7.5 exporter, which upstream rustls and
upstream Go expose; the Privasys forks of both are retired with v2.

## 2. Certificate

- Leaf key: ECDSA P-256. Issued inside the enclave by the environment intermediate
  (prod or dev), chain `leaf -> Privasys Intermediate CA -> Privasys Root CA`.
- Extensions: the v2 OID set (`oids.md`). No DCAP quote, no SEV-SNP report, no GPU
  evidence in the certificate. A verifier that finds a v1 quote OID in a leaf treats the
  certificate as v1 and fails closed.
- Validity: 24 hours, renewed by the runtime. The leaf key is kept across re-mints that
  change only extension values (deploy, configuration change, dependency-set change), so
  a deterministic quote minted for the key stays valid across such a re-mint.
- SNI routing, per-workload leaves and the platform leaf for unknown SNI are unchanged
  from v1.
- ALPN: the server still offers `privasys-ratls/1` for the platform gateway, which uses
  it to splice the connection to the enclave instead of terminating it with the public
  certificate. The value has no meaning for attestation and is not bumped.

Client verification of the certificate, in the SDKs: chain to the fleet anchors
(embedded Privasys intermediates, or a caller-supplied PEM), not hostname (peers are
dialled by IP, identity is measurement plus app id), then the v2 extensions against the
caller's policy. This step is complete before the evidence request.

### 2.1 Trust anchors

The chain check is mandatory and its anchors follow the attestation mode. An attested
connection (deterministic or challenge) must chain to the Privasys fleet anchors, or to
the CA the caller supplies: the evidence proves the key, the chain proves the key was
minted for a fleet member, and a valid public-PKI certificate for the same name (a
gateway terminating TLS, or any CA) cannot stand in. A connection that asks for no
evidence (`none`) is an ordinary TLS connection as far as the chain is concerned: hosts
that are not enclaves, such as the identity provider, present public-PKI certificates and
never chain to the fleet. SDKs expose a `trust` option with three values: `auto` (the
default: fleet for attested modes; for `none`, fleet without the name check or public PKI
with the name check), `fleet`, and `public` (refused together with an attested mode).
An SDK never downgrades an attested connection to the public PKI.

## 3. Evidence exchange

The exchange is two messages, request and response, encoded as JSON. Two bindings carry
them: HTTP for HTTP workloads, and a raw frame for legs that do not speak HTTP.

### 3.1 HTTP binding

`POST /__privasys/attest` on the enclave's own HTTP surface, `Content-Type:
application/json`. The path is reserved: the runtime answers it before any workload
router sees the request, on the platform leaf and on every per-workload leaf. It is
reachable only on the spliced path; the gateway terminate path serves the public
certificate and answers `404`.

For HTTP/1.1 the client sends the request as the first request of the connection. For
HTTP/2 the client sends it on the first stream and opens no other stream until the
response has verified. One attestation covers every later request and stream on that
TLS connection.

### 3.2 Raw binding

For legs that carry a non-HTTP protocol over RA-TLS (KMIP gateway, raft peer link, and
any future binary protocol): the first application record after the handshake, in each
direction, is one frame `u32 big-endian length || JSON`, length at most 65536. The
client sends the request frame, the server answers with the response frame, then the
protocol starts. Nothing else is multiplexed before the response.

### 3.3 Request

```json
{ "v": 2, "mode": "deterministic", "leaf": "<SHA-256(SPKI_DER) of the received leaf, base64url>" }
{ "v": 2, "mode": "challenge", "leaf": "<same>", "context": "<32 bytes, base64url without padding>" }
```

`leaf` names the certificate the client received in the handshake, so the server binds
the evidence to that key even if it rotated the leaf for that name in the meantime. A
server answers only for a leaf key it holds (current or previous for the name), `404`
otherwise. `context` is fresh random per request, except that a verifier relaying a
challenge chosen elsewhere (a browser talking to the management service) may supply it
verbatim. A server rejects a challenge request whose context is not exactly 32 bytes.
All base64 in this protocol is base64url without padding.

### 3.4 Response

```json
{
  "v": 2,
  "mode": "deterministic" | "challenge",
  "tee": "sgx" | "tdx" | "tdx-gpu",
  "quote": "<DCAP quote, base64url>",
  "gpu_evidence": "<NVIDIA CC evidence bundle, base64url>" | null,
  "quote_time": "2026-09-04T10:15Z",
  "client_evidence": "none" | "required",
  "client_context": "<32 bytes, base64url>" | null
}
```

- `quote_time` is the minute at which the quote was minted, ASCII `YYYY-MM-DDTHH:MMZ`.
  It is present in both modes. In deterministic mode it is an input of `report_data`.
- `client_evidence` and `client_context` implement the mutual leg (section 5).
- Errors: HTTP `400` (malformed request), `404` (not an RA-TLS v2 endpoint, or gateway
  terminate path), `503` (quote provider unavailable). On the raw binding the response
  frame carries `{"v":2,"error":"..."}` and the server closes the connection.

### 3.5 report_data

`SPKI_DER` is the DER `SubjectPublicKeyInfo` of the leaf certificate the client
received in the handshake (91 bytes for P-256). All hashes are over raw bytes; `||` is
concatenation.

Deterministic:

```
report_data = SHA-512( SHA-256(SPKI_DER) || quote_time )
```

where `quote_time` is the 17-byte ASCII string from the response. The runtime caches
one deterministic quote per leaf key for 24 hours and serves the same `quote_time`
with it. A verifier accepts `quote_time` within the last 24 hours plus 5 minutes of
skew, and rejects a `quote_time` in the future beyond that skew.

Challenge:

```
hctx        = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2", context, 32)
report_data = SHA-512( SHA-256(SPKI_DER) || context || hctx )
```

`TLS-Exporter` is RFC 8446 section 7.5, keyed by `exporter_master_secret` of this
connection, with the request `context` as the exporter context value. Both ends compute
`hctx` independently; it never travels. The verifier computes its own `hctx` and its own
expected `report_data` and compares; it never takes either from the peer.

GPU evidence, when present (both modes):

```
report_data = SHA-512( SHA-256(SPKI_DER) || binding || SHA-256(gpu_evidence) )
```

with `binding` the deterministic or challenge binding above, i.e. the GPU fold is
applied after the binding, as in v1. The GPU evidence's own nonce is the first 32 bytes
of the TDX `report_data`, as in v1, so the two evidence bodies cross-commit.

Rationale for the challenge recipe: `exporter_master_secret` is derived from the Master
Secret and the transcript through server Finished, exactly as the application traffic
secrets are, so a quote that commits to `hctx` commits to this connection's application
keys. This is Level 3 by construction; the ProVerif result is in
`github.com/Privasys/security`, folder `attested-tls-level3`, models G and H. The
handshake already proved possession of the leaf key (CertificateVerify), so the
response carries no further signature; the RFC 9261 authenticator shape is not needed
when the attested certificate is the handshake certificate.

### 3.6 Verifier procedure

After the handshake and before any application data:

1. Certificate: chain to the fleet anchors and v2 extensions against policy (already
   done during the handshake; the SDK fails the connection there).
2. Send the request in the caller's mode. `challenge` is the default in the SDKs;
   `deterministic` is opt-in for callers that accept the "trust the TEE" tier.
3. Parse the response; reject `v != 2` or a mode different from the one requested.
4. Quote: signature and TCB through the attestation server, as in v1 (same request and
   response shape, the quote body is unchanged). Measurements against the caller's
   policy (MRENCLAVE / MRSIGNER, MRTD / RTMRs), including the runtime's measured OIDs
   in the certificate against the quote's measurements where the policy pins them.
   Platform, when the policy carries an allow-list (`AllowedPlatformIDs`): the server
   reports the hardware identity it read from the verified evidence (PCK Platform
   Instance ID, else PPID; SEV-SNP CHIP_ID) and enforces the list sent with the
   request; the SDK checks the reported identity against the list as well and fails
   closed when none is reported (docs/platform-allow-list.md). The server also checks
   the PCK chain against Intel's CRLs; a revoked platform never passes.
5. `report_data`: compute the expected value from the connection's own leaf SPKI, the
   mode, `quote_time` or the client's own `context` and `hctx`, and `gpu_evidence` when
   present; compare with the quote's `report_data`. A mismatch fails the connection.
   A verifier never accepts a `report_data` it did not predict.
6. GPU evidence, when present: verify as in v1 (NVIDIA NRAS or local verifier), check
   its nonce against the TDX `report_data` prefix.
7. Mutual leg, when `client_evidence` is `required`: section 5.
8. Only then hand the connection to the caller. Failure closes the connection with an
   error that names the step.

Re-attestation: on long-lived connections (sealed WebSockets, session relay, drive
streams, vault sessions) the client repeats the exchange every 5 minutes, default, on
the same connection, with a fresh `context`. On HTTP/2 that is a new stream; on the raw
binding a re-attestation frame is not possible, the client reconnects instead. A
failure, or a change in the pinned extension values between the handshake certificate
and the runtime's current leaf (the response's quote measurements no longer match), drops
the connection.

## 4. Connection tag

The server records, per TLS connection, `attestation: none | deterministic | challenge`,
set when a response is served and left at `none` otherwise. Caddy exposes it to the
workload as the request header `X-Privasys-Attestation`; the manager counts connections
per tag. A workload that requires attested callers checks the header, it never trusts
the caller's word.

## 5. Mutual leg (client evidence)

Used by app-to-vault, app-to-app, management-to-vault and the raft peer link, where the
server must know that the caller is a specific enclave.

- The client presents a v2 client certificate in the handshake: leaf key, chain to the
  same intermediate, v2 extensions, no evidence. The server verifies chain and
  extensions against its policy at the handshake.
- The server's attest response carries `client_evidence: "required"` and a fresh
  32-byte `client_context` when the presented client leaf carries the workload app-id
  extension (OID 1.3.6.1.4.1.65230.4.1), that is, when it claims a fleet-minted enclave
  identity. A client certificate without that extension is a bare key holder (a CLI user
  presenting a holder-of-key grant): the server answers `client_evidence: "none"`, binds
  nothing to it beyond the key it holds, and grants it no TEE principal.
- The client answers with a second request on the same connection:

```json
{ "v": 2, "mode": "present", "context": "<client_context>", "tee": "...",
  "quote": "...", "gpu_evidence": null, "quote_time": "..." }
```

  with

```
hctx_c      = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2-client", client_context, 32)
report_data = SHA-512( SHA-256(SPKI_DER_client) || client_context || hctx_c )
```

- The server verifies it exactly as a client verifies a server response (section 3.6,
  steps 4 to 6, with the client's SPKI and its own `hctx_c`), answers `204` (HTTP) or an
  empty `{"v":2}` frame (raw), and only then serves application traffic. `403` on
  failure. On the raw binding the client's `present` frame follows the server's response
  frame, and the server's acknowledgement frame precedes the protocol.
- A server that requires client evidence and receives application data before a
  verified `present` closes the connection.

Deterministic client evidence is not defined; the mutual leg is always challenge.

## 6. Deterministic mode

The "trust the TEE" tier of v1 is unchanged in what it proves: the leaf key was
generated inside an enclave with the quoted measurements within the last 24 hours. It
has no session binding by design and offers no relay resistance beyond the certificate
key. The v1 rule that the certificate `NotBefore` equals the quote minute is dropped:
`quote_time` is carried in the response, so an extension-only re-mint does not
invalidate the cached quote.

## 7. What v2 removes

- The `0xFFBB` ClientHello / CertificateRequest extension.
- The handshake-secret binder `privasys-ratls-binder-v1` and the Certificate-emit
  re-mint in both forks.
- The DCAP, SEV-SNP and GPU evidence certificate extensions; the OID plan renames the
  remaining extensions (`oids.md`).
- The forks `Privasys/rustls` and `Privasys/go`: runtimes and SDKs build on upstream.
  The forks are archived with a README pointing here.

## 8. Test vectors

`tests/vectors/ratls-v2/` holds JSON vectors generated by the Go reference
implementation and checked by the Rust, Go, TypeScript, Python and C# SDKs:

- `report_data.json`: deterministic cases (`spki_der`, `quote_time`, expected
  `report_data`) and challenge cases (`spki_der`, `context`, `hctx` given, since it
  depends on a live key schedule, expected `report_data`), with and without
  `gpu_evidence`.
- `exporter.json`: an `exporter_master_secret`, both labels, a context, and the expected
  `hctx` values, for SHA-256 and SHA-384 suites, so the exporter step is checked
  independently of a TLS stack (RFC 8446 section 7.5, 32-byte length).

Message parsing and its rejections (wrong `v`, wrong mode echo, context length, stale
`quote_time`) are covered by each SDK's own test suite against the shapes in section 3;
the rejection wording is SDK-specific.

## 9. Version and interop

- SDKs: `ra-tls-clients` v0.9.0 implements v2 only. Rust `connect`, `connect_mutual`
  and the Go `Client` take an `Attestation` mode option (`Challenge` default,
  `Deterministic`, `None`) and expose the verified `Attestation` result as before.
  From v0.10.0 the Python and .NET SDKs run challenge mode, re-attestation and the
  mutual leg too, on a second transport that exposes the exporter (pyOpenSSL, used
  automatically when installed; Bouncy Castle through `Privasys.RaTls.BouncyCastle`);
  their standard-library transports stay deterministic.
- Runtimes: `enclave-os-mini` and `enclave-os-virtual` releases tagged for v2 serve
  v2 leaves and the endpoint; the measurement roll is part of the cutover window.
- CLI: `privasys attest <host>` and every RA-TLS call in the CLI use the SDK and
  print the connection tag and the verified fields.
- Wallet: the native bridge exposes the same result shape as v1 plus the tag; users on
  a v1 wallet fail closed with "update the wallet".
