
![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)

# Remote Attestation TLS Clients

This repository provides multi-language client utilities for connecting to Remote Attestation TLS (RA-TLS) servers. Supported languages: **Python**, **Go**, **Rust**, **TypeScript**, and **C# (.NET)**. Each client demonstrates how to verify attested TLS connections using RA-TLS certificates.

Read more about RA-TLS in our [blog post](https://privasys.org/blog/a-practical-guide-for-an-attested-web/) and the [IETF RATS working group](https://datatracker.ietf.org/wg/rats/about/).



> **Test Certificates:**
> Instructions for creating development CA and certificates are provided in [tests/certificates/README.md](tests/certificates/README.md).
> The client examples below use certificates from this directory.


## What is RA-TLS?

Confidential Computing promises that data stays encrypted even while being processed, shielded from the cloud provider, the host OS, and the hypervisor. But there is an unsolved UX problem: **how does a remote client know it's actually talking to a genuine TEE?**

RA-TLS answers it by tying hardware attestation evidence to the TLS key the client is talking to. The Privasys design (version 2, specified in [docs/ratls-v2.md](docs/ratls-v2.md)) keeps the TLS handshake completely standard and moves the evidence to a small exchange that runs on the connection right after it:

1. The TEE generates a key pair and gets a certificate for it from the Privasys intermediate CA. The certificate carries the runtime and workload identity as X.509 extensions (the OID scheme in [docs/oids.md](docs/oids.md)) and no evidence.
2. The client completes a normal TLS 1.3 handshake and checks the chain.
3. The client asks for evidence on the connection (`POST /__privasys/attest`, or a length-framed message on raw servers). The TEE answers with a quote whose `report_data` commits to the certificate's public key and, in challenge mode, to this very connection.
4. The client verifies the quote with the attestation service and re-derives `report_data` from the certificate and the connection before it sends any application data.

The result is a **normal HTTPS connection** from the client's perspective: the chain verifies with the Privasys CA, no TLS library needs patching, and the evidence rides on the same connection for any verifier that wants it.

### Why This Matters

- **No modified TLS stacks.** The handshake is unchanged, so the SDKs build on upstream TLS libraries (rustls, Go `crypto/tls`, Node `tls`, Python `ssl` or pyOpenSSL, .NET `SslStream` or Bouncy Castle).
- **Composable with existing PKI.** The certificate chains to the Privasys intermediate CA, and can chain into your organisation's own hierarchy.
- **Cryptographic binding.** The quote's `report_data` contains a hash of the public key, so the attestation is inseparable from the TLS key.
- **Session binding when you need it.** In challenge mode the quote also commits to a TLS exporter value of this connection, so a quote relayed from another session cannot pass.
- **Verifiable by anyone.** A relying party checks the chain, obtains the evidence, verifies it against the vendor's attestation infrastructure, and re-derives `report_data` from the certificate to confirm the binding.


## Attestation modes

Every SDK takes an attestation mode when it connects:

**Deterministic** binds the quote to the certificate's public key and the minute the quote was produced: `report_data = SHA-512( SHA-256(SPKI_DER) || quote_time )`, where `SPKI_DER` is the DER-encoded `SubjectPublicKeyInfo` of the leaf public key (the structure whose SHA-256 appears as "Public Key SHA-256" in certificate viewers) and `quote_time` is carried in the evidence response as `"2006-01-02T15:04Z"`. The TEE caches the quote and refreshes it on a schedule, so the mode is cheap and reproducible by any verifier. It proves the key lives in the TEE and that the quote is recent; it does not bind the quote to a particular connection.

**Challenge** (the default in Rust, Go and TypeScript) sends a fresh 32-byte context and expects `report_data = SHA-512( SHA-256(SPKI_DER) || context || hctx )`, where `hctx` is the RFC 8446 TLS exporter of this connection with the label `EXPORTER-privasys-ratls-attest-v2` and the context as exporter context. Both ends derive `hctx` from the key schedule and never send it, so the quote is bound to the connection. The server side of this binding was checked with a ProVerif model, see [Privasys/security](https://github.com/Privasys/security).

**None** completes the handshake and chain check only. It is for callers that verify evidence out of band.

When GPU evidence accompanies the quote (confidential AI workloads), `SHA-256(gpu_evidence)` is appended to the input of `report_data` in both modes. The mutual direction works the same way: a server that requires an attested client answers `client_evidence: required`, and the client presents a quote for its own certificate bound to the connection with the label `EXPORTER-privasys-ratls-attest-v2-client`.

> Python's `ssl` module and .NET's `SslStream` expose no TLS exporter, so on those standard-library transports the two clients use **deterministic** mode; they verify the same certificate, chain and quote and only lack the per-connection binding. Each SDK has a second transport that exposes the exporter and makes challenge mode, re-attestation bound to the connection and the mutual leg available: Python uses [pyOpenSSL](https://www.pyopenssl.org/) automatically when it is installed (`pip install pyopenssl`), and .NET has the `Privasys.RaTls.BouncyCastle` project on [Bouncy Castle](https://www.bouncycastle.org/csharp/) (`options.UseBouncyCastle()`). Both then default to challenge mode.

Each verified connection is tagged `X-Privasys-Attestation: none|deterministic|challenge` so a caller or a log can tell which mode produced the verdict.

The chain check follows the mode. An attested connection must chain to the Privasys fleet anchors (or a CA you supply); a valid public-PKI certificate for the same name cannot stand in. A connection that asks for no evidence (`none`) is an ordinary TLS connection as far as the chain is concerned, so a host that is not an enclave (the identity provider, for instance) verifies against the public PKI with the usual hostname check. Every SDK exposes a `trust` option: `auto` (the default described here), `fleet`, or `public` (refused with an attested mode).

### Platform allow-list

A quote that verifies proves that a genuine TEE with the reported measurements signed it, not which machine it came from: evidence from any platform whose attestation key has not been revoked passes. A relying party that knows which machines it operates pins them with `AllowedPlatformIDs` on the verification policy (`allowed_platform_ids`, `allowedPlatformIds`, `AllowedPlatformIds` in the other SDKs): hex identifiers, case and separators ignored. The identity is read by the attestation server from the verified evidence and reported in its response: for Intel SGX and TDX the PCK certificate's Platform Instance ID (SGX extension `1.2.840.113741.1.13.1.6`, present on certificates issued by the PCK Platform CA), else its PPID; for AMD SEV-SNP the report's CHIP_ID. The list travels with the verify request, so the server enforces it too (`PLATFORM_NOT_ALLOWED`), and every SDK checks the reported identity itself. A non-empty list needs quote verification and fails closed against a server that reports no identity. The server also checks every PCK chain against Intel's CRLs, so a revoked platform never passes. Intel's Platform Ownership Endorsements will replace the list once a distribution channel exists. Details in [docs/platform-allow-list.md](docs/platform-allow-list.md).

### What the CLI Verifies

The Go CLI performs four verification steps on every connection:

1. **Certificate chain** — validates the server certificate against the Privasys intermediate CA (or a CA you supply).
2. **Evidence exchange** — obtains the quote on the connection in the requested mode.
3. **`report_data` binding** — recomputes the mode's `report_data` from the certificate (and the connection, in challenge mode) and confirms it matches the quote. This proves the TLS key was generated inside the TEE.
4. **Quote verification** — sends the raw quote to a remote attestation verification service that checks the cryptographic signature and certificate chain, and checks `quote_time` against the clock.

### SGX Format Detection

Both the Rust and Go clients automatically detect whether an SGX attestation blob is a **DCAP Quote v3** (with 48-byte `QuoteHeader`) or a **raw SGX Report** (from `sgx_create_report`, no header). This is determined by checking the first two bytes: DCAP Quote v3 starts with version `3` (LE), while raw Reports start with `CPUSVN[16]` which never decodes to `3`.

### Challenge Test Binary

Both Rust and Go include a `test_challenge` binary for integration testing:

```bash
# Rust
cd rust && cargo run --release --bin test_challenge -- <host> <port>

# Go
cd go && go build -o test_challenge ./cmd/test_challenge
./test_challenge <host> <port>
```

The binary connects in challenge mode, verifies the server's `report_data` against the certificate and the connection's exporter value, and sends a Ping.

### Test vectors

`tests/vectors/ratls-v2/` holds the `report_data`, message and exporter vectors every SDK checks in its test suite.


## How to Use

### CLI (Go)

The repository ships a Go CLI that connects, inspects the RA-TLS certificate, and verifies the quote.

#### Build

```bash
cd go

# Linux / macOS
go build -o ratls-cli .

# Windows
go build -o ratls-cli.exe .
```

Then run it directly:

```bash
./ratls-cli            # interactive mode
./ratls-cli --help     # non-interactive
```

#### Interactive mode

Run with no flags and the CLI prompts for each setting. Press Enter to accept the default:

```
$ cd go && go run .
--- RA-TLS Client Configuration ---
Press Enter to accept the default value shown in brackets.

  Host [machine-id.privasys.org]:
  Port [443]:
  CA certificate path (empty to skip) [../tests/certificates/privasys.root-ca.dev.crt]:
  Attestation server URL (empty to skip) [https://as.privasys.org]:
  Attestation server bearer token []:
```

#### Non-interactive mode

Pass any flag to skip the prompts entirely:

```bash
go run . --host 10.0.0.5 --port 443
go run . --help
```

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `machine-id.privasys.org` | Server host |
| `--port` | `443` | Server port |
| `--ca-cert` | `../tests/certificates/privasys.root-ca.dev.crt` | PEM CA certificate (empty to skip) |
| `--attestation-server-url` | `https://as.privasys.org` | Attestation verification endpoint (empty to skip) |
| `--attestation-server-bearer-token` | *(empty)* | Bearer token for attestation server |

### Client Libraries

Each language directory contains a standalone RA-TLS client library (no CLI, no framework dependency):

| Language | File | Import |
|----------|------|--------|
| Go | `go/ratls/client.go` | `enclave-os-mini/clients/go/ratls` |
| Rust | `rust/src/ratls_client.rs` | `ratls_client` (library crate) |
| Python | `python/ratls_client.py` | `from ratls_client import ...` (challenge mode and the mutual leg with `pip install pyopenssl`) |
| TypeScript | `typescript/ratls_client.ts` | `import { ... } from "./ratls_client.ts"` (Node 22.6+ type stripping) |
| C# (.NET) | `dotnet/RaTlsClient.cs` | `using Privasys.RaTls;` |
| C# (.NET), Bouncy Castle transport | `dotnet/BouncyCastle/` | `using Privasys.RaTls.BouncyCastle;` then `options.UseBouncyCastle()` (challenge mode and the mutual leg) |

Each library provides:
- TLS connection with optional CA certificate verification
- RA-TLS certificate inspection (SGX / TDX quote extraction, OID verification)
- Remote quote verification via HTTP
- Length-delimited framing and typed request/response helpers

### Vault Client Libraries

The vault client builds on top of the RA-TLS transport to provide a high-level
interface for storing and retrieving secrets across multiple vault instances
running inside SGX enclaves or TDX VMs.

`GetSecret` uses **mutual RA-TLS**: the client presents its own RA-TLS
certificate during the TLS handshake so the vault can extract attestation
evidence directly from the peer cert's X.509 extensions.  No attestation
data is sent in the JSON request body.

| Language | Directory | Import |
|----------|-----------|--------|
| Go | `go/vault/` | `enclave-os-mini/clients/go/vault` |
| Rust | `rust/vault/` | `vault_client` (library crate) |

#### Architecture

```
 ┌──────────────┐       RA-TLS         ┌─────────────┐
 │              │──── share 1 ────────►│  Vault #1   │
 │  VaultClient │──── share 2 ────────►│  Vault #2   │
 │  (Shamir)    │──── share 3 ────────►│  Vault #3   │
 │              │       ...            │    ...      │
 │              │──── share M ────────►│  Vault #M   │
 └──────────────┘                      └─────────────┘

 Reconstruction: any N-of-M shares → original secret
```

The client uses **Shamir Secret Sharing** over GF(2^8) to split each secret
into M shares (one per vault endpoint) such that any N shares (the threshold)
can reconstruct the original, but fewer than N reveal nothing. This provides
both **redundancy** (any N-of-M vaults can serve a read) and **confidentiality**
(no single vault holds the full secret).

#### Operations

| Operation | Authentication | Description |
|-----------|----------------|-------------|
| **StoreSecret** | ES256 JWT | Shamir-splits the secret and distributes one share to each vault endpoint. |
| **GetSecret** | Mutual RA-TLS + optional manager JWT | Collects N shares from vault endpoints via mutual RA-TLS and reconstructs the original secret. Attestation evidence is extracted from the client's RA-TLS certificate by the vault. |
| **DeleteSecret** | ES256 JWT | Removes the secret from all vault endpoints. |
| **UpdatePolicy** | ES256 JWT | Updates the access policy on all vault endpoints. |

#### Access Policies

Each secret has an access policy that controls who can retrieve it:

| Field | Description |
|-------|-------------|
| `allowed_mrenclave` | List of permitted SGX MRENCLAVE measurements (hex). |
| `allowed_mrtd` | List of permitted TDX MRTD measurements (hex). |
| `manager_pubkey` | Hex-encoded uncompressed P-256 public key of the manager. When set, `GetSecret` requires a bearer token (ES256 JWT signed by the manager). |
| `required_oids` | OID/value pairs the caller's RA-TLS certificate must contain. |
| `ttl_seconds` | Secret time-to-live (max 90 days, default 30 days). |

The **manager** is a separate actor whose only role is to issue bearer tokens at
secret-fetch time as defence-in-depth. Even if remote attestation is compromised,
the attacker still needs the manager to sign a fresh JWT for the specific secret.
The manager cannot read, write, delete, or modify policies.

#### Shamir Secret Sharing

Both implementations use identical parameters:

- **Field:** GF(2^8) with irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x11b, same as AES)
- **Generator:** g = 3
- **Share format:** `[x_byte, data...]` where `x` is the evaluation point (1–255)
- **Constraints:** threshold ≥ 2, num_shares ≥ threshold, num_shares ≤ 255

#### Go Example

```go
import (
	"crypto/tls"
	"enclave-os-mini/clients/go/vault"
)

client, err := vault.NewVaultClient(vault.VaultConfig{
    Endpoints: []vault.Endpoint{
        {Host: "vault1.example.com", Port: 443},
        {Host: "vault2.example.com", Port: 443},
        {Host: "vault3.example.com", Port: 443},
    },
    Threshold:      2,
    SigningKeyPKCS8: signingKeyBytes,
    CACertPEM:      "vault-ca.pem",
    // Mutual RA-TLS: the client's own RA-TLS certificate for GetSecret.
    // The vault extracts attestation evidence from this cert.
    ClientCert:     &myRaTlsCert,  // *tls.Certificate
})

// Store a secret (Shamir-split across 3 vaults, threshold 2)
policy := vault.SecretPolicy{
    AllowedMrenclave: []string{"abcd1234..."},
    TTLSeconds:       86400 * 7, // 7 days
}
results, err := client.StoreSecret("my-dek", secretBytes, policy)

// Retrieve via mutual RA-TLS (any 2 vaults suffice)
secret, err := client.GetSecret("my-dek", nil)
```

#### Rust Example

```rust
use vault_client::client::{VaultClient, VaultClientConfig, VaultEndpoint, SecretPolicy};

let config = VaultClientConfig {
    endpoints: vec![
        VaultEndpoint { host: "vault1.example.com".into(), port: 443 },
        VaultEndpoint { host: "vault2.example.com".into(), port: 443 },
        VaultEndpoint { host: "vault3.example.com".into(), port: 443 },
    ],
    threshold: 2,
    signing_key_pkcs8: std::fs::read("owner-key.p8").unwrap(),
    ca_cert_pem: Some("vault-ca.pem".into()),
    vault_policy: None,
    // Mutual RA-TLS: the client's own RA-TLS certificate for GetSecret.
    // The vault extracts attestation evidence from this cert.
    client_cert_der: Some(vec![my_ratls_cert_der]),
    client_key_pkcs8: Some(my_ratls_key_pkcs8),
};

let client = VaultClient::new(config).unwrap();

// Store
let policy = SecretPolicy::new()
    .allow_mrenclave("abcd1234...")
    .ttl(86400 * 7);
let results = client.store_secret("my-dek", &secret_bytes, &policy).unwrap();

// Retrieve via mutual RA-TLS
let reconstructed = client.get_secret("my-dek", None).unwrap();
```

## Third-party dependencies

The Go and TypeScript clients rely exclusively on their standard libraries. The
Python and C#/.NET clients do too by default, and each has an optional transport
on a third-party TLS stack that exposes the RFC 8446 exporter (challenge mode,
re-attestation bound to the connection, the mutual leg):

| Library | License | Usage |
|---------|---------|-------|
| [pyOpenSSL](https://github.com/pyca/pyopenssl) (optional, Python) | Apache 2.0 | TLS 1.3 client with the exporter; used automatically when installed |
| [Bouncy Castle C#](https://github.com/bcgit/bc-csharp) (optional, .NET) | MIT | TLS 1.3 client with the exporter; `Privasys.RaTls.BouncyCastle` project |

The **Rust** client has the following dependencies:

| Library | License | Usage |
|---------|---------|-------|
| [rustls](https://github.com/rustls/rustls) | Apache 2.0 / MIT / ISC | TLS 1.3 client (upstream; the exporter feeds the challenge binding) |
| [ring](https://github.com/briansmith/ring) | ISC | Cryptographic primitives |
| [x509-parser](https://github.com/rusticata/x509-parser) | Apache 2.0 / MIT | X.509 certificate parsing |
| [ureq](https://github.com/algesten/ureq) | Apache 2.0 / MIT | HTTP client for quote verification |
| [serde](https://github.com/serde-rs/serde) / serde_json | Apache 2.0 / MIT | JSON serialization |
| [base64](https://github.com/marshallpierce/rust-base64) | Apache 2.0 / MIT | Base64 encoding |
| [hex](https://github.com/KokaKiwi/rust-hex) | Apache 2.0 / MIT | Hex encoding |
| [rustls-pemfile](https://github.com/rustls/pemfile) | Apache 2.0 / MIT / ISC | PEM file parsing |

Full license texts are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).

## Contributing

Contributions are welcome! Please open issues or pull requests for bug reports, feature requests, or improvements. For security issues, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

You are free to use, modify, and distribute this software under the terms of the AGPL-3.0. Any modified versions or services built on this software that are accessible over a network **must** make the complete source code available under the same license.

### Commercial Licensing

For commercial, closed-source, or proprietary use that is not compatible with the AGPL-3.0, a separate **commercial license** is available.

Please contact **legal@privasys.org** for licensing enquiries.
