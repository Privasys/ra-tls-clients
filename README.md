
![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)

# Remote Attestation TLS Clients

This repository provides multi-language client utilities for connecting to Remote Attestation TLS (RA-TLS) servers. Supported languages: **Python**, **Go**, **Rust**, **TypeScript**, and **C# (.NET)**. Each client demonstrates how to verify attested TLS connections using RA-TLS certificates.

Read more about RA-TLS in our [blog post](https://privasys.org/blog/a-practical-guide-for-an-attested-web/) and the [IETF RATS working group](https://datatracker.ietf.org/wg/rats/about/).



> **Test Certificates:**
> Instructions for creating development CA and certificates are provided in [tests/certificates/README.md](tests/certificates/README.md).
> The client examples below use certificates from this directory.


## What is RA-TLS?

Confidential Computing promises that data stays encrypted even while being processed, shielded from the cloud provider, the host OS, and the hypervisor. But there is an unsolved UX problem: **how does a remote client know it's actually talking to a genuine TEE?**

RA-TLS solves this by embedding the attestation evidence directly into a standard **X.509 certificate**. The concept, discussed in the [IETF RATS working group](https://datatracker.ietf.org/wg/rats/about/), is elegant:

1. The TEE generates a key pair.
2. It requests attestation from the hardware, binding the public key to the quote via the `ReportData` field.
3. It builds an X.509 certificate carrying the quote in a custom extension OID.
4. This certificate is served over standard TLS.

The result is a **normal HTTPS connection** from the client's perspective. Any TLS client (a browser, `curl`, a mobile app) can connect without modification. The attestation evidence rides along inside the certificate for any verifier that wants to inspect it, while clients that don't care simply see a valid TLS handshake.

### Why This Matters

- **Zero client-side changes.** No custom SDK, no attestation protocol, no out-of-band channel. HTTPS just works.
- **Composable with existing PKI.** The RA-TLS cert can be signed by a private CA, chaining into your organisation's existing trust hierarchy.
- **Cryptographic binding.** The quote's `ReportData` contains a hash of the public key, so the attestation is inseparable from the TLS session.
- **Verifiable by anyone.** A relying party extracts the quote from the certificate extension, verifies it against the vendor's attestation infrastructure, and re-derives the `ReportData` from the certificate's public key to confirm the binding.
- **Compatible with TLS 1.3.** Works with modern protocol versions, ECDSA keys, and HTTP/1-3.


## RA-TLS Challenges

RA-TLS can work in two modes:

**Deterministic attestation** binds the quote to the certificate's public key and a known time value. The verifier can reproduce the `ReportData` from the certificate alone, with no interactive protocol needed. Since certificates are renewed on a regular schedule (every 24 hours in our case), this provides a satisfactory level of trust: the quote proves the key was generated inside the TEE within the last renewal window.

**Challenge-response attestation** (per [draft-ietf-rats-tls-attestation](https://datatracker.ietf.org/doc/draft-ietf-rats-tls-attestation/)) binds the quote to a client-supplied nonce sent in the TLS ClientHello. This proves freshness at the connection level, but requires the TLS library to expose raw ClientHello extension payloads.

> **Note on challenge-response:** As of February 2026, no mainstream TLS library in Go, Python, TypeScript/Node.js, Rust, or C#/.NET provides an API to inject custom extensions into the TLS ClientHello. Challenge-response attestation therefore requires either a custom TLS implementation or a forked runtime (see the [Privasys/go fork](https://github.com/Privasys/go/tree/ratls) used by ra-tls-caddy on the server side). Until upstream support lands, the CLI and all client libraries use **deterministic verification** only.

That said, **most users will not need challenge-response attestation.** A deterministic certificate with a quote bound to a recent creation time is sufficient for the vast majority of use cases. To keep things simple and reproducible, we compute `ReportData = SHA-512( SHA-256(DER public key) || creation_time )`, where `creation_time` is the certificate's `NotBefore` truncated to 1-minute precision (`"2006-01-02T15:04Z"`). With 24-hour certificate renewal, any verifier can confirm the key was generated inside the TEE within the last day by reproducing this value from the certificate fields alone.

### What the CLI Verifies

The Go CLI performs three verification steps on every connection:

1. **Certificate chain** — validates the server certificate against the provided root CA.
2. **ReportData binding** — recomputes `SHA-512( SHA-256(DER public key) || NotBefore )` from the certificate and confirms it matches the quote's `ReportData`. This proves the TLS key was generated inside the TEE.
3. **DCAP quote verification** — sends the raw quote to a remote verification service that checks the cryptographic signature and Intel certificate chain.


## How to Use

### CLI (Go)

The repository ships a Go CLI that connects, inspects the RA-TLS certificate, and verifies the DCAP quote.

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

  Host [tdx-paris-1.dev.privasys.org]:
  Port [443]:
  CA certificate path (empty to skip) [../tests/certificates/privasys.root-ca.dev.crt]:
  DCAP verification URL (empty to skip) [https://gcp-lon-1.dcap.privasys.org/api/verify]:
  DCAP API key (JWT) [eyJ...]:
```

#### Non-interactive mode

Pass any flag to skip the prompts entirely:

```bash
go run . --host 10.0.0.5 --port 443
go run . --help
```

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `tdx-paris-1.dev.privasys.org` | Server host |
| `--port` | `443` | Server port |
| `--ca-cert` | `../tests/certificates/privasys.root-ca.dev.crt` | PEM CA certificate (empty to skip) |
| `--dcap-url` | `https://gcp-lon-1.dcap.privasys.org/api/verify` | DCAP verification endpoint (empty to skip) |
| `--dcap-key` | *(dev JWT)* | Bearer token for DCAP endpoint |

### Client Libraries

Each language directory contains a standalone RA-TLS client library (no CLI, no framework dependency):

| Language | File | Import |
|----------|------|--------|
| Go | `go/ratls/client.go` | `enclave-os-mini/clients/go/ratls` |
| Rust | `rust/src/ratls_client.rs` | `ratls_client` (library crate) |
| Python | `python/ratls_client.py` | `from ratls_client import ...` |
| TypeScript | `typescript/ratls_client.ts` | `import { ... } from "./ratls_client"` |
| C# (.NET) | `dotnet/RaTlsClient.cs` | `using EnclaveOsMini.Client;` |

Each library provides:
- TLS connection with optional CA certificate verification
- RA-TLS certificate inspection (SGX / TDX quote extraction, OID verification)
- DCAP / QVL quote verification via HTTP
- Length-delimited framing and typed request/response helpers

## Contributing

Contributions are welcome! Please open issues or pull requests for bug reports, feature requests, or improvements. For security issues, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

You are free to use, modify, and distribute this software under the terms of the AGPL-3.0. Any modified versions or services built on this software that are accessible over a network **must** make the complete source code available under the same license.

### Commercial Licensing

For commercial, closed-source, or proprietary use that is not compatible with the AGPL-3.0, a separate **commercial license** is available.

Please contact **legal@privasys.org** for licensing enquiries.
