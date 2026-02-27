
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

That said, **most users will not need challenge-response attestation.** A deterministic certificate with a quote bound to a recent creation time is sufficient for the vast majority of use cases. To keep things simple and reproducible, we compute `ReportData = SHA-512( SHA-256(DER public key) || creation_time )`, where `creation_time` is the certificate's `NotBefore` truncated to 1-minute precision (`"2026-01-02T15:04Z"`). With 24-hour certificate renewal, any verifier can confirm the key was generated inside the TEE within the last day by reproducing this value from the certificate fields alone.


## How to Use the Client Libraries


All client libraries accept a `--ca-cert` flag to verify the server's certificate chain against the root CA. The test certificates are in `tests/certificates/`.

### Integration Testing

To quickly test connectivity for each client, use the provided scripts in [tests/integration](tests/integration):

- `test_python.bat`
- `test_typescript.bat`
- `test_rust.bat`
- `test_dotnet.bat`
- `test_go.bat`

Each script runs the respective client with the required parameters. Update `[yourserver].com` and `[yourname]` as needed for your environment.

### Python

```bash
cd clients/python
pip install cryptography   # optional, for cert inspection
python test_hello.py \
    --host 141.94.219.130 \
    --port 443 \
    --ca-cert ../../tests/certificates/privasys.root-ca.dev.crt
```

### TypeScript

```bash
cd clients/typescript
npm install
npx ts-node test_hello.ts \
    --host 141.94.219.130 \
    --port 443 \
    --ca-cert ../../tests/certificates/privasys.root-ca.dev.crt
```

### Rust

```bash
cd clients/rust
cargo run -- \
    --host 141.94.219.130 \
    --port 443 \
    --ca-cert ../../tests/certificates/privasys.root-ca.dev.crt
```

### C# (.NET)

```bash
dotnet run -- \
    --host 141.94.219.130 \
    --port 443 \
    --ca-cert ../../tests/certificates/privasys.root-ca.dev.crt
```

### Go

```bash
cd clients/go
go run . \
    --host 141.94.219.130 \
    --port 443 \
    --ca-cert ../../tests/certificates/privasys.root-ca.dev.crt
```

## Contributing

Contributions are welcome! Please open issues or pull requests for bug reports, feature requests, or improvements. For security issues, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).

You are free to use, modify, and distribute this software under the terms of the AGPL-3.0. Any modified versions or services built on this software that are accessible over a network **must** make the complete source code available under the same license.

### Commercial Licensing

For commercial, closed-source, or proprietary use that is not compatible with the AGPL-3.0, a separate **commercial license** is available.

Please contact **legal@privasys.org** for licensing enquiries.
