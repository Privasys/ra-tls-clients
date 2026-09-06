# Platform allow-list

Status: implemented in `ra-tls-clients` v0.11.0 and `attestation-server` v0.5.1 (identity,
allow-list and revocation).

## 1. Problem

A quote that verifies proves that a genuine TEE with the reported measurements signed it,
not which machine it came from. Evidence from any platform whose attestation key has not
been revoked passes, and measurements say what runs, not where. A relying party that knows
which machines it operates needs a way to pin them, and a platform whose key Intel has
revoked must not pass at all.

## 2. Identity

Every SGX and TDX quote embeds the platform's PCK certificate chain. Intel issues the PCK
certificate at provisioning; its SGX extension (`1.2.840.113741.1.13.1`) carries:

| OID | Field | Present on |
|-----|-------|-----------|
| `.1` | PPID, 16 bytes | every PCK certificate |
| `.4` | FMSPC, 6 bytes | every PCK certificate |
| `.6` | Platform Instance ID, 16 bytes | certificates issued by the Intel SGX PCK Platform CA (multi-package platforms) |

SEV-SNP reports carry the 64-byte `CHIP_ID`.

The identifier of record is the Platform Instance ID when present, else the PPID, else the
`CHIP_ID`. The PPID does not stand in for a Platform Instance ID that is present.

These values are bound to the signer of the quote: the quote body is signed by the
attestation key, the QE report that vouches for the attestation key is signed by the PCK
private key, and the PCK certificate chains to the Intel SGX Root CA. The attestation server
reads them from the leaf that verified the QE report signature, never from any other
certificate present in the quote, and reports them in every response:

```json
"platform": {"ppid": "...", "platformInstanceId": "...", "fmspc": "..."}
```

(`"chipId"` for SEV-SNP.)

## 3. Policy

`VerificationPolicy` carries the list: `AllowedPlatformIDs` (Go), `allowed_platform_ids`
(Rust, Python), `allowedPlatformIds` (TypeScript), `AllowedPlatformIds` (.NET). Entries are
hex; case and the separators `-`, `:` and space are ignored.

Enforcement happens twice:

1. The SDK sends the list as `allowedPlatformIds` in the verification request. The server
   refuses evidence from any other platform, or evidence whose identity cannot be read, with
   the verdict `PLATFORM_NOT_ALLOWED`.
2. Once the server has accepted the quote, the SDK reads the identity itself from the PCK
   leaf embedded in that same quote (`PlatformIdentityFromQuote` and its equivalents; the
   leaf whose key certified the quote, so its value is covered by the verification the
   server just performed), cross-checks it with the server's `platform` object, and enforces
   the list on the local value. A server report that disagrees with the quote fails the
   verification; the server's value stands alone only for evidence that carries no PEM chain.
   The relying party's decision therefore depends on the server for the quote verdict, not
   for the identity.

Rules:

- An empty list accepts any platform (the default).
- A non-empty list needs `QuoteVerification`: the identity is read from the verified
  evidence. The policy is refused before anything else is looked at otherwise.
- A non-empty list fails closed when neither the quote nor the server yields an identity.
- `QuoteVerificationResult` carries the identity fields, a `PlatformID` accessor with the
  precedence above, and `PlatformFromQuote` saying whether the SDK read it from the quote.

## 4. Revocation

The chain to the pinned Intel root says nothing about revocation. The attestation server
checks every SGX and TDX quote against Intel's CRLs: the PCK leaf against the PCK CRL of
its issuing CA (Processor or Platform), and the issuing CA against the Root CA CRL. The PCK
CRL must arrive with an issuer chain ending at the pinned root and be signed by the CA that
issued the leaf, matched by subject and key; a CRL outside its validity window is refused.
A revoked certificate, or a CRL that cannot be obtained or has expired, fails the
verification (`PCK_REVOCATION_MODE=enforce`, the default). CRLs are cached with a 24-hour
grace window through a PCS outage. The response reports `pckRevocationChecked`.

## 5. Limits

- Pinning names machines; the owner decides which machines are physically protected.
- The identifier names the host, not the VM. A cloud VM that lands on another host after a
  stop and start has a new identity, which is the point of pinning.
- The SDKs read the identity from the quote but do not verify the PCK chain themselves; the
  attestation server's quote verdict is what makes the embedded certificate the one that
  certified the quote. A relying party trusts the server for that verdict as it already does
  for the signature and TCB verdicts.
- Intel's Platform Ownership Endorsements will let a platform prove its owner directly; the
  certificate scheme reserves OID `1.4` for them. The allow-list is the interim mechanism.

## 6. Test vectors and fixtures

- Unit checks of the precedence and matching rules in every SDK.
- Fake attestation servers in the Go, Python and .NET test suites exercise the request, the
  reported identity and the refusal.
- The attestation server's tests carry a production PCK leaf (Platform CA) and run the
  identity and revocation checks against a real TDX quote when `AS_TEST_TDX_QUOTE` names one.
