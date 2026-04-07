// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// RA-TLS client connector for enclave-os-mini.
//
// Provides:
//   - TLS connection with optional CA certificate verification
//   - RA-TLS certificate inspection (SGX / TDX quote extraction)
//   - Length-delimited framing (4-byte big-endian prefix)
//   - Typed request/response helpers matching the Rust protocol
//
// Dependencies: System.Net.Security, System.Security.Cryptography.X509Certificates
//               System.Text.Json (built-in with .NET 6+)
//
// Usage:
//   using var client = new RaTlsClient("141.94.219.130", 443, caCertPath: "ca.pem");
//   client.Connect();
//   var info = client.InspectCertificate();
//   byte[] resp = client.SendData("hello"u8);

using System.Formats.Asn1;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using System.Net.Http.Headers;

namespace EnclaveOsMini.Client;

// ---------------------------------------------------------------------------
//  RA-TLS OIDs
// ---------------------------------------------------------------------------

public static class RaTlsOids
{
    /// <summary>Intel SGX Quote (enclave-os-mini): 1.2.840.113741.1.13.1.0</summary>
    public const string SgxQuote = "1.2.840.113741.1.13.1.0";

    /// <summary>Intel TDX Quote (ra-tls-caddy): 1.2.840.113741.1.5.5.1.6</summary>
    public const string TdxQuote = "1.2.840.113741.1.5.5.1.6";

    /// <summary>AMD SEV-SNP Attestation Report: 1.3.6.1.4.1.65230.4.1</summary>
    public const string SevSnpReport = "1.3.6.1.4.1.65230.4.1";

    /// <summary>NVIDIA GPU Evidence: 1.3.6.1.4.1.65230.5.1</summary>
    public const string NvidiaGpuEvidence = "1.3.6.1.4.1.65230.5.1";

    // Privasys configuration OIDs

    /// <summary>Config Merkle root — proves all config inputs.</summary>
    public const string ConfigMerkleRoot = "1.3.6.1.4.1.65230.1.1";

    /// <summary>Egress CA bundle hash — proves the outbound trust anchors.</summary>
    public const string EgressCaHash = "1.3.6.1.4.1.65230.2.1";

    /// <summary>Runtime version hash — SHA-256 of the runtime version (Wasmtime / containerd).</summary>
    public const string RuntimeVersionHash = "1.3.6.1.4.1.65230.2.4";

    /// <summary>Combined workloads hash — proves the application code (WASM apps / container images).</summary>
    public const string CombinedWorkloadsHash = "1.3.6.1.4.1.65230.2.5";

    /// <summary>Data Encryption Key origin — "byok:&lt;fingerprint&gt;" or "generated".</summary>
    public const string DekOrigin = "1.3.6.1.4.1.65230.2.6";

    /// <summary>Attestation servers hash — SHA-256 of the sorted attestation server URL list.</summary>
    public const string AttestationServersHash = "1.3.6.1.4.1.65230.2.7";

    /// <summary>Per-workload config Merkle root.</summary>
    public const string WorkloadConfigMerkleRoot = "1.3.6.1.4.1.65230.3.1";

    /// <summary>Per-workload code/image hash.</summary>
    public const string WorkloadCodeHash = "1.3.6.1.4.1.65230.3.2";

    /// <summary>Per-workload image ref (Virtual only).</summary>
    public const string WorkloadImageRef = "1.3.6.1.4.1.65230.3.3";

    /// <summary>Per-workload key source / volume encryption.</summary>
    public const string WorkloadKeySource = "1.3.6.1.4.1.65230.3.4";

    /// <summary>Alias for CombinedWorkloadsHash (legacy name).</summary>
    public const string WasmAppsHash = CombinedWorkloadsHash;

    public static readonly HashSet<string> PrivasysOids = new()
    {
        ConfigMerkleRoot,
        EgressCaHash,
        RuntimeVersionHash,
        CombinedWorkloadsHash,
        DekOrigin,
        AttestationServersHash,
        WorkloadConfigMerkleRoot,
        WorkloadCodeHash,
        WorkloadImageRef,
        WorkloadKeySource,
    };

    public static string Label(string oid) => oid switch
    {
        SgxQuote => "SGX Quote",
        TdxQuote => "TDX Quote",
        SevSnpReport => "SEV-SNP Report",
        NvidiaGpuEvidence => "NVIDIA GPU Evidence",
        ConfigMerkleRoot => "Config Merkle Root",
        EgressCaHash => "Egress CA Hash",
        RuntimeVersionHash => "Runtime Version Hash",
        CombinedWorkloadsHash => "Combined Workloads Hash",
        DekOrigin => "DEK Origin",
        AttestationServersHash => "Attestation Servers Hash",
        WorkloadConfigMerkleRoot => "Workload Config Merkle Root",
        WorkloadCodeHash => "Workload Code Hash",
        WorkloadImageRef => "Workload Image Ref",
        WorkloadKeySource => "Workload Key Source",
        _ => "Unknown",
    };
}

// ---------------------------------------------------------------------------
//  Quote byte-offset constants
// ---------------------------------------------------------------------------

public static class SgxQuoteLayout
{
    public const int MinSize = 432;
    public const int MrEnclaveOff = 112;
    public const int MrEnclaveEnd = 144;
    public const int MrSignerOff = 176;
    public const int MrSignerEnd = 208;
    public const int ReportDataOff = 368;
    public const int ReportDataEnd = 432;
}

public static class TdxQuoteLayout
{
    public const int MinSize = 632;
    public const int MrTdOff = 184;
    public const int MrTdEnd = 232;
    public const int ReportDataOff = 568;
    public const int ReportDataEnd = 632;
}

public static class SevSnpReportLayout
{
    public const int MinSize = 0x4A0; // 1184 bytes
    public const int ReportDataOff = 0x050;
    public const int ReportDataEnd = 0x090;
    public const int MeasurementOff = 0x090;
    public const int MeasurementEnd = 0x0C0;
    public const int HostDataOff = 0x0C0;
    public const int HostDataEnd = 0x0E0;
}

// ---------------------------------------------------------------------------
//  RA-TLS verification types
// ---------------------------------------------------------------------------

public enum TeeType { Sgx, Tdx, SevSnp, NvidiaGpu }

public enum ReportDataMode { Skip, Deterministic, ChallengeResponse }

public record ExpectedOid(string Oid, byte[] ExpectedValue);

// ---------------------------------------------------------------------------
//  Quote verification types
// ---------------------------------------------------------------------------

/// <summary>TCB status returned by a quote verification service.</summary>
public enum QuoteVerificationStatus
{
    Ok,
    TcbOutOfDate,
    ConfigurationNeeded,
    SwHardeningNeeded,
    ConfigurationAndSwHardeningNeeded,
    TcbRevoked,
    TcbExpired,
    Unrecognized,
}

public static class QuoteVerificationStatusExt
{
    public static string ToStatusString(this QuoteVerificationStatus s) => s switch
    {
        QuoteVerificationStatus.Ok => "OK",
        QuoteVerificationStatus.TcbOutOfDate => "TCB_OUT_OF_DATE",
        QuoteVerificationStatus.ConfigurationNeeded => "CONFIGURATION_NEEDED",
        QuoteVerificationStatus.SwHardeningNeeded => "SW_HARDENING_NEEDED",
        QuoteVerificationStatus.ConfigurationAndSwHardeningNeeded => "CONFIGURATION_AND_SW_HARDENING_NEEDED",
        QuoteVerificationStatus.TcbRevoked => "TCB_REVOKED",
        QuoteVerificationStatus.TcbExpired => "TCB_EXPIRED",
        _ => "UNRECOGNIZED",
    };

    public static QuoteVerificationStatus FromString(string s) => s switch
    {
        "OK" => QuoteVerificationStatus.Ok,
        "TCB_OUT_OF_DATE" => QuoteVerificationStatus.TcbOutOfDate,
        "CONFIGURATION_NEEDED" => QuoteVerificationStatus.ConfigurationNeeded,
        "SW_HARDENING_NEEDED" => QuoteVerificationStatus.SwHardeningNeeded,
        "CONFIGURATION_AND_SW_HARDENING_NEEDED" => QuoteVerificationStatus.ConfigurationAndSwHardeningNeeded,
        "TCB_REVOKED" => QuoteVerificationStatus.TcbRevoked,
        "TCB_EXPIRED" => QuoteVerificationStatus.TcbExpired,
        _ => QuoteVerificationStatus.Unrecognized,
    };
}

/// <summary>
/// Configuration for remote quote verification via an HTTP service.
/// Point Endpoint at a quote verification service (e.g. an attestation server).
/// </summary>
public record QuoteVerificationConfig(
    string Endpoint,
    string? Token = null,
    QuoteVerificationStatus[]? AcceptedStatuses = null,
    int TimeoutSecs = 10
);

/// <summary>Result of remote quote verification.</summary>
public record QuoteVerificationResult(
    QuoteVerificationStatus Status,
    string? TcbDate = null,
    string[]? AdvisoryIds = null
);

public record VerificationPolicy(
    TeeType Tee,
    byte[]? MrEnclave = null,
    byte[]? MrSigner = null,
    byte[]? MrTd = null,
    byte[]? Measurement = null,
    byte[]? HostData = null,
    ReportDataMode ReportData = ReportDataMode.Skip,
    byte[]? Nonce = null,
    ExpectedOid[]? ExpectedOids = null,
    QuoteVerificationConfig? QuoteVerification = null
);

// ---------------------------------------------------------------------------
//  Certificate inspection result
// ---------------------------------------------------------------------------

public record QuoteInfo(
    string Oid,
    string Label,
    bool Critical,
    byte[] Raw,
    bool IsMock = false,
    ushort? Version = null,
    byte[]? ReportData = null
);

public record OidExtension(string Oid, string Label, byte[] Value);

public record CertInfo(
    string Subject,
    string Issuer,
    string SerialNumber,
    string NotBefore,
    string NotAfter,
    string SignatureAlgorithm,
    string PubKeySha256,
    QuoteInfo? Quote = null,
    OidExtension[]? CustomOids = null,
    QuoteVerificationResult? QuoteVerification = null
);

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

public static class RaTlsCertInspector
{
    public static CertInfo Inspect(X509Certificate2 cert)
    {
        var pubKeyHash = SHA256.HashData(cert.GetPublicKey());

        QuoteInfo? quote = null;
        var customOids = new List<OidExtension>();

        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == RaTlsOids.SgxQuote || ext.Oid?.Value == RaTlsOids.TdxQuote
                || ext.Oid?.Value == RaTlsOids.SevSnpReport || ext.Oid?.Value == RaTlsOids.NvidiaGpuEvidence)
            {
                var raw = ext.RawData;
                quote = ParseQuote(ext.Oid.Value, ext.Critical, raw);
            }
            else if (ext.Oid?.Value != null && RaTlsOids.PrivasysOids.Contains(ext.Oid.Value))
            {
                customOids.Add(new OidExtension(
                    ext.Oid.Value,
                    RaTlsOids.Label(ext.Oid.Value),
                    ext.RawData
                ));
            }
        }

        return new CertInfo(
            Subject: cert.Subject,
            Issuer: cert.Issuer,
            SerialNumber: cert.SerialNumber,
            NotBefore: cert.NotBefore.ToString("o"),
            NotAfter: cert.NotAfter.ToString("o"),
            SignatureAlgorithm: cert.SignatureAlgorithm.FriendlyName ?? "",
            PubKeySha256: Convert.ToHexString(pubKeyHash).ToLowerInvariant(),
            Quote: quote,
            CustomOids: customOids.Count > 0 ? customOids.ToArray() : null
        );
    }

    private static QuoteInfo ParseQuote(string oid, bool critical, byte[] raw)
    {
        var label = RaTlsOids.Label(oid);
        bool isMock = raw.Length >= 11 && Encoding.ASCII.GetString(raw, 0, 11) == "MOCK_QUOTE:";
        ushort? version = null;
        byte[]? reportData = null;

        if (isMock)
        {
            int rdEnd = Math.Min(raw.Length, 75);
            reportData = raw[11..rdEnd];
        }
        else if (oid == RaTlsOids.SgxQuote && raw.Length >= 4)
        {
            version = BitConverter.ToUInt16(raw, 0);
            if (raw.Length >= 432)
                reportData = raw[368..432];
        }
        else if (oid == RaTlsOids.TdxQuote && raw.Length >= 4)
        {
            version = BitConverter.ToUInt16(raw, 0);
            if (raw.Length >= TdxQuoteLayout.MinSize)
                reportData = raw[TdxQuoteLayout.ReportDataOff..TdxQuoteLayout.ReportDataEnd];
        }
        else if (oid == RaTlsOids.SevSnpReport && raw.Length >= SevSnpReportLayout.MinSize)
        {
            version = BitConverter.ToUInt16(raw, 0);
            reportData = raw[SevSnpReportLayout.ReportDataOff..SevSnpReportLayout.ReportDataEnd];
        }

        return new QuoteInfo(oid, label, critical, raw, isMock, version, reportData);
    }
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

public static class RaTlsVerifier
{
    /// <summary>
    /// Verify an RA-TLS certificate against a policy.
    /// Returns CertInfo on success, throws on failure.
    /// </summary>
    public static CertInfo Verify(X509Certificate2 cert, VerificationPolicy policy)
    {
        var info = RaTlsCertInspector.Inspect(cert);

        // 1. Quote must be present
        if (info.Quote is null)
            throw new InvalidOperationException("no RA-TLS attestation quote in certificate");
        if (info.Quote.IsMock)
            throw new InvalidOperationException("certificate contains a MOCK quote");

        // 2. Correct TEE type
        var expectedOid = policy.Tee switch
        {
            TeeType.Sgx => RaTlsOids.SgxQuote,
            TeeType.Tdx => RaTlsOids.TdxQuote,
            TeeType.SevSnp => RaTlsOids.SevSnpReport,
            TeeType.NvidiaGpu => RaTlsOids.NvidiaGpuEvidence,
            _ => null,
        };
        if (expectedOid is not null && info.Quote.Oid != expectedOid)
            throw new InvalidOperationException($"expected {policy.Tee} quote ({expectedOid}), found {info.Quote.Oid}");

        // 3. Measurement registers
        VerifyMeasurements(info.Quote.Raw, policy);

        // 4. ReportData
        VerifyReportData(cert, info.Quote.Raw, policy);

        // 5. Custom OID values
        VerifyExpectedOids(info.CustomOids, policy.ExpectedOids);

        // 6. Remote quote verification
        if (policy.QuoteVerification is not null)
        {
            var qvResult = VerifyQuote(info.Quote.Raw, policy.QuoteVerification);
            info = info with { QuoteVerification = qvResult };
        }

        return info;
    }

    private static void VerifyMeasurements(byte[] raw, VerificationPolicy policy)
    {
        if (policy.Tee == TeeType.Sgx)
        {
            if (raw.Length < SgxQuoteLayout.MinSize)
                throw new InvalidOperationException($"SGX quote too small: {raw.Length} < {SgxQuoteLayout.MinSize}");

            if (policy.MrEnclave is not null)
            {
                var actual = raw.AsSpan(SgxQuoteLayout.MrEnclaveOff, 32);
                if (!actual.SequenceEqual(policy.MrEnclave))
                    throw new InvalidOperationException(
                        $"MRENCLAVE mismatch: got {ToHex(actual)}, expected {ToHex(policy.MrEnclave)}");
            }
            if (policy.MrSigner is not null)
            {
                var actual = raw.AsSpan(SgxQuoteLayout.MrSignerOff, 32);
                if (!actual.SequenceEqual(policy.MrSigner))
                    throw new InvalidOperationException(
                        $"MRSIGNER mismatch: got {ToHex(actual)}, expected {ToHex(policy.MrSigner)}");
            }
        }
        else if (policy.Tee == TeeType.SevSnp)
        {
            if (raw.Length < SevSnpReportLayout.MinSize)
                throw new InvalidOperationException($"SEV-SNP report too small: {raw.Length} < {SevSnpReportLayout.MinSize}");

            if (policy.Measurement is not null)
            {
                var actual = raw.AsSpan(SevSnpReportLayout.MeasurementOff, 48);
                if (!actual.SequenceEqual(policy.Measurement))
                    throw new InvalidOperationException(
                        $"Measurement mismatch: got {ToHex(actual)}, expected {ToHex(policy.Measurement)}");
            }
            if (policy.HostData is not null)
            {
                var actual = raw.AsSpan(SevSnpReportLayout.HostDataOff, 32);
                if (!actual.SequenceEqual(policy.HostData))
                    throw new InvalidOperationException(
                        $"HostData mismatch: got {ToHex(actual)}, expected {ToHex(policy.HostData)}");
            }
        }
        else if (policy.Tee == TeeType.NvidiaGpu)
        {
            // NVIDIA GPU evidence measurement verification is handled by NRAS.
        }
        else // Tdx
        {
            if (raw.Length < TdxQuoteLayout.MinSize)
                throw new InvalidOperationException($"TDX quote too small: {raw.Length} < {TdxQuoteLayout.MinSize}");

            if (policy.MrTd is not null)
            {
                var actual = raw.AsSpan(TdxQuoteLayout.MrTdOff, 48);
                if (!actual.SequenceEqual(policy.MrTd))
                    throw new InvalidOperationException(
                        $"MRTD mismatch: got {ToHex(actual)}, expected {ToHex(policy.MrTd)}");
            }
        }
    }

    private static void VerifyReportData(X509Certificate2 cert, byte[] raw, VerificationPolicy policy)
    {
        if (policy.ReportData == ReportDataMode.Skip) return;
        // NVIDIA GPU evidence does not carry ReportData bound to the TLS key.
        if (policy.Tee == TeeType.NvidiaGpu) return;

        byte[] binding;
        if (policy.ReportData == ReportDataMode.Deterministic)
        {
            if (policy.Tee == TeeType.Sgx) return; // Not applicable for SGX
            var nb = cert.NotBefore.ToUniversalTime();
            binding = Encoding.UTF8.GetBytes(
                $"{nb.Year:D4}-{nb.Month:D2}-{nb.Day:D2}T{nb.Hour:D2}:{nb.Minute:D2}Z");
        }
        else if (policy.ReportData == ReportDataMode.ChallengeResponse)
        {
            binding = policy.Nonce ?? throw new InvalidOperationException("ChallengeResponse mode requires a nonce");
        }
        else return;

        // Build pubkey input
        byte[] pubkeyInput;
        using var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            var spkiDer = ecdsa.ExportSubjectPublicKeyInfo();
            if (policy.Tee == TeeType.Sgx)
            {
                // SGX: raw EC point (last 65 bytes)
                pubkeyInput = spkiDer.Length >= 65
                    ? spkiDer[^65..]
                    : spkiDer;
            }
            else
            {
                // TDX / SEV-SNP: full SPKI DER
                pubkeyInput = spkiDer;
            }
        }
        else
        {
            throw new InvalidOperationException("Cannot extract EC public key for ReportData verification");
        }

        var expected = ComputeReportDataHash(pubkeyInput, binding);

        // Get actual ReportData
        ReadOnlySpan<byte> actual;
        if (policy.Tee == TeeType.Sgx)
        {
            if (raw.Length < SgxQuoteLayout.ReportDataEnd)
                throw new InvalidOperationException("quote too small for ReportData");
            actual = raw.AsSpan(SgxQuoteLayout.ReportDataOff, 64);
        }
        else if (policy.Tee == TeeType.SevSnp)
        {
            if (raw.Length < SevSnpReportLayout.ReportDataEnd)
                throw new InvalidOperationException("report too small for ReportData");
            actual = raw.AsSpan(SevSnpReportLayout.ReportDataOff, 64);
        }
        else
        {
            if (raw.Length < TdxQuoteLayout.ReportDataEnd)
                throw new InvalidOperationException("quote too small for ReportData");
            actual = raw.AsSpan(TdxQuoteLayout.ReportDataOff, 64);
        }

        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException(
                $"ReportData mismatch:\n  got:      {ToHex(actual)}\n  expected: {ToHex(expected)}");
    }

    private static void VerifyExpectedOids(OidExtension[]? actual, ExpectedOid[]? expected)
    {
        if (expected is null or { Length: 0 }) return;

        var map = new Dictionary<string, byte[]>();
        if (actual is not null)
            foreach (var ext in actual)
                map[ext.Oid] = ext.Value;

        foreach (var exp in expected)
        {
            if (!map.TryGetValue(exp.Oid, out var value))
                throw new InvalidOperationException(
                    $"expected OID {exp.Oid} ({RaTlsOids.Label(exp.Oid)}) not found in certificate");
            if (!value.AsSpan().SequenceEqual(exp.ExpectedValue))
                throw new InvalidOperationException(
                    $"{RaTlsOids.Label(exp.Oid)} ({exp.Oid}) mismatch: got {ToHex(value)}, expected {ToHex(exp.ExpectedValue)}");
        }
    }

    /// <summary>Compute SHA-512( SHA-256(pubkey) || binding ).</summary>
    private static byte[] ComputeReportDataHash(byte[] pubkeyInput, byte[] binding)
    {
        var pkHash = SHA256.HashData(pubkeyInput);
        var buf = new byte[pkHash.Length + binding.Length];
        pkHash.CopyTo(buf, 0);
        binding.CopyTo(buf, pkHash.Length);
        return SHA512.HashData(buf);
    }

    private static string ToHex(ReadOnlySpan<byte> data)
        => Convert.ToHexString(data).ToLowerInvariant();

    /// <summary>Verify the raw quote against a remote quote verification service.</summary>
    private static QuoteVerificationResult VerifyQuote(byte[] quoteRaw, QuoteVerificationConfig config)
    {
        using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(config.TimeoutSecs) };

        var body = JsonSerializer.Serialize(new { quote = Convert.ToBase64String(quoteRaw) });
        var content = new StringContent(body, Encoding.UTF8, "application/json");

        if (config.Token is not null)
            httpClient.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", config.Token);

        var resp = httpClient.PostAsync(config.Endpoint, content).GetAwaiter().GetResult();
        var respBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        var json = JsonSerializer.Deserialize<JsonElement>(respBody);
        var statusStr = json.TryGetProperty("status", out var sProp) ? sProp.GetString() ?? "" : "";
        var status = QuoteVerificationStatusExt.FromString(statusStr);

        string? tcbDate = json.TryGetProperty("tcbDate", out var tProp) ? tProp.GetString() : null;
        string[]? advisoryIds = null;
        if (json.TryGetProperty("advisoryIds", out var aProp) && aProp.ValueKind == JsonValueKind.Array)
            advisoryIds = aProp.EnumerateArray().Select(e => e.GetString() ?? "").ToArray();

        var result = new QuoteVerificationResult(status, tcbDate, advisoryIds);

        if (result.Status != QuoteVerificationStatus.Ok)
        {
            var accepted = config.AcceptedStatuses?.Contains(result.Status) ?? false;
            if (!accepted)
                throw new InvalidOperationException(
                    $"quote verification failed: status={result.Status.ToStatusString()}, " +
                    $"advisories=[{string.Join(", ", advisoryIds ?? Array.Empty<string>())}]");
        }

        return result;
    }
}

// ---------------------------------------------------------------------------
//  Framing
// ---------------------------------------------------------------------------

public static class Framing
{
    public static byte[] EncodeFrame(byte[] payload)
    {
        var frame = new byte[4 + payload.Length];
        frame[0] = (byte)(payload.Length >> 24);
        frame[1] = (byte)(payload.Length >> 16);
        frame[2] = (byte)(payload.Length >> 8);
        frame[3] = (byte)(payload.Length);
        Array.Copy(payload, 0, frame, 4, payload.Length);
        return frame;
    }

    public static byte[]? TryDecodeFrame(byte[] buf, out int consumed)
    {
        consumed = 0;
        if (buf.Length < 4) return null;
        int length = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
        if (buf.Length < 4 + length) return null;
        consumed = 4 + length;
        return buf[4..(4 + length)];
    }
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

public class RaTlsClient : IDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _caCertPath;
    private readonly int _timeoutMs;

    private TcpClient? _tcp;
    private SslStream? _ssl;
    private X509Certificate2? _serverCert;

    public RaTlsClient(string host, int port = 443, string? caCertPath = null, int timeoutMs = 10_000)
    {
        _host = host;
        _port = port;
        _caCertPath = caCertPath;
        _timeoutMs = timeoutMs;
    }

    public void Connect()
    {
        _tcp = new TcpClient();
        _tcp.SendTimeout = _timeoutMs;
        _tcp.ReceiveTimeout = _timeoutMs;
        _tcp.Connect(_host, _port);

        _ssl = new SslStream(
            _tcp.GetStream(),
            leaveInnerStreamOpen: false,
            userCertificateValidationCallback: ValidateCert
        );

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = _host,
        };

        _ssl.AuthenticateAsClient(options);
    }

    private bool ValidateCert(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is X509Certificate2 cert2)
            _serverCert = cert2;
        else if (certificate != null)
            _serverCert = new X509Certificate2(certificate);

        if (_caCertPath != null)
        {
            // Verify against the provided CA
            using var caCert = new X509Certificate2(_caCertPath);
            using var ch = new X509Chain();
            ch.ChainPolicy.ExtraStore.Add(caCert);
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            ch.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            ch.ChainPolicy.CustomTrustStore.Add(caCert);
            return _serverCert != null && ch.Build(_serverCert);
        }

        // No CA provided → accept any cert (dev mode)
        return true;
    }

    public string TlsVersion => _ssl?.SslProtocol.ToString() ?? "";
    public string CipherSuite => _ssl?.NegotiatedCipherSuite.ToString() ?? "";

    public CertInfo InspectCertificate()
    {
        if (_serverCert == null)
            return new CertInfo("", "", "", "", "", "", "");

        return RaTlsCertInspector.Inspect(_serverCert);
    }

    /// <summary>Verify the server's leaf certificate against a policy.</summary>
    public CertInfo VerifyCertificate(VerificationPolicy policy)
    {
        if (_serverCert == null)
            throw new InvalidOperationException("no peer certificate");
        return RaTlsVerifier.Verify(_serverCert, policy);
    }

    // -- HTTP/1.1 protocol ---------------------------------------------------

    private void SendHttpRequest(string method, string path, byte[]? body = null, string? authToken = null, bool connectionClose = false)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append($"{method} {path} HTTP/1.1\r\nHost: {_host}\r\n");
        if (body is { Length: > 0 })
        {
            sb.Append($"Content-Length: {body.Length}\r\nContent-Type: application/json\r\n");
        }
        if (authToken is not null)
            sb.Append($"Authorization: Bearer {authToken}\r\n");
        if (connectionClose)
            sb.Append("Connection: close\r\n");
        sb.Append("\r\n");

        var header = Encoding.ASCII.GetBytes(sb.ToString());
        _ssl!.Write(header);
        if (body is { Length: > 0 })
            _ssl.Write(body);
        _ssl.Flush();
    }

    private (int StatusCode, byte[] Body) RecvHttpResponse()
    {
        var buf = new List<byte>();
        var tmp = new byte[4096];

        // Read until \r\n\r\n
        while (true)
        {
            int n = _ssl!.Read(tmp, 0, tmp.Length);
            if (n == 0) throw new Exception("Connection closed before HTTP headers received");
            buf.AddRange(tmp.AsSpan(0, n).ToArray());

            var bufArr = buf.ToArray();
            int idx = FindHeaderEnd(bufArr);
            if (idx >= 0) break;
        }

        var rawBuf = buf.ToArray();
        int headerEnd = FindHeaderEnd(rawBuf);
        var headerSection = Encoding.ASCII.GetString(rawBuf, 0, headerEnd);
        int bodyStart = headerEnd + 4;

        // Parse status
        var statusLine = headerSection.Split("\r\n")[0];
        var parts = statusLine.Split(' ', 3);
        int statusCode = parts.Length >= 2 ? int.Parse(parts[1]) : 0;

        // Parse content-length
        int contentLength = 0;
        foreach (var line in headerSection.Split("\r\n")[1..])
        {
            if (line.StartsWith("content-length:", StringComparison.OrdinalIgnoreCase))
                contentLength = int.Parse(line.Split(':', 2)[1].Trim());
        }

        // Collect body
        var body = new List<byte>();
        if (bodyStart < rawBuf.Length)
            body.AddRange(rawBuf.AsSpan(bodyStart, Math.Min(rawBuf.Length - bodyStart, contentLength)).ToArray());

        while (body.Count < contentLength)
        {
            int n = _ssl!.Read(tmp, 0, tmp.Length);
            if (n == 0) break;
            body.AddRange(tmp.AsSpan(0, Math.Min(n, contentLength - body.Count)).ToArray());
        }

        return (statusCode, body.ToArray());
    }

    private static int FindHeaderEnd(byte[] buf)
    {
        for (int i = 0; i <= buf.Length - 4; i++)
        {
            if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
                return i;
        }
        return -1;
    }

    /// <summary>GET /healthz — liveness probe (no auth).</summary>
    public Dictionary<string, JsonElement> Healthz()
    {
        SendHttpRequest("GET", "/healthz");
        var (status, body) = RecvHttpResponse();
        if (status != 200) throw new Exception($"healthz failed ({status}): {Encoding.UTF8.GetString(body)}");
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body)!;
    }

    /// <summary>GET /readyz — readiness probe (monitoring+).</summary>
    public Dictionary<string, JsonElement> Readyz(string? authToken = null)
    {
        SendHttpRequest("GET", "/readyz", authToken: authToken);
        var (status, body) = RecvHttpResponse();
        if (status != 200) throw new Exception($"readyz failed ({status}): {Encoding.UTF8.GetString(body)}");
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body)!;
    }

    /// <summary>POST /data — send module command and return response bytes.</summary>
    public byte[] SendData(byte[] data, string? authToken = null)
    {
        SendHttpRequest("POST", "/data", body: data, authToken: authToken);
        var (status, body) = RecvHttpResponse();
        if (status != 200)
            throw new Exception($"send_data failed ({status}): {Encoding.UTF8.GetString(body)}");
        return body;
    }

    /// <summary>POST /shutdown — request graceful shutdown.</summary>
    public void Shutdown(string? authToken = null)
    {
        SendHttpRequest("POST", "/shutdown", authToken: authToken, connectionClose: true);
        var (status, body) = RecvHttpResponse();
        if (status != 200) throw new Exception($"shutdown failed ({status}): {Encoding.UTF8.GetString(body)}");
    }

    // -- Legacy frame protocol (deprecated) --------------------------------

    /// <summary>Deprecated: Use Healthz() instead.</summary>
    public bool Ping()
    {
        var result = Healthz();
        return result.TryGetValue("status", out var s) && s.GetString() == "ok";
    }

    /// <summary>Deprecated: Use SendData(byte[], string?) instead.</summary>
    public byte[] SendData(ReadOnlySpan<byte> data)
    {
        return SendData(data.ToArray(), null);
    }

    private void SendFrame(byte[] payload)
    {
        _ssl!.Write(Framing.EncodeFrame(payload));
        _ssl.Flush();
    }

    private byte[] RecvFrame()
    {
        var buf = new List<byte>();
        var tmp = new byte[4096];
        while (true)
        {
            int n = _ssl!.Read(tmp, 0, tmp.Length);
            if (n == 0) throw new Exception("Connection closed before frame received");
            buf.AddRange(tmp.AsSpan(0, n).ToArray());

            var payload = Framing.TryDecodeFrame(buf.ToArray(), out _);
            if (payload != null) return payload;
        }
    }

    public void Dispose()
    {
        _ssl?.Dispose();
        _tcp?.Dispose();
    }
}

// ---------------------------------------------------------------------------
//  Pretty-print
// ---------------------------------------------------------------------------

public static class RaTlsPrinter
{
    public static void PrintCertInfo(CertInfo info)
    {
        Console.WriteLine($"  Subject      : {info.Subject}");
        Console.WriteLine($"  Issuer       : {info.Issuer}");
        Console.WriteLine($"  Serial       : {info.SerialNumber}");
        Console.WriteLine($"  Not Before   : {info.NotBefore}");
        Console.WriteLine($"  Not After    : {info.NotAfter}");
        Console.WriteLine($"  Sig Algo     : {info.SignatureAlgorithm}");
        Console.WriteLine($"  PubKey SHA256: {info.PubKeySha256}");

        if (info.Quote is { } q)
        {
            Console.WriteLine();
            Console.WriteLine("  ** RA-TLS Extension found! **");
            Console.WriteLine($"    OID       : {q.Oid}  ({q.Label})");
            Console.WriteLine($"    Critical  : {q.Critical}");
            Console.WriteLine($"    Size      : {q.Raw.Length} bytes");
            if (q.IsMock) Console.WriteLine("    ** MOCK QUOTE **");
            if (q.Version.HasValue) Console.WriteLine($"    Version   : {q.Version}");
            if (q.ReportData != null) Console.WriteLine($"    ReportData: {Convert.ToHexString(q.ReportData).ToLowerInvariant()}");

            // Display measurement registers
            if (q.Oid == RaTlsOids.SgxQuote && q.Raw.Length >= SgxQuoteLayout.MinSize)
            {
                Console.WriteLine($"    MRENCLAVE : {Convert.ToHexString(q.Raw.AsSpan(SgxQuoteLayout.MrEnclaveOff, 32)).ToLowerInvariant()}");
                Console.WriteLine($"    MRSIGNER  : {Convert.ToHexString(q.Raw.AsSpan(SgxQuoteLayout.MrSignerOff, 32)).ToLowerInvariant()}");
            }
            else if (q.Oid == RaTlsOids.TdxQuote && q.Raw.Length >= TdxQuoteLayout.MinSize)
            {
                Console.WriteLine($"    MRTD      : {Convert.ToHexString(q.Raw.AsSpan(TdxQuoteLayout.MrTdOff, 48)).ToLowerInvariant()}");
            }
            else if (q.Oid == RaTlsOids.SevSnpReport && q.Raw.Length >= SevSnpReportLayout.MinSize)
            {
                Console.WriteLine($"    Measurement: {Convert.ToHexString(q.Raw.AsSpan(SevSnpReportLayout.MeasurementOff, 48)).ToLowerInvariant()}");
                Console.WriteLine($"    HostData   : {Convert.ToHexString(q.Raw.AsSpan(SevSnpReportLayout.HostDataOff, 32)).ToLowerInvariant()}");
            }

            Console.WriteLine($"    Preview   : {Convert.ToHexString(q.Raw.AsSpan(0, Math.Min(32, q.Raw.Length))).ToLowerInvariant()}...");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("  No RA-TLS extension found.");
        }

        if (info.CustomOids is { Length: > 0 })
        {
            Console.WriteLine();
            Console.WriteLine("  ** Privasys Configuration OIDs **");
            foreach (var ext in info.CustomOids)
            {
                Console.WriteLine($"    {ext.Label} ({ext.Oid}): {Convert.ToHexString(ext.Value).ToLowerInvariant()}");
            }
        }

        if (info.QuoteVerification is { } qv)
        {
            Console.WriteLine();
            Console.WriteLine("  ** Quote Verification **");
            Console.WriteLine($"    Status    : {qv.Status.ToStatusString()}");
            if (qv.TcbDate is not null)
                Console.WriteLine($"    TCB Date  : {qv.TcbDate}");
            if (qv.AdvisoryIds is { Length: > 0 })
                Console.WriteLine($"    Advisories: {string.Join(", ", qv.AdvisoryIds)}");
        }
    }
}
