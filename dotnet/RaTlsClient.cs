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

    // Privasys configuration OIDs (PEN 1337)

    /// <summary>Config Merkle root — proves all config inputs.</summary>
    public const string ConfigMerkleRoot = "1.3.6.1.4.1.1337.1.1";

    /// <summary>Egress CA bundle hash — proves the outbound trust anchors.</summary>
    public const string EgressCaHash = "1.3.6.1.4.1.1337.2.1";

    /// <summary>WASM apps combined hash — proves the application code.</summary>
    public const string WasmAppsHash = "1.3.6.1.4.1.1337.2.3";

    public static readonly HashSet<string> PrivasysOids = new()
    {
        ConfigMerkleRoot,
        EgressCaHash,
        WasmAppsHash,
    };

    public static string Label(string oid) => oid switch
    {
        SgxQuote => "SGX Quote",
        TdxQuote => "TDX Quote",
        ConfigMerkleRoot => "Config Merkle Root",
        EgressCaHash => "Egress CA Hash",
        WasmAppsHash => "WASM Apps Hash",
        _ => "Unknown",
    };
}

// ---------------------------------------------------------------------------
//  DCAP quote byte-offset constants
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

// ---------------------------------------------------------------------------
//  RA-TLS verification types
// ---------------------------------------------------------------------------

public enum TeeType { Sgx, Tdx }

public enum ReportDataMode { Skip, Deterministic, ChallengeResponse }

public record ExpectedOid(string Oid, byte[] ExpectedValue);

public record VerificationPolicy(
    TeeType Tee,
    byte[]? MrEnclave = null,
    byte[]? MrSigner = null,
    byte[]? MrTd = null,
    ReportDataMode ReportData = ReportDataMode.Skip,
    byte[]? Nonce = null,
    ExpectedOid[]? ExpectedOids = null
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
    OidExtension[]? CustomOids = null
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
            if (ext.Oid?.Value == RaTlsOids.SgxQuote || ext.Oid?.Value == RaTlsOids.TdxQuote)
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
        if (policy.Tee == TeeType.Sgx && info.Quote.Oid != RaTlsOids.SgxQuote)
            throw new InvalidOperationException($"expected SGX quote ({RaTlsOids.SgxQuote}), found {info.Quote.Oid}");
        if (policy.Tee == TeeType.Tdx && info.Quote.Oid != RaTlsOids.TdxQuote)
            throw new InvalidOperationException($"expected TDX quote ({RaTlsOids.TdxQuote}), found {info.Quote.Oid}");

        // 3. Measurement registers
        VerifyMeasurements(info.Quote.Raw, policy);

        // 4. ReportData
        VerifyReportData(cert, info.Quote.Raw, policy);

        // 5. Custom OID values
        VerifyExpectedOids(info.CustomOids, policy.ExpectedOids);

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

        byte[] binding;
        if (policy.ReportData == ReportDataMode.Deterministic)
        {
            if (policy.Tee == TeeType.Sgx) return; // Not applicable for SGX
            // TDX: binding is NotBefore as "YYYY-MM-DDTHH:MMZ"
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
                // TDX: full SPKI DER
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

    // -- Protocol ---------------------------------------------------------

    public bool Ping()
    {
        SendFrame(JsonSerializer.SerializeToUtf8Bytes("Ping"));
        var resp = JsonSerializer.Deserialize<JsonElement>(RecvFrame());
        return resp.GetString() == "Pong";
    }

    public byte[] SendData(ReadOnlySpan<byte> data)
    {
        var req = new Dictionary<string, object> { ["Data"] = data.ToArray().Select(b => (int)b).ToArray() };
        SendFrame(JsonSerializer.SerializeToUtf8Bytes(req));

        var respRaw = RecvFrame();
        var resp = JsonSerializer.Deserialize<JsonElement>(respRaw);

        if (resp.TryGetProperty("Data", out var dataElem))
        {
            return dataElem.EnumerateArray().Select(e => (byte)e.GetInt32()).ToArray();
        }
        if (resp.TryGetProperty("Error", out var errElem))
        {
            var errBytes = errElem.EnumerateArray().Select(e => (byte)e.GetInt32()).ToArray();
            throw new Exception(Encoding.UTF8.GetString(errBytes));
        }
        throw new Exception($"Unexpected response: {Encoding.UTF8.GetString(respRaw)}");
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
    }
}
