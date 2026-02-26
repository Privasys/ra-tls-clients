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
//   using var client = new RaTlsClient("141.94.219.130", 8443, caCertPath: "ca.pem");
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

    /// <summary>Intel TDX Quote (caddy-ra-tls-module): 1.2.840.113741.1.5.5.1.6</summary>
    public const string TdxQuote = "1.2.840.113741.1.5.5.1.6";

    public static string Label(string oid) => oid switch
    {
        SgxQuote => "SGX Quote",
        TdxQuote => "TDX Quote",
        _ => "Unknown",
    };
}

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

public record CertInfo(
    string Subject,
    string Issuer,
    string SerialNumber,
    string NotBefore,
    string NotAfter,
    string SignatureAlgorithm,
    string PubKeySha256,
    QuoteInfo? Quote = null
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
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == RaTlsOids.SgxQuote || ext.Oid?.Value == RaTlsOids.TdxQuote)
            {
                var raw = ext.RawData;
                quote = ParseQuote(ext.Oid.Value, ext.Critical, raw);
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
            Quote: quote
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
        }

        return new QuoteInfo(oid, label, critical, raw, isMock, version, reportData);
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

    public RaTlsClient(string host, int port = 8443, string? caCertPath = null, int timeoutMs = 10_000)
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
            Console.WriteLine($"    Preview   : {Convert.ToHexString(q.Raw.AsSpan(0, Math.Min(32, q.Raw.Length))).ToLowerInvariant()}...");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("  No RA-TLS extension found.");
        }
    }
}
