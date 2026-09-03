// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>The shared vectors of tests/vectors/ratls-v2 (docs/ratls-v2.md section 8).</summary>
public class VectorTests
{
    private static string VectorPath(string name) => Path.Combine(RepoRoot(), "tests", "vectors", "ratls-v2", name);

    [Fact]
    public void ReportDataVectorsMatchTheGoReference()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(VectorPath("report_data.json")));
        var vectors = doc.RootElement.EnumerateArray().ToList();
        Assert.Equal(4, vectors.Count);
        var seen = new HashSet<string>();
        foreach (var v in vectors)
        {
            var name = v.GetProperty("name").GetString()!;
            seen.Add(name);
            var spki = Hex(v.GetProperty("spki_der").GetString()!);
            var ev = new Evidence
            {
                Mode = v.GetProperty("mode").GetString() == "challenge" ? AttestationMode.Challenge : AttestationMode.Deterministic,
            };
            if (v.TryGetProperty("quote_time", out var qt)) ev.QuoteTimeRaw = qt.GetString()!;
            if (v.TryGetProperty("context", out var ctx)) ev.Context = Hex(ctx.GetString()!);
            if (v.TryGetProperty("hctx", out var hctx)) ev.Hctx = Hex(hctx.GetString()!);
            if (v.TryGetProperty("gpu_evidence", out var gpu)) ev.GpuEvidence = Hex(gpu.GetString()!);

            var got = RaTlsVerifier.ExpectedReportData(spki, ev);
            Assert.True(v.GetProperty("report_data").GetString() == ToHex(got), $"vector {name} differs");
        }
        Assert.Equal(new[] { "challenge", "challenge-gpu", "deterministic", "deterministic-gpu" }, seen.OrderBy(s => s, StringComparer.Ordinal));
    }

    // A further SHA-256 data point, produced while writing this suite from a live TLS 1.3
    // connection between OpenSSL 3.5.4 (s_server -keylogfile, EXPORTER_SECRET line) and Go 1.26
    // crypto/tls (ConnectionState.ExportKeyingMaterial), cipher TLS_AES_128_GCM_SHA256,
    // in the shape of exporter.json.
    private const string EmbeddedExporterVector = """
        {"name": "TLS_AES_128_GCM_SHA256 (openssl 3.5.4)", "hash": "sha256",
         "exporter_master_secret": "6a4218ff76c40e1d0183729635fa680539c925a8f9fe4b5ce2aa4346bce226d7",
         "label": "EXPORTER-privasys-ratls-attest-v2",
         "context": "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
         "length": 32,
         "hctx": "6043273290aeb83e64d20c44ee79ea36b4ca0536927dc199e4db955fa316e6e2",
         "client_label": "EXPORTER-privasys-ratls-attest-v2-client",
         "client_hctx": "e9c9bff4b05f0b0b2c77cafc1de073984c981b6ba8050e83b61ea88954e7a4b8"}
        """;

    [Fact]
    public void ExporterVectorsMatchRfc8446Section75()
    {
        using var file = JsonDocument.Parse(File.ReadAllText(VectorPath("exporter.json")));
        using var embedded = JsonDocument.Parse(EmbeddedExporterVector);
        var vectors = file.RootElement.GetProperty("vectors").EnumerateArray().Append(embedded.RootElement).ToList();
        Assert.True(vectors.Count >= 3);
        var hashes = new HashSet<string>();
        foreach (var v in vectors)
        {
            var name = v.GetProperty("name").GetString();
            var hash = v.GetProperty("hash").GetString()!;
            hashes.Add(hash);
            var ems = Hex(v.GetProperty("exporter_master_secret").GetString()!);
            var context = Hex(v.GetProperty("context").GetString()!);
            var length = v.GetProperty("length").GetInt32();
            Assert.Equal(RaTlsAttest.HctxLen, length);
            Assert.Equal(RaTlsAttest.ExporterLabelServer, v.GetProperty("label").GetString());
            Assert.Equal(RaTlsAttest.ExporterLabelClient, v.GetProperty("client_label").GetString());
            var hctx = Tls13Exporter.Export(hash, ems, RaTlsAttest.ExporterLabelServer, context, length);
            Assert.True(v.GetProperty("hctx").GetString() == ToHex(hctx), $"server hctx differs for {name}");
            var clientHctx = Tls13Exporter.Export(hash, ems, RaTlsAttest.ExporterLabelClient, context, length);
            Assert.True(v.GetProperty("client_hctx").GetString() == ToHex(clientHctx), $"client hctx differs for {name}");
        }
        Assert.Contains("sha256", hashes);
        Assert.Contains("sha384", hashes);
    }

    [Fact]
    public void ExporterDependsOnLabelAndContext()
    {
        var ems = Rep(0x42, 32);
        var ctx = Rep(0xC0, 32);
        var a = Tls13Exporter.Export("sha256", ems, RaTlsAttest.ExporterLabelServer, ctx, 32);
        var b = Tls13Exporter.Export("sha256", ems, RaTlsAttest.ExporterLabelClient, ctx, 32);
        var c = Tls13Exporter.Export("sha256", ems, RaTlsAttest.ExporterLabelServer, Rep(0xC1, 32), 32);
        Assert.NotEqual(ToHex(a), ToHex(b));
        Assert.NotEqual(ToHex(a), ToHex(c));
        Assert.Equal(32, a.Length);
    }

    [Fact]
    public void HkdfExpandLabelMatchesRfc8448()
    {
        // RFC 8448 section 3: early secret = HKDF-Extract(0, 0^32), then Derive-Secret(., "derived", "").
        var early = HMACSHA256.HashData(new byte[32], new byte[32]);
        Assert.Equal("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a", ToHex(early));
        var derived = Tls13Exporter.HkdfExpandLabel("sha256", early, "derived", SHA256.HashData(Array.Empty<byte>()), 32);
        Assert.Equal("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba", ToHex(derived));
    }
}

/// <summary>
/// The RFC 8446 section 7.5 exporter, written out in full so the exporter step is checked
/// without a TLS stack ("sha256" for the AES-128-GCM and ChaCha20 suites, "sha384" for
/// AES-256-GCM):
///   TLS-Exporter(label, context, L) =
///     HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""), "exporter", Hash(context), L)
/// </summary>
internal static class Tls13Exporter
{
    public static byte[] Export(string hash, byte[] exporterMasterSecret, string label, byte[] context, int length)
    {
        var derived = HkdfExpandLabel(hash, exporterMasterSecret, label, HashOf(hash, Array.Empty<byte>()), HashLength(hash));
        return HkdfExpandLabel(hash, derived, "exporter", HashOf(hash, context), length);
    }

    /// <summary>HKDF-Expand-Label(Secret, Label, Context, Length) with the "tls13 " prefix (RFC 8446 section 7.1).</summary>
    public static byte[] HkdfExpandLabel(string hash, byte[] secret, string label, byte[] context, int length)
    {
        var fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + fullLabel.Length + 1 + context.Length];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)fullLabel.Length;
        fullLabel.CopyTo(info, 3);
        info[3 + fullLabel.Length] = (byte)context.Length;
        context.CopyTo(info, 4 + fullLabel.Length);
        return HkdfExpand(hash, secret, info, length);
    }

    /// <summary>HKDF-Expand (RFC 5869): T(i) = HMAC(PRK, T(i-1) || info || i).</summary>
    public static byte[] HkdfExpand(string hash, byte[] prk, byte[] info, int length)
    {
        using HMAC hmac = hash == "sha384" ? new HMACSHA384(prk) : new HMACSHA256(prk);
        var output = new byte[length];
        var previous = Array.Empty<byte>();
        var written = 0;
        for (byte counter = 1; written < length; counter++)
        {
            var block = hmac.ComputeHash(previous.Concat(info).Append(counter).ToArray());
            var take = Math.Min(block.Length, length - written);
            Array.Copy(block, 0, output, written, take);
            written += take;
            previous = block;
        }
        return output;
    }

    private static byte[] HashOf(string hash, byte[] data) => hash == "sha384" ? SHA384.HashData(data) : SHA256.HashData(data);
    private static int HashLength(string hash) => hash == "sha384" ? 48 : 32;
}
