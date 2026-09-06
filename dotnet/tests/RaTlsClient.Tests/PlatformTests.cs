// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>The platform allow-list: the identity precedence, the check, and the whole path through a fake attestation server.</summary>
public class PlatformTests
{
    private const string Piid = "c055fc7b49bd4185dda796bf1795af32";
    private const string Ppid = "414afbe506e8ac361add41f3133aab6f";

    [Fact]
    public void PlatformIdPrecedence()
    {
        Assert.Equal(Piid, new QuoteVerificationResult(QuoteVerificationStatus.Ok, PlatformInstanceId: Piid, Ppid: "aa", ChipId: "cc").PlatformId);
        Assert.Equal("aa", new QuoteVerificationResult(QuoteVerificationStatus.Ok, Ppid: "aa", ChipId: "cc").PlatformId);
        Assert.Equal("cc", new QuoteVerificationResult(QuoteVerificationStatus.Ok, ChipId: "cc").PlatformId);
        Assert.Equal("", new QuoteVerificationResult(QuoteVerificationStatus.Ok).PlatformId);
    }

    [Fact]
    public void CheckSemantics()
    {
        var r = new QuoteVerificationResult(QuoteVerificationStatus.Ok, PlatformInstanceId: Piid, Ppid: Ppid);
        PlatformAllowList.Check(r, null);
        PlatformAllowList.Check(r, Array.Empty<string>());
        foreach (var ok in new[] { Piid, Piid.ToUpperInvariant(), "c055fc7b-49bd-4185-dda7-96bf1795af32" })
            PlatformAllowList.Check(r, new[] { "deadbeef", ok });
        // The PPID does not stand in for a reported Platform Instance ID.
        Assert.Throws<RaTlsException>(() => PlatformAllowList.Check(r, new[] { Ppid }));
        Assert.Contains("reported no platform identity", Assert.Throws<RaTlsException>(() => PlatformAllowList.Check(new QuoteVerificationResult(QuoteVerificationStatus.Ok), new[] { Piid })).Message);
        Assert.Contains("not in AllowedPlatformIds", Assert.Throws<RaTlsException>(() => PlatformAllowList.Check(r, new[] { "0000" })).Message);
    }

    /// <summary>A fake attestation server: records the request, reports a platform, enforces the list like the real one.</summary>
    private sealed class FakeAttestationServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly bool _reportsPlatform;
        public string Url { get; }
        public JsonElement? LastRequest { get; private set; }

        public FakeAttestationServer(bool reportsPlatform)
        {
            _reportsPlatform = reportsPlatform;
            var port = FreePort();
            Url = $"http://127.0.0.1:{port}/api/verify";
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            _listener.Start();
            _ = Task.Run(Loop);
        }

        private static int FreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        private async Task Loop()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync(); } catch (Exception) { return; }
                using var reader = new StreamReader(ctx.Request.InputStream);
                var doc = JsonDocument.Parse(await reader.ReadToEndAsync());
                LastRequest = doc.RootElement.Clone();
                var resp = new Dictionary<string, object?> { ["success"] = true, ["status"] = "OK", ["teeType"] = "tdx", ["tcbStatus"] = "UpToDate" };
                if (_reportsPlatform)
                {
                    resp["platform"] = new { ppid = Ppid, platformInstanceId = Piid, fmspc = "00806f050000" };
                    if (doc.RootElement.TryGetProperty("allowedPlatformIds", out var allowed) && allowed.ValueKind == JsonValueKind.Array
                        && !allowed.EnumerateArray().Any(a => string.Equals(a.GetString(), Piid, StringComparison.OrdinalIgnoreCase)))
                    {
                        resp["success"] = false;
                        resp["status"] = "PLATFORM_NOT_ALLOWED";
                        resp["error"] = "platform not in the allow-list";
                    }
                }
                if (doc.RootElement.TryGetProperty("type", out var t) && t.GetString() == "tdx-gpu")
                    resp["gpuAttestation"] = new { verified = true, status = "OK" };
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(resp));
                ctx.Response.ContentType = "application/json";
                ctx.Response.ContentLength64 = bytes.Length;
                await ctx.Response.OutputStream.WriteAsync(bytes);
                ctx.Response.Close();
            }
        }

        public void Dispose() { try { _listener.Stop(); } catch (Exception) { } }
    }

    private static readonly byte[] AppId = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

    private static (X509Certificate2Holder, Evidence) Attested()
    {
        var chain = MakeChain(new[] { PrivasysExt(Oids.ImageProfile, "production"), PrivasysExt(Oids.WorkloadAppID, AppId) });
        var spki = chain.Leaf.PublicKey.ExportSubjectPublicKeyInfo();
        var quoteTime = DateTime.UtcNow.ToString(RaTlsAttest.QuoteTimeLayout, System.Globalization.CultureInfo.InvariantCulture);
        var ev = new Evidence { Mode = AttestationMode.Deterministic, Tee = "tdx", QuoteTimeRaw = quoteTime, QuoteTime = DateTime.UtcNow };
        ev.Quote = TdxQuoteWith(RaTlsVerifier.ExpectedReportData(spki, ev));
        return (new X509Certificate2Holder(chain), ev);
    }

    private sealed class X509Certificate2Holder : IDisposable
    {
        public Chain Chain { get; }
        public X509Certificate2Holder(Chain chain) { Chain = chain; }
        public void Dispose() => Chain.Dispose();
    }

    private static VerificationPolicy Policy(string endpoint, params string[] allowed) => new(TeeType.Tdx,
        MrTd: Rep(0xAA, 48), Rtmr1: Rep(0xB1, 48), Rtmr2: Rep(0xB2, 48),
        QuoteVerification: new QuoteVerificationConfig(endpoint),
        AllowedPlatformIds: allowed.Length == 0 ? null : allowed);

    [Fact]
    public void VerifyEvidenceReportsAndEnforcesThePlatform()
    {
        using var server = new FakeAttestationServer(reportsPlatform: true);
        var (holder, ev) = Attested();
        using var keep = holder;
        var leaf = holder.Chain.Leaf;

        // No list: reported, not enforced, and nothing sent.
        var info = RaTlsVerifier.VerifyEvidence(leaf, ev, Policy(server.Url));
        Assert.Equal(Piid, info.QuoteVerification!.PlatformId);
        Assert.Equal("00806f050000", info.QuoteVerification.Fmspc);
        Assert.False(server.LastRequest!.Value.TryGetProperty("allowedPlatformIds", out _));

        // On the list (any case): the list is sent and the platform passes.
        RaTlsVerifier.VerifyEvidence(leaf, ev, Policy(server.Url, "0000", Piid.ToUpperInvariant()));
        Assert.Equal(2, server.LastRequest!.Value.GetProperty("allowedPlatformIds").GetArrayLength());

        // Off the list: the server refuses and the client agrees.
        var e = Assert.Throws<RaTlsException>(() => RaTlsVerifier.VerifyEvidence(leaf, ev, Policy(server.Url, "0000")));
        Assert.Contains("PLATFORM_NOT_ALLOWED", e.Message);

        // A list without a verifier is refused before anything is looked at.
        var gate = Assert.Throws<RaTlsException>(() => RaTlsVerifier.VerifyEvidence(leaf, ev, new VerificationPolicy(TeeType.Tdx, AllowedPlatformIds: new[] { Piid })));
        Assert.Contains("needs QuoteVerification", gate.Message);
    }

    [Fact]
    public void AnOlderServerWithoutPlatformIdentityFailsClosedAgainstAList()
    {
        using var server = new FakeAttestationServer(reportsPlatform: false);
        var (holder, ev) = Attested();
        using var keep = holder;
        var leaf = holder.Chain.Leaf;
        var info = RaTlsVerifier.VerifyEvidence(leaf, ev, Policy(server.Url));
        Assert.Equal("", info.QuoteVerification!.PlatformId);
        var e = Assert.Throws<RaTlsException>(() => RaTlsVerifier.VerifyEvidence(leaf, ev, Policy(server.Url, Piid)));
        Assert.Contains("reported no platform identity", e.Message);
    }
}
