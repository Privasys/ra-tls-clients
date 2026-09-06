// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Text;
using Privasys.RaTls.BouncyCastle;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>
/// The Bouncy Castle transport end to end against a Bouncy Castle loopback server with the
/// real exporter: challenge mode, re-attestation, the mutual leg, trust modes, and interop
/// with the SslStream transport in both directions.
/// </summary>
public class BouncyCastleTests
{
    private static readonly byte[] AppId = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] CallerAppId = Enumerable.Range(17, 16).Select(i => (byte)i).ToArray();

    private static readonly VerificationPolicy TdxPolicy = new(TeeType.Tdx,
        MrTd: Rep(0xAA, 48), Rtmr1: Rep(0xB1, 48), Rtmr2: Rep(0xB2, 48),
        ExpectedOids: new[] { new ExpectedOid(Oids.WorkloadAppID, AppId) });

    private static Chain EnclaveChain(byte[]? appId = null) => MakeChain(new[]
    {
        PrivasysExt(Oids.ImageProfile, "production"),
        PrivasysExt(Oids.WorkloadAppID, appId ?? AppId),
    });

    private static RaTlsClient Client(BcFakeServer server, Chain chain, Action<RaTlsClientOptions>? configure = null)
    {
        var options = new RaTlsClientOptions { TrustAnchors = chain.Anchors, Framing = server.Framing, TimeoutMs = 10_000 }.UseBouncyCastle();
        configure?.Invoke(options);
        return new RaTlsClient("127.0.0.1", server.Port, options);
    }

    private static string QuoteTimeNow() => DateTime.UtcNow.ToString(RaTlsAttest.QuoteTimeLayout, System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>Connects, and on failure names the server-side error too (a TLS alert alone says little).</summary>
    private static void Connect(RaTlsClient client, BcFakeServer server)
    {
        try { client.Connect(); }
        catch (Exception e)
        {
            for (var i = 0; i < 20 && server.Error is null; i++) Thread.Sleep(50);
            if (server.Error is not null) throw new Exception($"client: {e.Message}; server: {server.Error}", e);
            throw;
        }
    }

    /// <summary>A client evidence source: a fake TDX quote carrying the requested report_data.</summary>
    private static ClientEvidence CallerEvidence(ClientEvidenceRequest req)
    {
        Assert.Equal(RaTlsAttest.ContextLen, req.Context.Length);
        Assert.Equal(RaTlsAttest.HctxLen, req.Hctx.Length);
        Assert.Equal(RaTlsVerifier.ClientReportData(req.SpkiDer, req.Context, req.Hctx, null), req.ReportData);
        return new ClientEvidence("tdx", TdxQuoteWith(req.ReportData), null, QuoteTimeNow());
    }

    [Fact]
    public void UseBouncyCastleSelectsTheTransportAndChallenge()
    {
        var o = new RaTlsClientOptions().UseBouncyCastle();
        Assert.Equal(AttestationMode.Challenge, o.Attestation);
        Assert.IsType<BouncyCastleTransport>(o.Transport!());
        Assert.True(o.Transport!().SupportsExporter);
        Assert.Equal(AttestationMode.Deterministic, new RaTlsClientOptions().UseBouncyCastle(AttestationMode.Deterministic).Attestation);
        Assert.False(SslStreamTransport.Create().SupportsExporter);
        Assert.Throws<NotSupportedException>(() => SslStreamTransport.Create().ExportKeyingMaterial("x", new byte[32], 32));
    }

    [Fact]
    public void ChallengeOverHttp()
    {
        using var chain = EnclaveChain();
        using var server = new BcFakeServer(chain);
        server.Start();
        using var client = Client(server, chain);
        Connect(client, server);
        Assert.Null(server.Error);

        Assert.IsType<BouncyCastleTransport>(client.Transport);
        Assert.Equal("Tls13", client.TlsVersion);
        Assert.StartsWith("TLS_", client.CipherSuite);
        Assert.Equal(TrustMode.Fleet, client.TrustResolved);
        Assert.Equal("challenge", client.AttestationTag);
        Assert.Equal("challenge", server.RecordedTag);
        var ev = client.Evidence!;
        Assert.Equal(RaTlsAttest.ContextLen, ev.Context!.Length);
        Assert.Equal(RaTlsAttest.HctxLen, ev.Hctx!.Length);
        // Both ends derive the same exporter value: the binding is the connection's.
        Assert.Equal(server.Export(RaTlsAttest.ExporterLabelServer, ev.Context), ev.Hctx);
        Assert.Equal(ev.Hctx, client.Transport!.ExportKeyingMaterial(RaTlsAttest.ExporterLabelServer, ev.Context, 32));

        var info = client.VerifyCertificate(TdxPolicy);
        Assert.Equal(AttestationMode.Challenge, info.Attestation);
        Assert.Equal(chain.Leaf.Thumbprint, client.PeerCertificate!.Thumbprint);
        Assert.Equal(2, client.PeerCertificates.Count);

        var health = client.Healthz();
        Assert.Equal("challenge", health["attestation"].GetString());
        var (status, echoed) = client.HttpDo("POST", "/data", Encoding.UTF8.GetBytes("{\"x\":1}"));
        Assert.Equal(200, status);
        Assert.Equal("{\"x\":1}", Encoding.UTF8.GetString(echoed));

        // Re-attestation: a fresh context, verified against the last policy.
        var first = ev.Context.ToArray();
        Assert.NotNull(client.Reattest());
        Assert.NotEqual(first, client.Evidence!.Context);
        Assert.Equal(2, server.AttestCount);
        Assert.Contains("MRTD mismatch", Assert.Throws<RaTlsException>(() => client.VerifyCertificate(TdxPolicy with { MrTd = Rep(1, 48) })).Message);
    }

    [Fact]
    public void ChallengeOverRawFrames()
    {
        using var chain = EnclaveChain();
        using var server = new BcFakeServer(chain, AttestFraming.Raw);
        server.Start();
        using var client = Client(server, chain);
        client.Connect();
        Assert.Null(server.Error);
        Assert.Equal("challenge", client.AttestationTag);
        client.VerifyCertificate(TdxPolicy);
        client.SendFrame(Encoding.ASCII.GetBytes("kmip"));
        Assert.Equal("kmip", Encoding.ASCII.GetString(client.ReceiveFrame()));
        Assert.Contains("reconnect", Assert.Throws<RaTlsException>(() => client.Reattest()).Message);
    }

    [Fact]
    public void RelayedContextIsUsedOnce()
    {
        using var chain = EnclaveChain();
        using var server = new BcFakeServer(chain);
        server.Start();
        var relayed = Rep(0xC0, 32);
        using var client = Client(server, chain, o => o.Context = relayed);
        client.Connect();
        Assert.Equal(relayed, client.Evidence!.Context);
        client.VerifyCertificate(TdxPolicy);
        client.Reattest();
        Assert.NotEqual(relayed, client.Evidence!.Context);
    }

    [Theory]
    [InlineData(AttestFraming.Http)]
    [InlineData(AttestFraming.Raw)]
    public void MutualLeg(AttestFraming framing)
    {
        using var chain = EnclaveChain();
        using var caller = EnclaveChain(CallerAppId);
        using var server = new BcFakeServer(chain, framing, requireClientEvidence: true);
        server.Start();
        using var client = Client(server, chain, o =>
        {
            o.ClientCertificate = caller.Leaf;
            o.ClientEvidence = CallerEvidence;
        });
        client.Connect();
        Assert.Null(server.Error);
        Assert.True(client.Evidence!.ClientEvidenceRequired);
        Assert.Equal(RaTlsAttest.ContextLen, client.Evidence.ClientContext!.Length);
        Assert.True(server.Presented);
        Assert.Equal(caller.Leaf.RawData, server.ClientLeafDer);
        client.VerifyCertificate(TdxPolicy);
        if (framing == AttestFraming.Http)
            Assert.Equal("challenge", client.Healthz()["attestation"].GetString());
        else
        {
            client.SendFrame(new byte[] { 1, 2, 3 });
            Assert.Equal(new byte[] { 1, 2, 3 }, client.ReceiveFrame());
        }
    }

    [Fact]
    public void MutualLegFailsClosed()
    {
        using var chain = EnclaveChain();
        using var caller = EnclaveChain(CallerAppId);

        using (var server = new BcFakeServer(chain, requireClientEvidence: true))
        {
            server.Start();
            using var client = Client(server, chain, o => o.ClientCertificate = caller.Leaf);
            Assert.Contains("ClientEvidence is not set", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }
        using (var server = new BcFakeServer(chain, requireClientEvidence: true))
        {
            server.Start();
            using var client = Client(server, chain, o => o.ClientEvidence = CallerEvidence);
            Assert.Contains("no client certificate", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }
        using (var server = new BcFakeServer(chain, requireClientEvidence: true))
        {
            server.Start();
            using var client = Client(server, chain, o =>
            {
                o.ClientCertificate = caller.Leaf;
                o.ClientEvidence = _ => new ClientEvidence("tdx", Array.Empty<byte>(), null, QuoteTimeNow());
            });
            Assert.Contains("returned no quote", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }
        // A quote minted for another key: the server verifies report_data and refuses.
        using (var server = new BcFakeServer(chain, requireClientEvidence: true))
        {
            server.Start();
            using var client = Client(server, chain, o =>
            {
                o.ClientCertificate = caller.Leaf;
                o.ClientEvidence = _ => new ClientEvidence("tdx", TdxQuoteWith(Rep(1, 64)), null, QuoteTimeNow());
            });
            Assert.Contains("client evidence rejected (403)", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
            Assert.False(server.Presented);
        }
        using (var server = new BcFakeServer(chain, AttestFraming.Raw, requireClientEvidence: true))
        {
            server.Start();
            using var client = Client(server, chain, o =>
            {
                o.ClientCertificate = caller.Leaf;
                o.ClientEvidence = _ => new ClientEvidence("tdx", TdxQuoteWith(Rep(1, 64)), null, QuoteTimeNow());
            });
            Assert.Contains("client evidence rejected", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }
    }

    [Fact]
    public void DeterministicOnBouncyCastle()
    {
        using var chain = EnclaveChain();
        using var server = new BcFakeServer(chain);
        server.Start();
        using var client = Client(server, chain, o => o.Attestation = AttestationMode.Deterministic);
        client.Connect();
        Assert.Equal("deterministic", client.AttestationTag);
        client.VerifyCertificate(TdxPolicy);
        client.Reattest();
        Assert.Equal(2, server.AttestCount);
    }

    [Fact]
    public void InteropWithTheSslStreamTransportInBothDirections()
    {
        using var chain = EnclaveChain();
        // Bouncy Castle client, SslStream server: deterministic (the SslStream server has no exporter).
        using (var server = new FakeServer(chain))
        {
            server.Start();
            using var bc = new RaTlsClient("127.0.0.1", server.Port, new RaTlsClientOptions { TrustAnchors = chain.Anchors }.UseBouncyCastle(AttestationMode.Deterministic));
            bc.Connect();
            Assert.Null(server.Error);
            Assert.Equal("deterministic", bc.AttestationTag);
            bc.VerifyCertificate(TdxPolicy);
            Assert.Equal("deterministic", bc.Healthz()["attestation"].GetString());
        }
        // SslStream client, Bouncy Castle server: deterministic, and challenge with a caller-supplied exporter is impossible here, so deterministic only.
        using (var server = new BcFakeServer(chain))
        {
            server.Start();
            using var ssl = new RaTlsClient("127.0.0.1", server.Port, new RaTlsClientOptions { TrustAnchors = chain.Anchors });
            ssl.Connect();
            Assert.Null(server.Error);
            Assert.IsType<SslStreamTransport>(ssl.Transport);
            Assert.Equal("deterministic", ssl.AttestationTag);
            ssl.VerifyCertificate(TdxPolicy);
            Assert.Equal("deterministic", ssl.Healthz()["attestation"].GetString());
        }
    }

    [Fact]
    public void UntrustedChainFailsTheHandshake()
    {
        using var chain = EnclaveChain();
        using var otherFleet = MakeChain();
        using var server = new BcFakeServer(chain);
        server.Start();
        using var client = new RaTlsClient("127.0.0.1", server.Port, new RaTlsClientOptions { TrustAnchors = otherFleet.Anchors }.UseBouncyCastle());
        var e = Assert.Throws<RaTlsException>(() => client.Connect());
        Assert.Contains("fleet anchor", e.Message);
        Assert.Null(client.TrustResolved);
        Assert.Equal(0, server.AttestCount);
    }

    [Fact]
    public void TrustModesOnBouncyCastle()
    {
        using var chain = EnclaveChain();
        using var selfSigned = MakeSelfSigned();
        // Auto without evidence accepts the fleet chain.
        using (var server = new BcFakeServer(chain))
        {
            server.Start();
            using var client = Client(server, chain, o => o.Attestation = AttestationMode.None);
            client.Connect();
            Assert.Null(server.Error);
            Assert.Equal(TrustMode.Fleet, client.TrustResolved);
            Assert.Equal("none", client.Healthz()["attestation"].GetString());
            Assert.Equal(0, server.AttestCount);
        }
        // Auto without evidence: a self-signed server reaches neither the fleet nor a public root.
        using (var server = new BcFakeServer(selfSigned))
        {
            server.Start();
            using var client = new RaTlsClient("127.0.0.1", server.Port, new RaTlsClientOptions { TrustAnchors = chain.Anchors }.UseBouncyCastle(AttestationMode.None));
            var e = Assert.Throws<RaTlsException>(() => client.Connect());
            Assert.Contains("reaches neither", e.Message);
            Assert.Contains("public PKI verification failed", e.Message);
        }
        // Public only: the public verdict alone.
        using (var server = new BcFakeServer(selfSigned))
        {
            server.Start();
            using var client = new RaTlsClient("127.0.0.1", server.Port, new RaTlsClientOptions { Trust = TrustMode.Public }.UseBouncyCastle(AttestationMode.None));
            Assert.Contains("public PKI verification failed", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }
        // Attested modes never leave the fleet.
        using (var server = new BcFakeServer(selfSigned))
        {
            server.Start();
            using var client = Client(server, chain);
            Assert.Contains("fleet anchor", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
            Assert.Equal(0, server.AttestCount);
        }
    }

    [Fact]
    public void ServerFailuresCloseTheConnection()
    {
        using var chain = EnclaveChain();
        using (var server = new BcFakeServer(chain) { Handler = _ => (404, "404 page not found") })
        {
            server.Start();
            using var client = Client(server, chain);
            Assert.Contains("no RA-TLS v2 evidence endpoint", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
            Assert.Throws<InvalidOperationException>(() => client.Stream);
        }
        // A quote minted for another connection: report_data does not match this connection's binding.
        using (var server = new BcFakeServer(chain)
        {
            Handler = req => (200, System.Text.Json.JsonSerializer.Serialize(new
            {
                v = 2, mode = "challenge", tee = "tdx", quote = Base64Url.Encode(TdxQuoteWith(Rep(1, 64))), gpu_evidence = (string?)null,
                quote_time = QuoteTimeNow(), client_evidence = "none",
            })),
        })
        {
            server.Start();
            using var client = Client(server, chain);
            client.Connect();
            Assert.Contains("report_data mismatch", Assert.Throws<RaTlsException>(() => client.VerifyCertificate(TdxPolicy)).Message);
        }
    }
}
