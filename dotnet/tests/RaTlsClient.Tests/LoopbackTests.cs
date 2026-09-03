// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Text;
using System.Text.Json;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>The whole client flow against the loopback server: handshake, chain check, exchange, verification, tag, re-attestation.</summary>
public class LoopbackTests
{
    private static readonly byte[] AppId = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

    private static readonly VerificationPolicy TdxPolicy = new(TeeType.Tdx,
        MrTd: Rep(0xAA, 48), Rtmr1: Rep(0xB1, 48), Rtmr2: Rep(0xB2, 48),
        ExpectedOids: new[] { new ExpectedOid(Oids.WorkloadAppID, AppId) });

    private static Chain EnclaveChain() => MakeChain(new[]
    {
        PrivasysExt(Oids.ImageProfile, "production"),
        PrivasysExt(Oids.WorkloadAppID, AppId),
    });

    private static RaTlsClient Client(FakeServer server, Chain chain, Action<RaTlsClientOptions>? configure = null)
    {
        var options = new RaTlsClientOptions { TrustAnchors = chain.Anchors, Framing = server.Framing, TimeoutMs = 10_000 };
        configure?.Invoke(options);
        return new RaTlsClient("127.0.0.1", server.Port, options);
    }

    [Fact]
    public void DeterministicOverHttp()
    {
        using var chain = EnclaveChain();
        using var server = new FakeServer(chain);
        server.Start();
        using var client = Client(server, chain);
        client.Connect();
        Assert.Null(server.Error);

        Assert.Equal("Tls13", client.TlsVersion);
        Assert.Equal(AttestationMode.Deterministic, client.AttestationMode);
        Assert.Equal("deterministic", client.AttestationTag);
        Assert.Equal("deterministic", server.RecordedTag);
        Assert.NotNull(client.Evidence);
        Assert.Equal("tdx", client.Evidence!.Tee);
        Assert.Equal(17, client.Evidence.QuoteTimeRaw.Length);

        var unverified = client.InspectCertificate();
        Assert.Equal(AttestationMode.Deterministic, unverified.Attestation);
        Assert.NotNull(unverified.Quote);
        Assert.Null(unverified.QuoteVerification);

        var info = client.VerifyCertificate(TdxPolicy);
        Assert.Equal(AttestationMode.Deterministic, info.Attestation);
        Assert.Same(client.Evidence, info.Evidence);
        Assert.Equal(chain.Leaf.Thumbprint, client.PeerCertificate!.Thumbprint);

        // The workload sees the tag; /healthz is chunked to exercise the decoder.
        var health = client.Healthz();
        Assert.Equal("ok", health["status"].GetString());
        Assert.Equal("deterministic", health["attestation"].GetString());
        var (status, echoed) = client.HttpDo("POST", "/data", Encoding.UTF8.GetBytes("{\"x\":1}"));
        Assert.Equal(200, status);
        Assert.Equal("{\"x\":1}", Encoding.UTF8.GetString(echoed));

        // Re-attestation on the same connection re-verifies against the last policy.
        var again = client.Reattest();
        Assert.NotNull(again);
        Assert.Equal(2, server.AttestCount);
        Assert.Contains("MRTD mismatch", Assert.Throws<RaTlsException>(() => client.VerifyCertificate(TdxPolicy with { MrTd = Rep(1, 48) })).Message);
    }

    [Fact]
    public void DeterministicOverRawFrames()
    {
        using var chain = EnclaveChain();
        using var server = new FakeServer(chain, AttestFraming.Raw);
        server.Start();
        using var client = Client(server, chain);
        client.Connect();
        Assert.Null(server.Error);
        Assert.Equal("deterministic", client.AttestationTag);
        client.VerifyCertificate(TdxPolicy);
        // The protocol after the exchange: frames echoed by the server.
        client.SendFrame(Encoding.ASCII.GetBytes("kmip"));
        Assert.Equal("kmip", Encoding.ASCII.GetString(client.ReceiveFrame()));
        Assert.Contains("reconnect", Assert.Throws<RaTlsException>(() => client.Reattest()).Message);
    }

    [Fact]
    public void ChallengeWithASuppliedExporter()
    {
        using var chain = EnclaveChain();
        using var server = new FakeServer(chain);
        server.Start();
        var relayed = Rep(0xC0, 32);
        using var client = Client(server, chain, o =>
        {
            o.Attestation = AttestationMode.Challenge;
            o.Exporter = StubExporter;
            o.Context = relayed; // a context chosen elsewhere, relayed verbatim
        });
        client.Connect();
        Assert.Null(server.Error);
        Assert.Equal("challenge", client.AttestationTag);
        Assert.Equal("challenge", server.RecordedTag);
        Assert.Equal(relayed, client.Evidence!.Context);
        Assert.Equal(StubExporter(RaTlsAttest.ExporterLabelServer, relayed, 32), client.Evidence.Hctx);
        var info = client.VerifyCertificate(TdxPolicy);
        Assert.Equal(AttestationMode.Challenge, info.Attestation);
        // A fresh context each time.
        var first = client.Evidence.Context.ToArray();
        client.Reattest();
        Assert.NotEqual(first, client.Evidence!.Context);
        Assert.Equal(2, server.AttestCount);
    }

    [Fact]
    public void ChallengeWithoutAnExporterIsNotSupported()
    {
        using var chain = EnclaveChain();
        using var server = new FakeServer(chain);
        server.Start();
        using var client = Client(server, chain, o => o.Attestation = AttestationMode.Challenge);
        var e = Assert.Throws<NotSupportedException>(() => client.Connect());
        Assert.Contains("exporter", e.Message);
        Assert.Contains("Deterministic", e.Message);
        Assert.Equal(0, server.AttestCount);

        using var server2 = new FakeServer(chain);
        server2.Start();
        using var badContext = Client(server2, chain, o =>
        {
            o.Attestation = AttestationMode.Challenge;
            o.Exporter = StubExporter;
            o.Context = Rep(1, 16);
        });
        Assert.Contains("32 bytes", Assert.Throws<RaTlsException>(() => badContext.Connect()).Message);
    }

    [Fact]
    public void NoneVerifiesExtensionsOnly()
    {
        using var chain = EnclaveChain();
        using var server = new FakeServer(chain);
        server.Start();
        using var client = Client(server, chain, o => o.Attestation = AttestationMode.None);
        client.Connect();
        Assert.Equal("none", client.AttestationTag);
        Assert.Null(client.Evidence);
        var info = client.VerifyCertificate(TdxPolicy);
        Assert.Equal(AttestationMode.None, info.Attestation);
        Assert.Null(info.Quote);
        Assert.Contains("mode none", Assert.Throws<RaTlsException>(() => RaTlsVerifier.VerifyEvidence(client.PeerCertificate!, client.Evidence, TdxPolicy)).Message);
        Assert.Equal("none", client.Healthz()["attestation"].GetString());
        Assert.Equal(0, server.AttestCount);
        Assert.Throws<RaTlsException>(() => client.Reattest());
    }

    [Fact]
    public void ServerFailuresCloseTheConnection()
    {
        using var chain = EnclaveChain();

        using (var server = new FakeServer(chain) { Handler = _ => (404, "404 page not found") })
        {
            server.Start();
            using var client = Client(server, chain);
            Assert.Contains("no RA-TLS v2 evidence endpoint", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
            Assert.Throws<InvalidOperationException>(() => client.Stream);
        }

        using (var server = new FakeServer(chain)
        {
            Handler = req => (200, JsonSerializer.Serialize(new
            {
                v = 2, mode = "challenge", tee = "tdx", quote = Base64Url.Encode(TdxQuoteWith(Rep(1, 64))), gpu_evidence = (string?)null,
                quote_time = DateTime.UtcNow.ToString(RaTlsAttest.QuoteTimeLayout, System.Globalization.CultureInfo.InvariantCulture), client_evidence = "none",
            })),
        })
        {
            server.Start();
            using var client = Client(server, chain);
            Assert.Contains("mode \"challenge\", requested \"deterministic\"", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }

        using (var server = new FakeServer(chain) { Handler = _ => (503, "{\"v\":2,\"error\":\"quote provider unavailable\"}") })
        {
            server.Start();
            using var client = Client(server, chain);
            Assert.Contains("attest failed (503)", Assert.Throws<RaTlsException>(() => client.Connect()).Message);
        }
    }

    [Fact]
    public void WrongReportDataFailsVerification()
    {
        using var chain = EnclaveChain();
        // A server that answers with a quote minted for another key.
        using var server = new FakeServer(chain)
        {
            Handler = req => (200, JsonSerializer.Serialize(new
            {
                v = 2, mode = "deterministic", tee = "tdx", quote = Base64Url.Encode(TdxQuoteWith(Rep(1, 64))), gpu_evidence = (string?)null,
                quote_time = DateTime.UtcNow.ToString(RaTlsAttest.QuoteTimeLayout, System.Globalization.CultureInfo.InvariantCulture), client_evidence = "none",
            })),
        };
        server.Start();
        using var client = Client(server, chain);
        client.Connect();
        Assert.Contains("report_data mismatch", Assert.Throws<RaTlsException>(() => client.VerifyCertificate(TdxPolicy)).Message);
    }

    [Fact]
    public void UntrustedChainFailsTheHandshake()
    {
        using var chain = EnclaveChain();
        using var otherFleet = MakeChain();
        using var server = new FakeServer(chain);
        server.Start();
        using var client = new RaTlsClient("127.0.0.1", server.Port, new RaTlsClientOptions { TrustAnchors = otherFleet.Anchors });
        var e = Assert.Throws<RaTlsException>(() => client.Connect());
        Assert.Contains("fleet anchor", e.Message);
        Assert.Equal(0, server.AttestCount);
    }

    [Fact]
    public void V1LeafIsRejectedByTheVerifier()
    {
        using var chain = MakeChain(new[] { PrivasysExt(Oids.TDXQuote, Encoding.ASCII.GetBytes("  old evidence")) });
        using var server = new FakeServer(chain);
        server.Start();
        using var client = Client(server, chain);
        client.Connect();
        Assert.True(client.InspectCertificate().V1Leaf);
        Assert.Contains("v1", Assert.Throws<RaTlsException>(() => client.VerifyCertificate(new VerificationPolicy(TeeType.Tdx))).Message);
    }
}
