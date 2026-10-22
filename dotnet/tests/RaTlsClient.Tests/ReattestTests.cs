// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Text;
using Privasys.RaTls.BouncyCastle;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>A re-attestation that fails closes the connection, as Connect does: a caller that
/// catches the error and carries on sends nothing.</summary>
public class ReattestTests
{
    private static readonly byte[] AppId = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

    private static readonly VerificationPolicy TdxPolicy = new(TeeType.Tdx,
        MrTd: Rep(0xAA, 48), Rtmr1: Rep(0xB1, 48), Rtmr2: Rep(0xB2, 48),
        ExpectedOids: new[] { new ExpectedOid(Oids.WorkloadAppID, AppId) });

    [Fact]
    public void FailedReattestClosesTheConnection()
    {
        using var chain = MakeChain(new[]
        {
            PrivasysExt(Oids.ImageProfile, "production"),
            PrivasysExt(Oids.WorkloadAppID, AppId),
        });
        using var server = new BcFakeServer(chain);
        server.Start();
        using var client = new RaTlsClient("127.0.0.1", server.Port,
            new RaTlsClientOptions { TrustAnchors = chain.Anchors, TimeoutMs = 10_000 }.UseBouncyCastle());
        client.Connect();
        client.VerifyCertificate(TdxPolicy);

        server.Handler = _ => (500, "{\"v\":2,\"error\":\"evidence unavailable\"}");
        Assert.Throws<RaTlsException>(() => client.Reattest());

        Assert.Throws<InvalidOperationException>(() => client.HttpDo("POST", "/after-failure", Encoding.UTF8.GetBytes("must not be sent")));
        Assert.Throws<InvalidOperationException>(() => client.Healthz());
        Assert.DoesNotContain("/after-failure", server.Paths);
        Assert.DoesNotContain("/healthz", server.Paths);
    }
}
