// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Text;
using System.Text.Json;
using Xunit;

namespace Privasys.RaTls.Tests;

/// <summary>The platform identity read from the quote itself (tests/vectors/ratls-v2/platform.json) and its reconciliation with the server's report.</summary>
public class PlatformIdentityTests
{
    private static readonly JsonElement Vector = JsonDocument.Parse(File.ReadAllText(
        Path.Combine(RepoRoot(), "tests", "vectors", "ratls-v2", "platform.json"))).RootElement;

    private static string RepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(dir, "oids.json"))) dir = Path.GetDirectoryName(dir) ?? throw new DirectoryNotFoundException("repo root");
        return dir;
    }

    private static string V(string name) => Vector.GetProperty(name).GetString()!;

    private static byte[] QuoteWithChain()
        => Enumerable.Repeat((byte)0x11, 632).Concat(Encoding.ASCII.GetBytes(V("pck_leaf_pem"))).Concat(Enumerable.Repeat((byte)0x22, 8)).ToArray();

    [Fact]
    public void ReadsThePckLeafIdentifiers()
    {
        var p = PlatformIdentity.FromQuote("tdx", QuoteWithChain());
        Assert.NotNull(p);
        Assert.Equal(V("ppid"), p!.Ppid);
        Assert.Equal(V("platform_instance_id"), p.PlatformInstanceId);
        Assert.Equal(V("fmspc"), p.Fmspc);
        Assert.Equal(V("platform_id"), p.PlatformId);
        Assert.Null(PlatformIdentity.FromQuote("sgx", Encoding.ASCII.GetBytes("no chain here")));
        // A certificate without the SGX extension is an error, not silently empty.
        var anchorPem = PrivasysTrustAnchors.Load()[0].ExportCertificatePem();
        Assert.Contains("not a PCK certificate", Assert.Throws<RaTlsException>(() => PlatformIdentity.FromQuote("tdx", Encoding.ASCII.GetBytes(anchorPem))).Message);
    }

    [Fact]
    public void ReadsTheSevSnpChipId()
    {
        var snp = Vector.GetProperty("sev_snp");
        var report = new byte[snp.GetProperty("report_size").GetInt32()];
        var chip = snp.GetProperty("chip_id").GetString()!;
        Convert.FromHexString(chip).CopyTo(report, snp.GetProperty("chip_id_offset").GetInt32());
        var p = PlatformIdentity.FromQuote("sev-snp", report);
        Assert.Equal(chip, p!.ChipId);
        Assert.Equal(chip, p.PlatformId);
        Assert.Throws<RaTlsException>(() => PlatformIdentity.FromQuote("sev-snp", report[..100]));
    }

    [Fact]
    public void TheQuoteIsAuthoritativeAndCrossChecked()
    {
        var quote = QuoteWithChain();
        // The server agrees: the quote's identity is used and marked so.
        var agreeing = PlatformAllowList.ApplyLocal(new QuoteVerificationResult(QuoteVerificationStatus.Ok, PlatformInstanceId: V("platform_instance_id"), Ppid: V("ppid")), "tdx", quote);
        Assert.True(agreeing.PlatformFromQuote);
        Assert.Equal(V("fmspc"), agreeing.Fmspc);
        // An older server that reported nothing: the quote fills in and is enforced.
        var old = PlatformAllowList.ApplyLocal(new QuoteVerificationResult(QuoteVerificationStatus.Ok), "tdx", quote);
        Assert.Equal(V("platform_id"), old.PlatformId);
        PlatformAllowList.Check(old, new[] { V("platform_id") });
        Assert.Throws<RaTlsException>(() => PlatformAllowList.Check(old, new[] { "0000" }));
        // A server that disagrees with the quote is an error.
        var liar = new QuoteVerificationResult(QuoteVerificationStatus.Ok, PlatformInstanceId: "c055fc7b49bd4185dda796bf1795af32", Ppid: V("ppid"));
        Assert.Contains("platform identity mismatch", Assert.Throws<RaTlsException>(() => PlatformAllowList.ApplyLocal(liar, "tdx", quote)).Message);
        // An opaque quote leaves the server's report in place.
        var opaque = PlatformAllowList.ApplyLocal(liar, "tdx", Encoding.ASCII.GetBytes("opaque"));
        Assert.False(opaque.PlatformFromQuote);
        Assert.Equal("c055fc7b49bd4185dda796bf1795af32", opaque.PlatformId);
    }
}
