// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Security.Cryptography;
using System.Text;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>report_data recipes (docs/ratls-v2.md section 3.5), quote_time bounds, quote layouts.</summary>
public class RecipeTests
{
    private static readonly byte[] Spki = Rep(7, 91);
    private static readonly byte[] Gpu = Encoding.ASCII.GetBytes("PGAE gpu evidence envelope");

    private static byte[] Sha512(params byte[][] parts) => SHA512.HashData(parts.SelectMany(p => p).ToArray());

    [Fact]
    public void DeterministicRecipe()
    {
        var ev = new Evidence { Mode = AttestationMode.Deterministic, QuoteTimeRaw = "2026-09-04T10:15Z" };
        var want = Sha512(SHA256.HashData(Spki), Encoding.ASCII.GetBytes("2026-09-04T10:15Z"));
        Assert.Equal(want, RaTlsVerifier.ExpectedReportData(Spki, ev));
        ev.GpuEvidence = Gpu;
        want = Sha512(SHA256.HashData(Spki), Encoding.ASCII.GetBytes("2026-09-04T10:15Z"), SHA256.HashData(Gpu));
        Assert.Equal(want, RaTlsVerifier.ExpectedReportData(Spki, ev));
    }

    [Fact]
    public void ChallengeRecipeAndGpuFold()
    {
        var ctx = Rep(0xC0, 32);
        var hctx = Rep(0xE1, 32);
        var ev = new Evidence { Mode = AttestationMode.Challenge, Context = ctx, Hctx = hctx };
        var want = Sha512(SHA256.HashData(Spki), ctx, hctx);
        Assert.Equal(want, RaTlsVerifier.ExpectedReportData(Spki, ev));
        // GPU fold: SHA-256(gpu_evidence) appended after the binding.
        ev.GpuEvidence = Gpu;
        want = Sha512(SHA256.HashData(Spki), ctx, hctx, SHA256.HashData(Gpu));
        Assert.Equal(want, RaTlsVerifier.ExpectedReportData(Spki, ev));
        // The client recipe of the mutual leg coincides with the server one.
        Assert.Equal(want, RaTlsVerifier.ClientReportData(Spki, ctx, hctx, Gpu));
        Assert.Equal(RaTlsVerifier.ExpectedReportData(Spki, new Evidence { Mode = AttestationMode.Challenge, Context = ctx, Hctx = hctx }),
            RaTlsVerifier.ClientReportData(Spki, ctx, hctx, null));
    }

    [Fact]
    public void MalformedEvidenceNeverYieldsAValue()
    {
        var ctx = Rep(0xC0, 32);
        var hctx = Rep(0xE1, 32);
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.ExpectedReportData(Spki, new Evidence { Mode = AttestationMode.Challenge, Context = ctx[..31], Hctx = hctx }));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.ExpectedReportData(Spki, new Evidence { Mode = AttestationMode.Challenge, Context = ctx, Hctx = null }));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.ExpectedReportData(Spki, new Evidence { Mode = AttestationMode.Deterministic }));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.ExpectedReportData(Spki, new Evidence { Mode = AttestationMode.Deterministic, QuoteTimeRaw = "2026-09-04T10:15:00Z" }));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.ExpectedReportData(Spki, new Evidence { Mode = AttestationMode.None }));
    }

    [Fact]
    public void CheckQuoteTimeBounds()
    {
        var now = new DateTime(2026, 9, 4, 12, 0, 0, DateTimeKind.Utc);
        Assert.Equal(new DateTime(2026, 9, 4, 11, 59, 0, DateTimeKind.Utc), RaTlsVerifier.CheckQuoteTime("2026-09-04T11:59Z", now));
        RaTlsVerifier.CheckQuoteTime("2026-09-03T12:03Z", now); // 23h57m old: within 24h + skew
        RaTlsVerifier.CheckQuoteTime("2026-09-04T12:04Z", now); // 4 minutes ahead: within skew
        Assert.Contains("older than 24 hours", Assert.Throws<RaTlsException>(() => RaTlsVerifier.CheckQuoteTime("2026-09-03T11:50Z", now)).Message);
        Assert.Contains("in the future", Assert.Throws<RaTlsException>(() => RaTlsVerifier.CheckQuoteTime("2026-09-04T12:06Z", now)).Message);
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.CheckQuoteTime("2026-09-04T12:00:00Z", now));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.CheckQuoteTime("2026-09-04 12:00Z", now));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.CheckQuoteTime("", now));
    }

    [Fact]
    public void QuoteReportDataPerFamily()
    {
        var rd = Rep(0xD0, 64);
        Assert.Equal(rd, RaTlsVerifier.QuoteReportData("tdx", TdxQuoteWith(rd)));
        Assert.Equal(rd, RaTlsVerifier.QuoteReportData("tdx-gpu", TdxQuoteWith(rd)));
        Assert.Equal(rd, RaTlsVerifier.QuoteReportData("sgx", SgxQuoteWith(rd)));
        // Raw SGX report (no DCAP header): report_data at 320.
        var report = new byte[432];
        rd.CopyTo(report, SgxQuoteLayout.ReportReportDataOff);
        Assert.Equal(SgxQuoteFormat.RawReport, SgxQuoteLayout.DetectFormat(report));
        Assert.Equal(rd, RaTlsVerifier.QuoteReportData("sgx", report));
        var snp = new byte[SevSnpReportLayout.MinSize];
        rd.CopyTo(snp, SevSnpReportLayout.ReportDataOff);
        Assert.Equal(rd, RaTlsVerifier.QuoteReportData("sev-snp", snp));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.QuoteReportData("tdx", new byte[100]));
        Assert.Throws<RaTlsException>(() => RaTlsVerifier.QuoteReportData("nvidia-gpu", TdxQuoteWith(rd)));
    }

    [Fact]
    public void TeeFamilies()
    {
        Assert.Equal(TeeType.Sgx, RaTlsVerifier.TeeTypeOf("sgx"));
        Assert.Equal(TeeType.Tdx, RaTlsVerifier.TeeTypeOf("tdx"));
        Assert.Equal(TeeType.Tdx, RaTlsVerifier.TeeTypeOf("tdx-gpu"));
        Assert.Equal(TeeType.SevSnp, RaTlsVerifier.TeeTypeOf("sev-snp"));
        Assert.Null(RaTlsVerifier.TeeTypeOf("nvidia-gpu"));
        Assert.Equal("sev-snp", RaTlsVerifier.TeeName(TeeType.SevSnp));
        Assert.Equal("challenge", AttestationMode.Challenge.ToWire());
        Assert.Equal("none", AttestationMode.None.ToWire());
    }

    [Fact]
    public void HeaderIdentityHctxIsTheDomainHash()
    {
        Assert.Equal(SHA256.HashData(Encoding.ASCII.GetBytes("privasys-ratls-attest-v2-header-identity")), RaTlsAttest.HeaderIdentityHctx);
    }
}
