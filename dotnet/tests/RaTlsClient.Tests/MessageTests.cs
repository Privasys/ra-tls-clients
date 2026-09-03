// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;
using static Privasys.RaTls.Tests.TestSupport;

namespace Privasys.RaTls.Tests;

/// <summary>Attest messages (docs/ratls-v2.md sections 3.3 to 3.4), the raw frame binding and base64url.</summary>
public class MessageTests
{
    private static readonly byte[] Spki = Hex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    private static readonly DateTime Now = new(2026, 9, 4, 12, 0, 0, DateTimeKind.Utc);
    private static readonly byte[] Quote = TdxQuoteWith(Rep(0xD0, 64));

    private static string Response(string mode = "deterministic", string? v = "2", string tee = "tdx", string? quote = null,
        string gpu = "null", string quoteTime = "2026-09-04T11:58Z", string? clientEvidence = "\"none\"", string clientContext = "null", string extra = "")
    {
        quote ??= "\"" + Base64Url.Encode(Quote) + "\"";
        var ce = clientEvidence is null ? "" : $",\"client_evidence\":{clientEvidence}";
        return $"{{\"v\":{v},\"mode\":\"{mode}\",\"tee\":\"{tee}\",\"quote\":{quote},\"gpu_evidence\":{gpu},\"quote_time\":\"{quoteTime}\"{ce},\"client_context\":{clientContext}{extra}}}";
    }

    private static Evidence Parse(string body, AttestationMode mode = AttestationMode.Deterministic, int status = 200, byte[]? ctx = null, byte[]? hctx = null)
        => RaTlsAttest.ParseResponse(status, Encoding.UTF8.GetBytes(body), mode, Now, ctx, hctx);

    private static string Reject(string body, AttestationMode mode = AttestationMode.Deterministic, int status = 200)
        => Assert.Throws<RaTlsException>(() => Parse(body, mode, status)).Message;

    [Fact]
    public void RequestBodiesAreCanonical()
    {
        var leaf = Base64Url.Encode(SHA256.HashData(Spki));
        Assert.Equal($"{{\"v\":2,\"mode\":\"deterministic\",\"leaf\":\"{leaf}\"}}",
            Encoding.UTF8.GetString(RaTlsAttest.BuildRequest(AttestationMode.Deterministic, Spki)));
        var ctx = Rep(0xC0, 32);
        Assert.Equal($"{{\"v\":2,\"mode\":\"challenge\",\"leaf\":\"{leaf}\",\"context\":\"{Base64Url.Encode(ctx)}\"}}",
            Encoding.UTF8.GetString(RaTlsAttest.BuildRequest(AttestationMode.Challenge, Spki, ctx)));
        Assert.Equal(43, leaf.Length); // 32 bytes, no padding
        Assert.Throws<ArgumentException>(() => RaTlsAttest.BuildRequest(AttestationMode.Challenge, Spki, Rep(0xC0, 31)));
        Assert.Throws<ArgumentException>(() => RaTlsAttest.BuildRequest(AttestationMode.Challenge, Spki, null));
        Assert.Throws<ArgumentException>(() => RaTlsAttest.BuildRequest(AttestationMode.None, Spki));
    }

    [Fact]
    public void ParsesADeterministicResponse()
    {
        var ev = Parse(Response());
        Assert.Equal(AttestationMode.Deterministic, ev.Mode);
        Assert.Equal("tdx", ev.Tee);
        Assert.Equal(Quote, ev.Quote);
        Assert.Null(ev.GpuEvidence);
        Assert.Equal("2026-09-04T11:58Z", ev.QuoteTimeRaw);
        Assert.Equal(new DateTime(2026, 9, 4, 11, 58, 0, DateTimeKind.Utc), ev.QuoteTime);
        Assert.False(ev.ClientEvidenceRequired);
        Assert.Null(ev.Context);
        // client_evidence absent is "none".
        Assert.False(Parse(Response(clientEvidence: null)).ClientEvidenceRequired);
    }

    [Fact]
    public void ParsesAChallengeResponseWithGpuEvidenceAndMutualLeg()
    {
        var ctx = Rep(0xC0, 32);
        var hctx = Rep(0xE1, 32);
        var gpu = Encoding.ASCII.GetBytes("PGAE gpu evidence envelope");
        var cc = Rep(0x55, 32);
        var ev = Parse(Response(mode: "challenge", tee: "tdx-gpu", gpu: "\"" + Base64Url.Encode(gpu) + "\"",
            clientEvidence: "\"required\"", clientContext: "\"" + Base64Url.Encode(cc) + "\""), AttestationMode.Challenge, ctx: ctx, hctx: hctx);
        Assert.Equal(AttestationMode.Challenge, ev.Mode);
        Assert.Equal("tdx-gpu", ev.Tee);
        Assert.Equal(gpu, ev.GpuEvidence);
        Assert.Equal(ctx, ev.Context);
        Assert.Equal(hctx, ev.Hctx);
        Assert.True(ev.ClientEvidenceRequired);
        Assert.Equal(cc, ev.ClientContext);
        // Padded base64url is tolerated.
        Assert.Equal(gpu, Parse(Response(gpu: "\"" + Base64Url.Encode(gpu) + "==\"")).GpuEvidence);
    }

    [Fact]
    public void RejectsMalformedResponses()
    {
        Assert.Contains("version 1", Reject(Response(v: "1")));
        Assert.Contains("version 0", Reject(Response(v: "\"2\"")));
        Assert.Contains("mode \"challenge\", requested \"deterministic\"", Reject(Response(mode: "challenge")));
        Assert.Contains("mode \"deterministic\", requested \"challenge\"", Reject(Response(), AttestationMode.Challenge));
        Assert.Contains("unknown tee", Reject(Response(tee: "nvidia-gpu")));
        Assert.Contains("quote is not base64url", Reject(Response(quote: "\"++++\"")));
        Assert.Contains("quote is not base64url", Reject(Response(quote: "\"\"")));
        Assert.Contains("quote is not base64url", Reject(Response(quote: "null")));
        Assert.Contains("gpu_evidence is not base64url", Reject(Response(gpu: "\"a/b\"")));
        Assert.Contains("in the future", Reject(Response(quoteTime: "2026-09-04T12:06Z")));
        Assert.Contains("older than 24 hours", Reject(Response(quoteTime: "2026-09-03T11:50Z")));
        Assert.Contains("not YYYY-MM-DDTHH:MMZ", Reject(Response(quoteTime: "2026-09-04T11:58:00Z")));
        Assert.Contains("unknown client_evidence", Reject(Response(clientEvidence: "\"maybe\"")));
        Assert.Contains("without a client_context", Reject(Response(clientEvidence: "\"required\"")));
        Assert.Contains("32-byte base64url", Reject(Response(clientEvidence: "\"required\"", clientContext: "\"" + Base64Url.Encode(Rep(1, 16)) + "\"")));
        Assert.Contains("not a JSON object", Reject("[1,2]"));
        Assert.Contains("attest response", Reject("not json"));
    }

    [Fact]
    public void RejectsErrorsAndStatuses()
    {
        Assert.Contains("no RA-TLS v2 evidence endpoint", Reject("404 page not found", status: 404));
        Assert.Contains("no RA-TLS v2 evidence endpoint", Reject("{\"v\":2,\"error\":\"unknown leaf\"}", status: 404));
        var e503 = Reject("{\"v\":2,\"error\":\"quote provider unavailable\"}", status: 503);
        Assert.Contains("attest failed (503)", e503);
        Assert.Contains("quote provider unavailable", e503);
        Assert.Contains("attest failed (400)", Reject("bad request", status: 400));
        // A raw-binding error frame comes with status 200 and an error field.
        Assert.Contains("frame error", Reject("{\"v\":2,\"error\":\"frame error\"}"));
        Assert.Throws<ArgumentException>(() => Parse(Response(), AttestationMode.None));
    }

    [Fact]
    public void PresentMessageAndAck()
    {
        var cc = Rep(0x55, 32);
        var body = RaTlsAttest.BuildPresent(cc, new ClientEvidence("sgx", SgxQuoteWith(Rep(1, 64)), null, "2026-09-04T11:58Z"));
        using var doc = JsonDocument.Parse(body);
        var r = doc.RootElement;
        Assert.Equal(2, r.GetProperty("v").GetInt32());
        Assert.Equal("present", r.GetProperty("mode").GetString());
        Assert.Equal(Base64Url.Encode(cc), r.GetProperty("context").GetString());
        Assert.Equal("sgx", r.GetProperty("tee").GetString());
        Assert.Equal(JsonValueKind.Null, r.GetProperty("gpu_evidence").ValueKind);
        Assert.Equal("2026-09-04T11:58Z", r.GetProperty("quote_time").GetString());

        RaTlsAttest.CheckPresentAck(Encoding.UTF8.GetBytes("{\"v\":2}"));
        Assert.Throws<RaTlsException>(() => RaTlsAttest.CheckPresentAck(Encoding.UTF8.GetBytes("{\"v\":2,\"error\":\"nope\"}")));
        Assert.Throws<RaTlsException>(() => RaTlsAttest.CheckPresentAck(Encoding.UTF8.GetBytes("{\"v\":1}")));
        Assert.Throws<RaTlsException>(() => RaTlsAttest.CheckPresentAck(Encoding.UTF8.GetBytes("garbage")));
    }

    [Fact]
    public void RawFramesRoundTrip()
    {
        var ms = new MemoryStream();
        RaTlsAttest.WriteFrame(ms, Encoding.ASCII.GetBytes("{\"v\":2}"));
        Assert.Equal(new byte[] { 0, 0, 0, 7 }, ms.ToArray()[..4]);
        ms.Position = 0;
        Assert.Equal("{\"v\":2}", Encoding.ASCII.GetString(RaTlsAttest.ReadFrame(ms)));
        Assert.Throws<RaTlsException>(() => RaTlsAttest.WriteFrame(ms, new byte[RaTlsAttest.MaxFrame + 1]));
        var big = new MemoryStream(new byte[] { 0, 1, 0, 1, 0 });
        Assert.Throws<RaTlsException>(() => RaTlsAttest.ReadFrame(big));
        Assert.Throws<EndOfStreamException>(() => RaTlsAttest.ReadFrame(new MemoryStream(new byte[] { 0, 0, 0, 9, 1 })));
    }

    [Fact]
    public void Base64UrlAlphabet()
    {
        var bytes = new byte[] { 0xfb, 0xff, 0xfe, 0x00, 0x01 };
        var s = Base64Url.Encode(bytes);
        Assert.DoesNotContain("=", s);
        Assert.DoesNotContain("+", s);
        Assert.DoesNotContain("/", s);
        Assert.Equal(bytes, Base64Url.Decode(s));
        Assert.Equal(bytes, Base64Url.Decode(s + "="));
        Assert.False(Base64Url.TryDecode("a+b", out _));
        Assert.False(Base64Url.TryDecode("a", out _));
        Assert.Equal(Array.Empty<byte>(), Base64Url.Decode(""));
    }
}
