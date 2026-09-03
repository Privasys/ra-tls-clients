// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// RA-TLS v2: attestation evidence after the handshake (docs/ratls-v2.md).
//
// The certificate identifies the enclave (leaf key, chain to the Privasys
// intermediate, Privasys OIDs) and carries no evidence. After the handshake the
// client asks for a quote on the same connection, before any application data,
// and checks that its report_data commits to the leaf key and, in challenge
// mode, to a value only the two ends of this TLS connection can derive (an
// RFC 8446 section 7.5 exporter keyed by exporter_master_secret).
//
// This file holds the protocol pieces that need no TLS stack: modes, the
// evidence record, message building and parsing, the raw frame binding and the
// base64url alphabet. The verifier (report_data recipes, policy checks) and the
// client live in RaTlsClient.cs.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Privasys.RaTls;

/// <summary>An RA-TLS verification or protocol failure. The message names the step that failed.</summary>
public class RaTlsException : InvalidOperationException
{
    public RaTlsException(string message) : base(message) { }
    public RaTlsException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// What the client asks the server for after the handshake. The .NET SDK defaults to
/// <see cref="Deterministic"/> because SslStream exposes no RFC 8446 exporter; see the
/// <see cref="RaTlsClient"/> summary.
/// </summary>
public enum AttestationMode
{
    /// <summary>The runtime's cached quote, bound to the leaf key and a minute timestamp only (the "trust the TEE" tier).</summary>
    Deterministic = 0,
    /// <summary>A quote bound to this connection through the TLS exporter and a fresh context (Level 3 binding).</summary>
    Challenge = 1,
    /// <summary>No request; the server tags the connection "none" and only the certificate extensions are verified.</summary>
    None = 2,
}

public static class AttestationModeExtensions
{
    /// <summary>The mode as it appears in attest messages and in the connection tag.</summary>
    public static string ToWire(this AttestationMode mode) => mode switch
    {
        AttestationMode.Challenge => "challenge",
        AttestationMode.Deterministic => "deterministic",
        AttestationMode.None => "none",
        _ => throw new ArgumentOutOfRangeException(nameof(mode)),
    };
}

/// <summary>How the attest messages are carried on the connection.</summary>
public enum AttestFraming
{
    /// <summary>POST /__privasys/attest as an HTTP/1.1 request.</summary>
    Http,
    /// <summary>One u32 big-endian length-prefixed JSON frame in each direction, for legs that do not speak HTTP.</summary>
    Raw,
}

/// <summary>
/// RFC 8446 section 7.5 exporter of a live connection: returns <paramref name="length"/>
/// bytes for <paramref name="label"/> and <paramref name="context"/>, keyed by this
/// connection's exporter_master_secret. SslStream has no such API; a caller whose TLS
/// stack exposes one supplies it through <see cref="RaTlsClientOptions.Exporter"/>.
/// </summary>
public delegate byte[] TlsExporter(string label, byte[] context, int length);

/// <summary>The evidence a server returned for a connection, verified only after VerifyEvidence succeeded.</summary>
public sealed class Evidence
{
    /// <summary>Mode the evidence was requested in.</summary>
    public AttestationMode Mode { get; set; }
    /// <summary>Evidence family: "sgx", "tdx", "tdx-gpu".</summary>
    public string Tee { get; set; } = "";
    /// <summary>Raw DCAP quote.</summary>
    public byte[] Quote { get; set; } = Array.Empty<byte>();
    /// <summary>NVIDIA CC evidence bundle, null when absent.</summary>
    public byte[]? GpuEvidence { get; set; }
    /// <summary>Minute the quote was minted, parsed from <see cref="QuoteTimeRaw"/> (UTC).</summary>
    public DateTime QuoteTime { get; set; }
    /// <summary>The 17-byte ASCII quote_time, an input of report_data in deterministic mode.</summary>
    public string QuoteTimeRaw { get; set; } = "";
    /// <summary>The client's 32-byte context (challenge mode).</summary>
    public byte[]? Context { get; set; }
    /// <summary>This connection's exporter output for Context (challenge mode). It never travels.</summary>
    public byte[]? Hctx { get; set; }
    /// <summary>The server asked for client evidence (mutual leg); <see cref="ClientContext"/> is the context it chose.</summary>
    public bool ClientEvidenceRequired { get; set; }
    public byte[]? ClientContext { get; set; }
}

/// <summary>What a <see cref="ClientEvidenceSource"/> receives when the server requires client evidence.</summary>
public sealed record ClientEvidenceRequest(
    /// <summary>DER SubjectPublicKeyInfo of the client certificate this connection presented.</summary>
    byte[] SpkiDer,
    /// <summary>The server-chosen 32-byte client_context.</summary>
    byte[] Context,
    /// <summary>This connection's exporter output under the client label.</summary>
    byte[] Hctx,
    /// <summary>
    /// The value the quote must carry: SHA-512( SHA-256(SpkiDer) || Context || Hctx ) [|| SHA-256(gpu_evidence)].
    /// A source that returns GPU evidence must recompute it with the fold (RaTlsVerifier.ClientReportData).
    /// </summary>
    byte[] ReportData);

/// <summary>What a <see cref="ClientEvidenceSource"/> returns.</summary>
public sealed record ClientEvidence(string Tee, byte[] Quote, byte[]? GpuEvidence, string QuoteTime);

/// <summary>Produces this client's own evidence for a mutual leg.</summary>
public delegate ClientEvidence ClientEvidenceSource(ClientEvidenceRequest request);

/// <summary>Protocol constants and the attest messages (docs/ratls-v2.md section 3).</summary>
public static class RaTlsAttest
{
    /// <summary>Reserved path of the evidence endpoint on every RA-TLS v2 server (HTTP binding).</summary>
    public const string AttestPath = "/__privasys/attest";
    /// <summary>The "v" field of every attest message.</summary>
    public const int ProtocolVersion = 2;
    /// <summary>Exporter label keying the server evidence of a connection.</summary>
    public const string ExporterLabelServer = "EXPORTER-privasys-ratls-attest-v2";
    /// <summary>Exporter label keying the client evidence of a connection (mutual leg).</summary>
    public const string ExporterLabelClient = "EXPORTER-privasys-ratls-attest-v2-client";
    /// <summary>Minute-precision layout of quote_time (.NET format string).</summary>
    public const string QuoteTimeLayout = "yyyy-MM-dd'T'HH:mm'Z'";
    /// <summary>Length of a quote_time string, 17 ASCII bytes.</summary>
    public const int QuoteTimeLength = 17;
    /// <summary>Length of a challenge context in bytes.</summary>
    public const int ContextLen = 32;
    /// <summary>Length of the exporter output in bytes.</summary>
    public const int HctxLen = 32;
    /// <summary>Largest raw-binding frame accepted, in bytes.</summary>
    public const int MaxFrame = 65536;

    /// <summary>
    /// Takes the place of the exporter output when a container proves its identity out of
    /// band, in HTTP headers to the control plane, where no TLS connection to the verifier
    /// exists: SHA-256("privasys-ratls-attest-v2-header-identity").
    /// </summary>
    public static readonly byte[] HeaderIdentityHctx =
        SHA256.HashData(Encoding.ASCII.GetBytes("privasys-ratls-attest-v2-header-identity"));

    /// <summary>The "leaf" field: base64url of SHA-256 of the received leaf's SPKI DER.</summary>
    public static string LeafId(byte[] spkiDer) => Base64Url.Encode(SHA256.HashData(spkiDer));

    /// <summary>
    /// The request body for <paramref name="mode"/> (Deterministic or Challenge). A challenge
    /// request carries the 32-byte <paramref name="context"/>.
    /// </summary>
    public static byte[] BuildRequest(AttestationMode mode, byte[] spkiDer, byte[]? context = null)
    {
        if (mode == AttestationMode.None)
            throw new ArgumentException("no attest request in mode none", nameof(mode));
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteNumber("v", ProtocolVersion);
            w.WriteString("mode", mode.ToWire());
            w.WriteString("leaf", LeafId(spkiDer));
            if (mode == AttestationMode.Challenge)
            {
                if (context is null || context.Length != ContextLen)
                    throw new ArgumentException($"a challenge context is {ContextLen} bytes", nameof(context));
                w.WriteString("context", Base64Url.Encode(context));
            }
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Parses and checks an attest response (section 3.4): HTTP status, error field,
    /// version, mode echo, evidence family, base64url bodies, quote_time freshness and the
    /// mutual-leg fields. <paramref name="context"/> and <paramref name="hctx"/> are this
    /// client's challenge values and are copied into the result. Throws
    /// <see cref="RaTlsException"/> naming the step on any rejection.
    /// </summary>
    public static Evidence ParseResponse(int httpStatus, ReadOnlySpan<byte> body, AttestationMode requested,
        DateTime nowUtc, byte[]? context = null, byte[]? hctx = null)
    {
        if (requested == AttestationMode.None)
            throw new ArgumentException("no attest response in mode none", nameof(requested));

        JsonDocument? doc = null;
        try { doc = JsonDocument.Parse(body.ToArray()); }
        catch (JsonException e)
        {
            // A non-JSON body only ever comes with an error status (a plain 404 from a
            // gateway terminate path, a proxy error page).
            if (httpStatus != 200) throw Failure(httpStatus, Encoding.UTF8.GetString(body).Trim());
            throw new RaTlsException("attest response: " + e.Message, e);
        }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new RaTlsException("attest response: not a JSON object");
            var error = GetString(root, "error");
            if (httpStatus != 200 || !string.IsNullOrEmpty(error))
                throw Failure(httpStatus, string.IsNullOrEmpty(error) ? Encoding.UTF8.GetString(body).Trim() : error);
            var v = root.TryGetProperty("v", out var vEl) && vEl.ValueKind == JsonValueKind.Number ? vEl.GetInt32() : 0;
            if (v != ProtocolVersion)
                throw new RaTlsException($"attest response version {v}, want {ProtocolVersion}");
            var mode = GetString(root, "mode") ?? "";
            if (mode != requested.ToWire())
                throw new RaTlsException($"attest response mode \"{mode}\", requested \"{requested.ToWire()}\"");
            var tee = GetString(root, "tee") ?? "";
            if (RaTlsVerifier.TeeTypeOf(tee) is null)
                throw new RaTlsException($"attest response: unknown tee \"{tee}\"");

            var ev = new Evidence { Mode = requested, Tee = tee, Context = context, Hctx = hctx };
            var quote = GetString(root, "quote");
            if (quote is null || !Base64Url.TryDecode(quote, out var quoteBytes) || quoteBytes.Length == 0)
                throw new RaTlsException("attest response: quote is not base64url");
            ev.Quote = quoteBytes;
            var gpu = GetString(root, "gpu_evidence");
            if (!string.IsNullOrEmpty(gpu))
            {
                if (!Base64Url.TryDecode(gpu, out var gpuBytes))
                    throw new RaTlsException("attest response: gpu_evidence is not base64url");
                ev.GpuEvidence = gpuBytes;
            }
            ev.QuoteTimeRaw = GetString(root, "quote_time") ?? "";
            ev.QuoteTime = RaTlsVerifier.CheckQuoteTime(ev.QuoteTimeRaw, nowUtc);

            switch (GetString(root, "client_evidence") ?? "")
            {
                case "":
                case "none":
                    break;
                case "required":
                    ev.ClientEvidenceRequired = true;
                    var cc = GetString(root, "client_context");
                    if (cc is null)
                        throw new RaTlsException("server requires client evidence without a client_context");
                    if (!Base64Url.TryDecode(cc, out var ccBytes) || ccBytes.Length != ContextLen)
                        throw new RaTlsException($"client_context is not a {ContextLen}-byte base64url value");
                    ev.ClientContext = ccBytes;
                    break;
                case var other:
                    throw new RaTlsException($"attest response: unknown client_evidence \"{other}\"");
            }
            return ev;
        }
    }

    /// <summary>The "present" message answering a server that requires client evidence (section 5).</summary>
    public static byte[] BuildPresent(byte[] clientContext, ClientEvidence ce)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteNumber("v", ProtocolVersion);
            w.WriteString("mode", "present");
            w.WriteString("context", Base64Url.Encode(clientContext));
            w.WriteString("tee", ce.Tee);
            w.WriteString("quote", Base64Url.Encode(ce.Quote));
            if (ce.GpuEvidence is { Length: > 0 }) w.WriteString("gpu_evidence", Base64Url.Encode(ce.GpuEvidence));
            else w.WriteNull("gpu_evidence");
            w.WriteString("quote_time", ce.QuoteTime);
            w.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>Checks the server's acknowledgement of a present message on the raw binding: {"v":2} without an error.</summary>
    public static void CheckPresentAck(ReadOnlySpan<byte> body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body.ToArray());
            var root = doc.RootElement;
            var v = root.TryGetProperty("v", out var vEl) && vEl.ValueKind == JsonValueKind.Number ? vEl.GetInt32() : 0;
            if (v == ProtocolVersion && string.IsNullOrEmpty(GetString(root, "error"))) return;
        }
        catch (JsonException) { }
        throw new RaTlsException("client evidence rejected: " + Encoding.UTF8.GetString(body).Trim());
    }

    private static string? GetString(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

    /// <summary>The error for a failed exchange; 404 means no v2 endpoint (or the gateway terminate path).</summary>
    private static RaTlsException Failure(int httpStatus, string error) => httpStatus == 404
        ? new RaTlsException($"server has no RA-TLS v2 evidence endpoint ({AttestPath}): {error}")
        : new RaTlsException($"attest failed ({httpStatus}): {error}");

    // -- raw binding ----------------------------------------------------------

    /// <summary>Writes one raw-binding frame: u32 big-endian length || payload.</summary>
    public static void WriteFrame(Stream stream, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > MaxFrame)
            throw new RaTlsException($"frame too large: {payload.Length}");
        Span<byte> hdr = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(hdr, (uint)payload.Length);
        stream.Write(hdr);
        stream.Write(payload);
        stream.Flush();
    }

    /// <summary>Reads one raw-binding frame, refusing lengths above <see cref="MaxFrame"/>.</summary>
    public static byte[] ReadFrame(Stream stream)
    {
        Span<byte> hdr = stackalloc byte[4];
        stream.ReadExactly(hdr);
        var n = BinaryPrimitives.ReadUInt32BigEndian(hdr);
        if (n > MaxFrame)
            throw new RaTlsException($"frame too large: {n}");
        var buf = new byte[n];
        stream.ReadExactly(buf);
        return buf;
    }
}

/// <summary>base64url without padding, the only base64 alphabet of the protocol.</summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Decodes base64url; padding is tolerated, the standard alphabet is not.</summary>
    public static bool TryDecode(string s, out byte[] data)
    {
        data = Array.Empty<byte>();
        if (s.IndexOf('+') >= 0 || s.IndexOf('/') >= 0) return false;
        var t = s.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4)
        {
            case 1: return false;
            case 2: t += "=="; break;
            case 3: t += "="; break;
        }
        try { data = Convert.FromBase64String(t); return true; }
        catch (FormatException) { return false; }
    }

    public static byte[] Decode(string s)
        => TryDecode(s, out var data) ? data : throw new FormatException("not base64url");
}
