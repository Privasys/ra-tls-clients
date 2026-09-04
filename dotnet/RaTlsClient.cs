// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// RA-TLS v2 client for the Privasys enclave runtimes (docs/ratls-v2.md).
//
// Provides:
//   - a TLS 1.3 connection whose server chain must reach a Privasys fleet anchor
//     (embedded intermediates, or a caller-supplied PEM), no hostname check
//   - the post-handshake evidence exchange (POST /__privasys/attest, or the raw
//     u32 big-endian frame binding) in deterministic, challenge or none mode
//   - certificate inspection (v2 OID extensions) and policy verification:
//     measurements, expected OIDs, image profile, predicted report_data,
//     quote_time freshness, attestation-server quote and GPU verdicts
//   - re-attestation on long-lived connections and the connection tag
//   - HTTP/1.1 helpers and raw frames over the verified connection
//
// Dependencies: the .NET base class library only (System.Net.Security,
// System.Security.Cryptography, System.Text.Json).
//
// Usage:
//   using var client = new RaTlsClient("141.94.219.130", 443);
//   client.Connect();                                  // handshake + evidence
//   var info = client.VerifyCertificate(new VerificationPolicy(TeeType.Tdx, MrTd: mrtd));
//   byte[] resp = client.SendData(payload, token);

using System.Buffers.Binary;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Privasys.RaTls;

// ---------------------------------------------------------------------------
//  Quote byte-offset constants
// ---------------------------------------------------------------------------

/// <summary>Format of an SGX attestation blob.</summary>
public enum SgxQuoteFormat
{
    /// <summary>Full DCAP Quote v3: 48-byte header, report body, signature.</summary>
    DcapV3,
    /// <summary>Raw SGX Report from sgx_create_report, no header.</summary>
    RawReport,
}

public static class SgxQuoteLayout
{
    // DCAP Quote v3: QuoteHeader(48) + ReportBody(384).
    public const int MinSize = 432;
    public const int MrEnclaveOff = 112;
    public const int MrEnclaveEnd = 144;
    public const int MrSignerOff = 176;
    public const int MrSignerEnd = 208;
    public const int ReportDataOff = 368;
    public const int ReportDataEnd = 432;

    // Raw Report (sgx_create_report): ReportBody(432) only.
    public const int ReportSize = 432;
    public const int ReportMrEnclaveOff = 64;
    public const int ReportMrSignerOff = 128;
    public const int ReportReportDataOff = 320;

    /// <summary>A DCAP Quote v3 starts with a little-endian u16 version equal to 3; a raw Report starts with CPUSVN and never does.</summary>
    public static SgxQuoteFormat DetectFormat(ReadOnlySpan<byte> raw)
        => raw.Length >= 4 && BinaryPrimitives.ReadUInt16LittleEndian(raw) == 3 ? SgxQuoteFormat.DcapV3 : SgxQuoteFormat.RawReport;

    /// <summary>MRENCLAVE, MRSIGNER and report_data offsets and the minimum size for a format.</summary>
    public static (int MrEnclaveOff, int MrSignerOff, int ReportDataOff, int MinSize) Offsets(SgxQuoteFormat format)
        => format == SgxQuoteFormat.DcapV3
            ? (MrEnclaveOff, MrSignerOff, ReportDataOff, MinSize)
            : (ReportMrEnclaveOff, ReportMrSignerOff, ReportReportDataOff, ReportSize);
}

/// <summary>
/// TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584). MRTD alone (the TD firmware)
/// does not identify the guest build; a full identity is MRTD + RTMR1 + RTMR2.
/// </summary>
public static class TdxQuoteLayout
{
    public const int MinSize = 632;
    public const int MrTdOff = 184;
    public const int MrTdEnd = 232;
    public const int Rtmr1Off = 424;
    public const int Rtmr1End = 472;
    public const int Rtmr2Off = 472;
    public const int Rtmr2End = 520;
    public const int ReportDataOff = 568;
    public const int ReportDataEnd = 632;
}

/// <summary>AMD SEV-SNP attestation report (raw report from /dev/sev-guest).</summary>
public static class SevSnpReportLayout
{
    public const int MinSize = 0x4A0;
    public const int ReportDataOff = 0x050;
    public const int ReportDataEnd = 0x090;
    public const int MeasurementOff = 0x090;
    public const int MeasurementEnd = 0x0C0;
    public const int HostDataOff = 0x0C0;
    public const int HostDataEnd = 0x0E0;
}

// ---------------------------------------------------------------------------
//  Verification types
// ---------------------------------------------------------------------------

public enum TeeType { Sgx, Tdx, SevSnp, NvidiaGpu }

/// <summary>An expected certificate extension value.</summary>
public sealed record ExpectedOid(string Oid, byte[] ExpectedValue);

/// <summary>Verdict of the quote verification service.</summary>
public enum QuoteVerificationStatus
{
    Ok,
    TcbOutOfDate,
    ConfigurationNeeded,
    SwHardeningNeeded,
    ConfigurationAndSwHardeningNeeded,
    TcbRevoked,
    TcbExpired,
    Unrecognized,
}

public static class QuoteVerificationStatusExt
{
    public static string ToStatusString(this QuoteVerificationStatus s) => s switch
    {
        QuoteVerificationStatus.Ok => "OK",
        QuoteVerificationStatus.TcbOutOfDate => "TCB_OUT_OF_DATE",
        QuoteVerificationStatus.ConfigurationNeeded => "CONFIGURATION_NEEDED",
        QuoteVerificationStatus.SwHardeningNeeded => "SW_HARDENING_NEEDED",
        QuoteVerificationStatus.ConfigurationAndSwHardeningNeeded => "CONFIGURATION_AND_SW_HARDENING_NEEDED",
        QuoteVerificationStatus.TcbRevoked => "TCB_REVOKED",
        QuoteVerificationStatus.TcbExpired => "TCB_EXPIRED",
        _ => "UNRECOGNIZED",
    };

    public static QuoteVerificationStatus FromString(string s) => s switch
    {
        "OK" => QuoteVerificationStatus.Ok,
        "TCB_OUT_OF_DATE" => QuoteVerificationStatus.TcbOutOfDate,
        "CONFIGURATION_NEEDED" => QuoteVerificationStatus.ConfigurationNeeded,
        "SW_HARDENING_NEEDED" => QuoteVerificationStatus.SwHardeningNeeded,
        "CONFIGURATION_AND_SW_HARDENING_NEEDED" => QuoteVerificationStatus.ConfigurationAndSwHardeningNeeded,
        "TCB_REVOKED" => QuoteVerificationStatus.TcbRevoked,
        "TCB_EXPIRED" => QuoteVerificationStatus.TcbExpired,
        _ => QuoteVerificationStatus.Unrecognized,
    };
}

/// <summary>
/// Intel's platform TCB status as reported in the attestation server's tcbStatus field
/// (CamelCase, distinct from the verdict enum above).
/// </summary>
public static class TcbStatuses
{
    public const string UpToDate = "UpToDate";
    public const string SwHardeningNeeded = "SWHardeningNeeded";
    public const string ConfigurationNeeded = "ConfigurationNeeded";
    public const string ConfigurationAndSwHardeningNeeded = "ConfigurationAndSWHardeningNeeded";
    public const string OutOfDate = "OutOfDate";
    public const string OutOfDateConfigurationNeeded = "OutOfDateConfigurationNeeded";
    public const string Revoked = "Revoked";

    /// <summary>
    /// Accepts a reported status: Revoked never; the secure floor (UpToDate, SWHardeningNeeded)
    /// always; anything else only when listed in <paramref name="acceptable"/>. An empty status
    /// (the server did not report one) is accepted.
    /// </summary>
    public static void CheckAcceptable(string? status, IReadOnlyList<string>? acceptable)
    {
        if (string.IsNullOrEmpty(status)) return;
        if (status == Revoked) throw new RaTlsException("TCB status Revoked is never acceptable");
        if (status is UpToDate or SwHardeningNeeded) return;
        if (acceptable is not null && acceptable.Contains(status)) return;
        throw new RaTlsException($"TCB status \"{status}\" not accepted: not in the secure floor and not in the configured acceptable set");
    }
}

/// <summary>Remote quote verification through an attestation server (POST Endpoint).</summary>
public sealed record QuoteVerificationConfig(
    string Endpoint,
    string? Token = null,
    /// <summary>Verdicts accepted in addition to OK.</summary>
    QuoteVerificationStatus[]? AcceptedStatuses = null,
    /// <summary>Opt-in client-side enforcement of the reported Intel tcbStatus against the secure floor and <see cref="AcceptableTcbStatuses"/>.</summary>
    bool EnforceTcbStatus = false,
    string[]? AcceptableTcbStatuses = null,
    int TimeoutSecs = 10);

public sealed record QuoteVerificationResult(
    QuoteVerificationStatus Status,
    string? TcbDate = null,
    string[]? AdvisoryIds = null,
    /// <summary>Intel's platform TCB status when the server reported it.</summary>
    string? TcbStatus = null);

/// <summary>The attestation server's NVIDIA GPU verdict for tdx-gpu evidence.</summary>
public sealed record GpuAttestationResult(
    bool Verified,
    string? Status = null,
    string? Message = null,
    string? Error = null,
    string? GpuUuid = null,
    string? Driver = null,
    string? Vbios = null,
    string? CcEnvironment = null,
    bool MeasurementsVerified = false);

/// <summary>What a connection must prove. Null measurement fields are not checked.</summary>
public sealed record VerificationPolicy(
    TeeType Tee,
    byte[]? MrEnclave = null,
    byte[]? MrSigner = null,
    byte[]? MrTd = null,
    /// <summary>TDX runtime registers (48 bytes each). A full TDX identity pins MRTD and both image-derived registers.</summary>
    byte[]? Rtmr1 = null,
    byte[]? Rtmr2 = null,
    byte[]? Measurement = null,
    byte[]? HostData = null,
    ExpectedOid[]? ExpectedOids = null,
    QuoteVerificationConfig? QuoteVerification = null,
    /// <summary>
    /// Accept certificates whose Image Profile extension is not "production" (dev images with
    /// SSH and debug tooling). Fail-closed otherwise; certificates without the extension pass.
    /// </summary>
    bool AllowDebugImages = false);

// ---------------------------------------------------------------------------
//  Certificate inspection result
// ---------------------------------------------------------------------------

/// <summary>An evidence body. Oid names the quote format (Intel-arc OIDs, as in v1 certificates).</summary>
public sealed record QuoteInfo(
    string Oid,
    string Label,
    bool Critical,
    byte[] Raw,
    bool IsMock = false,
    ushort? Version = null,
    byte[]? ReportData = null);

public sealed record OidExtension(string Oid, string Label, byte[] Value);

/// <summary>Summary of a server's RA-TLS certificate and, once obtained, the evidence of the connection.</summary>
public sealed record CertInfo
{
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string SerialNumber { get; init; } = "";
    public DateTime NotBefore { get; init; }
    public DateTime NotAfter { get; init; }
    public string SignatureAlgorithm { get; init; } = "";
    /// <summary>Lowercase hex SHA-256 of the SPKI DER, the value report_data commits to.</summary>
    public string PubKeySha256 { get; init; } = "";
    /// <summary>Every extension OID of the certificate.</summary>
    public IReadOnlyList<string> Extensions { get; init; } = Array.Empty<string>();
    /// <summary>A v1 certificate (evidence inside the certificate). A v2 verifier fails closed on it.</summary>
    public bool V1Leaf { get; init; }
    /// <summary>The evidence body of the connection (never from the certificate); on a V1Leaf, the unverified extension for display only.</summary>
    public QuoteInfo? Quote { get; init; }
    public byte[]? GpuEvidence { get; init; }
    /// <summary>The mode the evidence was obtained in; None when the connection carries no evidence.</summary>
    public AttestationMode Attestation { get; init; } = AttestationMode.None;
    public Evidence? Evidence { get; init; }
    /// <summary>Extensions under the Privasys arc.</summary>
    public IReadOnlyList<OidExtension> CustomOids { get; init; } = Array.Empty<OidExtension>();
    public QuoteVerificationResult? QuoteVerification { get; init; }
    public GpuAttestationResult? GpuAttestation { get; init; }
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

public static class RaTlsCertInspector
{
    /// <summary>Inspects a certificate for v2 extensions; flags a v1 leaf (Intel-arc quote extension).</summary>
    public static CertInfo Inspect(X509Certificate2 cert)
    {
        var spki = SpkiDerOf(cert);
        var extensions = new List<string>();
        var customOids = new List<OidExtension>();
        QuoteInfo? quote = null;
        var v1 = false;

        foreach (var ext in cert.Extensions)
        {
            var oid = ext.Oid?.Value;
            if (oid is null) continue;
            extensions.Add(oid);
            if (oid == Oids.SGXQuote || oid == Oids.TDXQuote)
            {
                // A v1 leaf: parsed for display, never verified.
                v1 = true;
                quote = ParseV1Quote(oid, ext.Critical, ext.RawData);
            }
            else if (oid.StartsWith(Oids.PrivasysArcPrefix, StringComparison.Ordinal))
            {
                customOids.Add(new OidExtension(oid, Oids.Label(oid), ext.RawData));
            }
        }

        return new CertInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "",
            PubKeySha256 = Hex(SHA256.HashData(spki)),
            Extensions = extensions,
            V1Leaf = v1,
            Quote = quote,
            CustomOids = customOids,
        };
    }

    /// <summary>DER SubjectPublicKeyInfo of a certificate (91 bytes for P-256).</summary>
    public static byte[] SpkiDerOf(X509Certificate2 cert) => cert.PublicKey.ExportSubjectPublicKeyInfo();

    private static QuoteInfo ParseV1Quote(string oid, bool critical, byte[] raw)
    {
        var isMock = IsMockQuote(raw);
        ushort? version = raw.Length >= 2 ? BinaryPrimitives.ReadUInt16LittleEndian(raw) : null;
        byte[]? reportData = null;
        if (isMock) reportData = raw[11..Math.Min(raw.Length, 75)];
        else if (oid == Oids.SGXQuote) { var o = SgxQuoteLayout.Offsets(SgxQuoteLayout.DetectFormat(raw)); if (raw.Length >= o.MinSize) reportData = raw[o.ReportDataOff..(o.ReportDataOff + 64)]; }
        else if (raw.Length >= TdxQuoteLayout.MinSize) reportData = raw[TdxQuoteLayout.ReportDataOff..TdxQuoteLayout.ReportDataEnd];
        return new QuoteInfo(oid, Oids.Label(oid), critical, raw, isMock, version, reportData);
    }

    /// <summary>QuoteInfo of an attest-response quote; the OID names the format so callers keep switching on it.</summary>
    internal static QuoteInfo QuoteInfoOf(Evidence ev)
    {
        var oid = ev.Tee switch
        {
            "tdx" or "tdx-gpu" => Oids.TDXQuote,
            "sev-snp" => Oids.EvidenceSEVSNPReport,
            _ => Oids.SGXQuote,
        };
        ushort? version = ev.Quote.Length >= 2 ? BinaryPrimitives.ReadUInt16LittleEndian(ev.Quote) : null;
        byte[]? rd = null;
        try { rd = RaTlsVerifier.QuoteReportData(ev.Tee, ev.Quote); } catch (RaTlsException) { }
        return new QuoteInfo(oid, Oids.Label(oid), false, ev.Quote, IsMockQuote(ev.Quote), version, rd);
    }

    internal static bool IsMockQuote(byte[] raw)
        => raw.Length >= 11 && Encoding.ASCII.GetString(raw, 0, 11) == "MOCK_QUOTE:";

    internal static string Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(data).ToLowerInvariant();
}

// ---------------------------------------------------------------------------
//  Verification
// ---------------------------------------------------------------------------

public static class RaTlsVerifier
{
    private static readonly TimeSpan QuoteSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan QuoteMaxAge = TimeSpan.FromHours(24) + QuoteSkew;

    /// <summary>Maps an evidence family string to a TeeType, null when unknown.</summary>
    public static TeeType? TeeTypeOf(string tee) => tee switch
    {
        "sgx" => TeeType.Sgx,
        "tdx" or "tdx-gpu" => TeeType.Tdx,
        "sev-snp" => TeeType.SevSnp,
        _ => null,
    };

    /// <summary>The TEE family as it appears in attest messages.</summary>
    public static string TeeName(TeeType tee) => tee switch
    {
        TeeType.Sgx => "sgx",
        TeeType.Tdx => "tdx",
        TeeType.SevSnp => "sev-snp",
        TeeType.NvidiaGpu => "nvidia-gpu",
        _ => tee.ToString(),
    };

    // -- report_data ----------------------------------------------------------

    /// <summary>
    /// The report_data a quote must carry for the leaf whose SubjectPublicKeyInfo is
    /// <paramref name="spkiDer"/> and the evidence <paramref name="ev"/>:
    /// deterministic SHA-512( SHA-256(SPKI_DER) || quote_time ), challenge
    /// SHA-512( SHA-256(SPKI_DER) || context || hctx ), with SHA-256(gpu_evidence) appended
    /// to the binding when GPU evidence is present. The verifier predicts this value; it
    /// never accepts one from the peer.
    /// </summary>
    public static byte[] ExpectedReportData(byte[] spkiDer, Evidence ev)
    {
        byte[] binding;
        switch (ev.Mode)
        {
            case AttestationMode.Deterministic:
                if (ev.QuoteTimeRaw.Length != RaTlsAttest.QuoteTimeLength)
                    throw new RaTlsException("deterministic evidence needs a quote_time");
                binding = Encoding.ASCII.GetBytes(ev.QuoteTimeRaw);
                break;
            case AttestationMode.Challenge:
                if (ev.Context is null || ev.Context.Length != RaTlsAttest.ContextLen || ev.Hctx is null || ev.Hctx.Length != RaTlsAttest.HctxLen)
                    throw new RaTlsException($"challenge evidence needs a {RaTlsAttest.ContextLen}-byte context and a {RaTlsAttest.HctxLen}-byte exporter value");
                binding = Concat(ev.Context, ev.Hctx);
                break;
            default:
                throw new RaTlsException($"no report_data for attestation mode {ev.Mode.ToWire()}");
        }
        return ReportDataHash(spkiDer, GpuFold(binding, ev.GpuEvidence));
    }

    /// <summary>
    /// ExpectedReportData for the client evidence of a mutual leg:
    /// SHA-512( SHA-256(client SPKI) || client_context || hctx_c ) with the same GPU fold.
    /// </summary>
    public static byte[] ClientReportData(byte[] spkiDer, byte[] clientContext, byte[] hctx, byte[]? gpuEvidence)
        => ReportDataHash(spkiDer, GpuFold(Concat(clientContext, hctx), gpuEvidence));

    /// <summary>The 64-byte report_data of a raw quote of the given evidence family.</summary>
    public static byte[] QuoteReportData(string tee, byte[] quote)
    {
        switch (tee)
        {
            case "sgx":
                var o = SgxQuoteLayout.Offsets(SgxQuoteLayout.DetectFormat(quote));
                if (quote.Length < o.ReportDataOff + 64) throw new RaTlsException("SGX quote too small to contain report_data");
                return quote[o.ReportDataOff..(o.ReportDataOff + 64)];
            case "tdx":
            case "tdx-gpu":
                if (quote.Length < TdxQuoteLayout.ReportDataEnd) throw new RaTlsException("TDX quote too small to contain report_data");
                return quote[TdxQuoteLayout.ReportDataOff..TdxQuoteLayout.ReportDataEnd];
            case "sev-snp":
                if (quote.Length < SevSnpReportLayout.ReportDataEnd) throw new RaTlsException("SEV-SNP report too small to contain report_data");
                return quote[SevSnpReportLayout.ReportDataOff..SevSnpReportLayout.ReportDataEnd];
            default:
                throw new RaTlsException($"unknown evidence family \"{tee}\"");
        }
    }

    /// <summary>
    /// Rejects a quote_time that is not YYYY-MM-DDTHH:MMZ, older than the 24-hour cache
    /// lifetime plus 5 minutes of skew, or ahead of <paramref name="nowUtc"/> by more than
    /// the skew. Returns the parsed minute (UTC).
    /// </summary>
    public static DateTime CheckQuoteTime(string raw, DateTime nowUtc)
    {
        if (raw.Length != RaTlsAttest.QuoteTimeLength
            || !DateTime.TryParseExact(raw, RaTlsAttest.QuoteTimeLayout, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            throw new RaTlsException($"quote_time \"{raw}\" is not YYYY-MM-DDTHH:MMZ");
        if (t > nowUtc + QuoteSkew) throw new RaTlsException($"quote_time {raw} is in the future");
        if (nowUtc - t > QuoteMaxAge) throw new RaTlsException($"quote_time {raw} is older than 24 hours");
        return t;
    }

    private static byte[] GpuFold(byte[] binding, byte[]? gpuEvidence)
        => gpuEvidence is { Length: > 0 } ? Concat(binding, SHA256.HashData(gpuEvidence)) : binding;

    /// <summary>SHA-512( SHA-256(spki) || binding ).</summary>
    private static byte[] ReportDataHash(byte[] spkiDer, byte[] binding)
        => SHA512.HashData(Concat(SHA256.HashData(spkiDer), binding));

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var buf = new byte[a.Length + b.Length];
        a.CopyTo(buf, 0);
        b.CopyTo(buf, a.Length);
        return buf;
    }

    // -- policy ---------------------------------------------------------------

    /// <summary>
    /// Verifies a v2 leaf against the certificate part of a policy only: v2 shape (no evidence
    /// in the certificate), image profile and expected OIDs. It proves nothing about the TEE.
    /// </summary>
    public static CertInfo VerifyCertificateExtensions(X509Certificate2 cert, VerificationPolicy policy)
    {
        var info = RaTlsCertInspector.Inspect(cert);
        RejectV1(info);
        VerifyImageProfile(info.CustomOids, policy);
        VerifyExpectedOids(info.CustomOids, policy.ExpectedOids);
        return info;
    }

    /// <summary>
    /// Verifies the evidence obtained for the connection whose leaf is <paramref name="cert"/>
    /// against <paramref name="policy"/>, in this order: v2 leaf shape, evidence family,
    /// measurement registers, report_data (predicted from the leaf SPKI and the evidence),
    /// image profile, expected OIDs, then the attestation server (quote signature and TCB,
    /// GPU verdict). Returns the CertInfo with Quote, Evidence and Attestation filled.
    /// </summary>
    public static CertInfo VerifyEvidence(X509Certificate2 cert, Evidence? ev, VerificationPolicy policy)
    {
        var info = RaTlsCertInspector.Inspect(cert);
        RejectV1(info);
        if (ev is null)
            throw new RaTlsException("no attestation evidence for this connection (attestation mode none)");
        if (RaTlsCertInspector.IsMockQuote(ev.Quote))
            throw new RaTlsException("evidence is a MOCK quote");

        // 1. Evidence family against the policy.
        var tee = TeeTypeOf(ev.Tee) ?? throw new RaTlsException($"unknown evidence family \"{ev.Tee}\"");
        if (policy.Tee == TeeType.NvidiaGpu)
            throw new RaTlsException("TeeType.NvidiaGpu is not a primary evidence family in RA-TLS v2; verify a tdx-gpu connection with TeeType.Tdx");
        if (tee != policy.Tee)
            throw new RaTlsException($"expected {TeeName(policy.Tee)} evidence, got {ev.Tee}");
        if (ev.Tee == "tdx-gpu" && ev.GpuEvidence is not { Length: > 0 })
            throw new RaTlsException("tdx-gpu evidence without gpu_evidence");

        // 2. Measurement registers.
        VerifyMeasurements(ev.Quote, policy);

        // 3. report_data, predicted from the leaf and the evidence.
        var expected = ExpectedReportData(RaTlsCertInspector.SpkiDerOf(cert), ev);
        var actual = QuoteReportData(ev.Tee, ev.Quote);
        if (!actual.AsSpan().SequenceEqual(expected))
            throw new RaTlsException($"report_data mismatch ({ev.Mode.ToWire()} mode):\n  got:      {RaTlsCertInspector.Hex(actual)}\n  expected: {RaTlsCertInspector.Hex(expected)}");

        // 4. Certificate extensions.
        VerifyImageProfile(info.CustomOids, policy);
        VerifyExpectedOids(info.CustomOids, policy.ExpectedOids);

        info = info with
        {
            Quote = RaTlsCertInspector.QuoteInfoOf(ev),
            GpuEvidence = ev.GpuEvidence,
            Attestation = ev.Mode,
            Evidence = ev,
        };

        // 5. Attestation server: quote signature, collateral, TCB; GPU verdict.
        if (policy.QuoteVerification is { } qv)
        {
            if (ev.GpuEvidence is { Length: > 0 })
            {
                var (result, gpu) = VerifyTdxGpu(ev.Quote, ev.GpuEvidence, qv);
                info = info with { QuoteVerification = result, GpuAttestation = gpu };
            }
            else
            {
                info = info with { QuoteVerification = VerifyQuote(ev.Quote, qv) };
            }
        }
        return info;
    }

    private static void RejectV1(CertInfo info)
    {
        if (info.V1Leaf)
            throw new RaTlsException("v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier");
    }

    /// <summary>Checks the measurement registers of a raw quote against the policy's non-null fields.</summary>
    public static void VerifyMeasurements(byte[] raw, VerificationPolicy policy)
    {
        switch (policy.Tee)
        {
            case TeeType.Sgx:
                var o = SgxQuoteLayout.Offsets(SgxQuoteLayout.DetectFormat(raw));
                if (raw.Length < o.MinSize) throw new RaTlsException($"SGX attestation blob too small: {raw.Length} < {o.MinSize}");
                Expect("MRENCLAVE", raw.AsSpan(o.MrEnclaveOff, 32), policy.MrEnclave);
                Expect("MRSIGNER", raw.AsSpan(o.MrSignerOff, 32), policy.MrSigner);
                break;
            case TeeType.Tdx:
                if (raw.Length < TdxQuoteLayout.MinSize) throw new RaTlsException($"TDX quote too small: {raw.Length} < {TdxQuoteLayout.MinSize}");
                Expect("MRTD", raw.AsSpan(TdxQuoteLayout.MrTdOff, 48), policy.MrTd);
                // RTMR1/RTMR2 pin the guest build (kernel/initrd + cmdline) alongside MRTD.
                Expect("RTMR1", raw.AsSpan(TdxQuoteLayout.Rtmr1Off, 48), policy.Rtmr1);
                Expect("RTMR2", raw.AsSpan(TdxQuoteLayout.Rtmr2Off, 48), policy.Rtmr2);
                break;
            case TeeType.SevSnp:
                if (raw.Length < SevSnpReportLayout.MinSize) throw new RaTlsException($"SEV-SNP report too small: {raw.Length} < {SevSnpReportLayout.MinSize}");
                Expect("MEASUREMENT", raw.AsSpan(SevSnpReportLayout.MeasurementOff, 48), policy.Measurement);
                Expect("HOST_DATA", raw.AsSpan(SevSnpReportLayout.HostDataOff, 32), policy.HostData);
                break;
            case TeeType.NvidiaGpu:
                // GPU evidence is verified remotely; no local measurement check.
                break;
        }
    }

    private static void Expect(string name, ReadOnlySpan<byte> actual, byte[]? expected)
    {
        if (expected is null) return;
        if (!actual.SequenceEqual(expected))
            throw new RaTlsException($"{name} mismatch: got {RaTlsCertInspector.Hex(actual)}, expected {RaTlsCertInspector.Hex(expected)}");
    }

    /// <summary>
    /// Rejects non-production image profiles unless the policy allows them. The Image Profile
    /// extension is baked into the measured rootfs; any value other than "production" counts
    /// as a debug image. Certificates without the extension are accepted.
    /// </summary>
    internal static void VerifyImageProfile(IReadOnlyList<OidExtension> exts, VerificationPolicy policy)
    {
        var ext = exts.FirstOrDefault(e => e.Oid == Oids.ImageProfile);
        if (ext is null) return;
        var profile = Encoding.UTF8.GetString(ext.Value).Trim();
        if (profile != "production" && !policy.AllowDebugImages)
            throw new RaTlsException($"server runs a \"{profile}\" image (OID {Oids.ImageProfile}): debug/dev images are rejected unless VerificationPolicy.AllowDebugImages is set");
    }

    /// <summary>Requires every expected OID to be present with the expected value.</summary>
    public static void VerifyExpectedOids(IReadOnlyList<OidExtension>? actual, IReadOnlyList<ExpectedOid>? expected)
    {
        if (expected is null) return;
        foreach (var exp in expected)
        {
            var found = actual?.FirstOrDefault(a => a.Oid == exp.Oid)
                ?? throw new RaTlsException($"expected OID {exp.Oid} ({Oids.Label(exp.Oid)}) not found in certificate");
            if (!found.Value.AsSpan().SequenceEqual(exp.ExpectedValue))
                throw new RaTlsException($"{Oids.Label(exp.Oid)} ({exp.Oid}) mismatch: got {RaTlsCertInspector.Hex(found.Value)}, expected {RaTlsCertInspector.Hex(exp.ExpectedValue)}");
        }
    }

    // -- attestation server ---------------------------------------------------

    private static QuoteVerificationResult VerifyQuote(byte[] quote, QuoteVerificationConfig config)
    {
        var body = JsonSerializer.Serialize(new { quote = Convert.ToBase64String(quote) });
        var json = PostJson(config, body, "quote verification");
        var result = ParseVerdict(json, config, "quote verification");
        return result;
    }

    /// <summary>
    /// Verifies a CPU quote plus NVIDIA GPU evidence (a "tdx-gpu" request). The GPU evidence is
    /// already bound to the leaf key through report_data; this establishes that the GPU is a
    /// genuine NVIDIA device in CC mode with an authentic, nonce-bound report.
    /// </summary>
    private static (QuoteVerificationResult, GpuAttestationResult) VerifyTdxGpu(byte[] quote, byte[] gpuEvidence, QuoteVerificationConfig config)
    {
        var body = JsonSerializer.Serialize(new
        {
            quote = Convert.ToBase64String(quote),
            type = "tdx-gpu",
            gpuQuote = Convert.ToBase64String(gpuEvidence),
        });
        using var json = PostJson(config, body, "tdx-gpu verification");
        var result = ParseVerdict(json, config, "tdx-gpu verification");
        if (!json.RootElement.TryGetProperty("gpuAttestation", out var g) || g.ValueKind != JsonValueKind.Object)
            throw new RaTlsException("tdx-gpu verification: server returned no GPU attestation result");
        var gpu = new GpuAttestationResult(
            Verified: g.TryGetProperty("verified", out var v) && v.ValueKind == JsonValueKind.True,
            Status: Str(g, "status"), Message: Str(g, "message"), Error: Str(g, "error"),
            GpuUuid: Str(g, "gpuUuid"), Driver: Str(g, "driver"), Vbios: Str(g, "vbios"),
            CcEnvironment: Str(g, "ccEnvironment"),
            MeasurementsVerified: g.TryGetProperty("measurementsVerified", out var mv) && mv.ValueKind == JsonValueKind.True);
        if (!gpu.Verified)
            throw new RaTlsException($"GPU attestation failed: status={gpu.Status} error={gpu.Error}");
        return (result, gpu);
    }

    private static JsonDocument PostJson(QuoteVerificationConfig config, string body, string what)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(config.TimeoutSecs > 0 ? config.TimeoutSecs : 10) };
        if (config.Token is not null)
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", config.Token);
        HttpResponseMessage resp;
        string respBody;
        try
        {
            resp = http.PostAsync(config.Endpoint, new StringContent(body, Encoding.UTF8, "application/json")).GetAwaiter().GetResult();
            respBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            throw new RaTlsException($"{what} request failed: {e.Message}", e);
        }
        if (!resp.IsSuccessStatusCode)
            throw new RaTlsException($"{what}: server returned HTTP {(int)resp.StatusCode}: {respBody}");
        try { return JsonDocument.Parse(respBody); }
        catch (JsonException e) { throw new RaTlsException($"failed to parse {what} response: {e.Message} (body: {respBody})", e); }
    }

    private static QuoteVerificationResult ParseVerdict(JsonDocument json, QuoteVerificationConfig config, string what)
    {
        var root = json.RootElement;
        var status = QuoteVerificationStatusExt.FromString(Str(root, "status") ?? "");
        string[]? advisories = null;
        if (root.TryGetProperty("advisoryIds", out var a) && a.ValueKind == JsonValueKind.Array)
            advisories = a.EnumerateArray().Select(e => e.GetString() ?? "").ToArray();
        var result = new QuoteVerificationResult(status, Str(root, "tcbDate"), advisories, Str(root, "tcbStatus"));

        if (result.Status != QuoteVerificationStatus.Ok && !(config.AcceptedStatuses?.Contains(result.Status) ?? false))
            throw new RaTlsException($"{what} failed: status={result.Status.ToStatusString()}, advisories=[{string.Join(", ", advisories ?? Array.Empty<string>())}]");
        // Opt-in client-side defence in depth: the relying party decides on the Intel TCB status.
        if (config.EnforceTcbStatus)
        {
            try { TcbStatuses.CheckAcceptable(result.TcbStatus, config.AcceptableTcbStatuses); }
            catch (RaTlsException e)
            {
                throw new RaTlsException($"{what} failed: {e.Message} (tcbDate={result.TcbDate}, advisories=[{string.Join(", ", advisories ?? Array.Empty<string>())}])", e);
            }
        }
        return result;
    }

    private static string? Str(JsonElement obj, string name)
        => obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

    // -- fleet chain ----------------------------------------------------------

    /// <summary>
    /// Requires the presented chain to reach one of the trust anchors (roots or intermediates),
    /// without hostname verification. The anchors are matched by identity, so an intermediate
    /// anchor is accepted although its own issuer is absent (PartialChain / UntrustedRoot above
    /// the anchor are the only excused statuses); every element up to the anchor must be clean.
    /// </summary>
    public static void VerifyFleetChain(X509Certificate2 leaf, X509Certificate2Collection? presented, X509Certificate2Collection anchors)
    {
        using var chain = new X509Chain();
        var p = chain.ChainPolicy;
        p.TrustMode = X509ChainTrustMode.CustomRootTrust;
        p.CustomTrustStore.AddRange(anchors);
        if (presented is not null) p.ExtraStore.AddRange(presented);
        p.RevocationMode = X509RevocationMode.NoCheck;
        p.DisableCertificateDownloads = true;
        var built = chain.Build(leaf);

        var anchorIdx = -1;
        for (var i = 0; i < chain.ChainElements.Count; i++)
        {
            var raw = chain.ChainElements[i].Certificate.RawData;
            if (anchors.Cast<X509Certificate2>().Any(a => a.RawData.AsSpan().SequenceEqual(raw))) { anchorIdx = i; break; }
        }
        if (anchorIdx < 0)
            throw new RaTlsException("certificate chain does not reach a trusted Privasys fleet anchor: " + Describe(chain.ChainStatus));
        if (built) return;
        for (var i = 0; i <= anchorIdx; i++)
            foreach (var s in chain.ChainElements[i].ChainElementStatus)
                if (!Excused(s.Status))
                    throw new RaTlsException($"certificate chain: {s.Status} ({s.StatusInformation.Trim()}) on {chain.ChainElements[i].Certificate.Subject}");
        foreach (var s in chain.ChainStatus)
            if (!Excused(s.Status))
                throw new RaTlsException($"certificate chain: {s.Status} ({s.StatusInformation.Trim()})");
    }

    private static bool Excused(X509ChainStatusFlags f)
        => (f & ~(X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.UntrustedRoot)) == 0;

    private static string Describe(X509ChainStatus[] statuses)
        => statuses.Length == 0 ? "no chain status" : string.Join("; ", statuses.Select(s => $"{s.Status} ({s.StatusInformation.Trim()})"));
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

/// <summary>Which verifier the server chain must satisfy at the handshake.</summary>
public enum TrustMode
{
    /// <summary>
    /// Fleet whenever evidence is requested (Challenge or Deterministic); with
    /// <see cref="AttestationMode.None"/> the chain is accepted when it satisfies Fleet or
    /// Public. An attested mode is never downgraded to Public. The default.
    /// </summary>
    Auto,
    /// <summary>
    /// The Privasys fleet anchors, or the caller anchors when given, without hostname
    /// verification: peers are dialled by IP and the identity is the evidence plus the app
    /// identity in the certificate.
    /// </summary>
    Fleet,
    /// <summary>
    /// The system's public PKI roots with ordinary hostname verification, for a host that is
    /// not an enclave (the identity provider, for example). Only valid with
    /// <see cref="AttestationMode.None"/> and without caller anchors.
    /// </summary>
    Public,
}

/// <summary>Options of an <see cref="RaTlsClient"/> connection.</summary>
public sealed class RaTlsClientOptions
{
    /// <summary>PEM file whose certificates become the fleet trust anchors of the server chain. Default: the embedded Privasys intermediates. Never combined with <see cref="TrustMode.Public"/>.</summary>
    public string? CaCertPath { get; set; }
    /// <summary>Fleet trust anchors given as certificates; takes precedence over <see cref="CaCertPath"/>. Never combined with <see cref="TrustMode.Public"/>.</summary>
    public X509Certificate2Collection? TrustAnchors { get; set; }
    /// <summary>Which verifier the server chain must satisfy: Auto (default), Fleet or Public, see <see cref="TrustMode"/>.</summary>
    public TrustMode Trust { get; set; } = TrustMode.Auto;
    /// <summary>Connect and read timeout in milliseconds (default 10000).</summary>
    public int TimeoutMs { get; set; } = 10_000;
    /// <summary>TLS SNI value and Host header of the attest request; set it to the workload hostname for per-workload leaves.</summary>
    public string? ServerName { get; set; }
    /// <summary>What to ask the server for after the handshake. Default Deterministic; Challenge needs <see cref="Exporter"/>.</summary>
    public AttestationMode Attestation { get; set; } = AttestationMode.Deterministic;
    /// <summary>Carrier of the attest messages: HTTP (default) or raw frames for non-HTTP protocols.</summary>
    public AttestFraming Framing { get; set; } = AttestFraming.Http;
    /// <summary>RFC 8446 section 7.5 exporter of the connection, required for Challenge mode and the mutual leg.</summary>
    public TlsExporter? Exporter { get; set; }
    /// <summary>
    /// Fixes the 32-byte challenge context of the first exchange, for a verifier relaying a
    /// challenge chosen elsewhere (section 3.3). Default: fresh random. Re-attestation always
    /// draws a fresh context.
    /// </summary>
    public byte[]? Context { get; set; }
    /// <summary>Client certificate for mutual RA-TLS (a v2 identity: leaf key, chain, OIDs, no evidence).</summary>
    public X509Certificate2? ClientCertificate { get; set; }
    /// <summary>Produces this client's evidence when the server requires it on a mutual leg.</summary>
    public ClientEvidenceSource? ClientEvidence { get; set; }
}

/// <summary>
/// A verified RA-TLS v2 connection: TLS 1.3 to a Privasys enclave, server chain checked
/// against the fleet anchors, evidence obtained after the handshake and verified against a
/// policy with <see cref="VerifyCertificate"/>.
///
/// Attestation modes: <see cref="AttestationMode.Deterministic"/> is the default of this
/// SDK. <see cref="AttestationMode.Challenge"/> (the Level 3 binding, default in the Go and
/// Rust SDKs) needs the RFC 8446 section 7.5 exporter keyed by the connection's
/// exporter_master_secret, and System.Net.Security.SslStream exposes no such API on the
/// net8.0 target of this project (nor on .NET 10, checked against Microsoft.NETCore.App.Ref
/// 10.0.3). Challenge therefore throws <see cref="NotSupportedException"/> unless the caller
/// supplies <see cref="RaTlsClientOptions.Exporter"/> from a TLS stack that exposes the
/// exporter; the exchange, the recipes and the verifier are complete and are exercised by
/// the test project through a supplied exporter. The mutual leg (client evidence) has the
/// same requirement.
///
/// The client speaks HTTP/1.1 (one request at a time) or raw frames; it does not speak HTTP/2.
/// </summary>
public sealed class RaTlsClient : IDisposable
{
    /// <summary>Request header through which Caddy exposes the connection tag (none | deterministic | challenge) to the workload.</summary>
    public const string AttestationHeader = "X-Privasys-Attestation";
    /// <summary>ALPN token that routes the connection to the platform gateway's splice path.</summary>
    public const string RaTlsAlpnProto = "privasys-ratls/1";

    private readonly string _host;
    private readonly int _port;
    private readonly RaTlsClientOptions _options;

    private TcpClient? _tcp;
    private SslStream? _ssl;
    private X509Certificate2? _peerCert;
    private X509Certificate2Collection _peerChain = new();
    private X509Certificate2Collection? _anchors;
    private bool _fleetOnly;
    private TrustMode? _trustResolved;
    private string? _chainError;
    private Evidence? _evidence;
    private VerificationPolicy? _lastPolicy;

    public RaTlsClient(string host, int port = 443, RaTlsClientOptions? options = null)
    {
        _host = host;
        _port = port;
        _options = options ?? new RaTlsClientOptions();
        ValidateTrust(_options);
    }

    /// <summary>Public trust never carries an attested mode (no downgrade) nor fleet anchors it would not use.</summary>
    private static void ValidateTrust(RaTlsClientOptions o)
    {
        if (o.Trust != TrustMode.Public) return;
        if (o.Attestation != AttestationMode.None)
            throw new ArgumentException($"RaTlsClientOptions.Trust Public cannot be combined with attestation mode {o.Attestation}: an attested connection must chain to the fleet anchors", nameof(RaTlsClientOptions.Trust));
        if (o.TrustAnchors is not null || o.CaCertPath is not null)
            throw new ArgumentException("RaTlsClientOptions.TrustAnchors and CaCertPath are fleet anchors and cannot be combined with Trust Public", nameof(RaTlsClientOptions.Trust));
    }

    /// <summary>Convenience constructor: anchors from a PEM file (or the embedded Privasys anchors when null).</summary>
    public RaTlsClient(string host, int port, string? caCertPath, int timeoutMs = 10_000)
        : this(host, port, new RaTlsClientOptions { CaCertPath = caCertPath, TimeoutMs = timeoutMs }) { }

    public RaTlsClientOptions Options => _options;

    /// <summary>The mode this connection was opened in.</summary>
    public AttestationMode AttestationMode => _options.Attestation;

    /// <summary>The configured trust mode (Auto, Fleet or Public).</summary>
    public TrustMode TrustMode => _options.Trust;

    /// <summary>
    /// The verifier the server chain satisfied, Fleet or Public; null before <see cref="Connect"/>.
    /// Public only ever appears with <see cref="AttestationMode.None"/>.
    /// </summary>
    public TrustMode? TrustResolved => _trustResolved;

    /// <summary>
    /// The connection tag as the server records it, "none" | "deterministic" | "challenge":
    /// the value the workload sees in <see cref="AttestationHeader"/> for requests on this connection.
    /// </summary>
    public string AttestationTag => _evidence?.Mode.ToWire() ?? AttestationMode.None.ToWire();

    /// <summary>The evidence obtained for this connection, null in None mode. Verified only after <see cref="VerifyCertificate"/> returned.</summary>
    public Evidence? Evidence => _evidence;

    /// <summary>The server's leaf certificate.</summary>
    public X509Certificate2? PeerCertificate => _peerCert;

    /// <summary>The chain the server presented, leaf first.</summary>
    public X509Certificate2Collection PeerCertificates => _peerChain;

    /// <summary>The TLS stream, for callers that take over the connection after verification.</summary>
    public SslStream Stream => _ssl ?? throw new InvalidOperationException("not connected");

    public string TlsVersion => _ssl?.SslProtocol.ToString() ?? "";
    public string CipherSuite => _ssl?.NegotiatedCipherSuite.ToString() ?? "";

    /// <summary>
    /// Connects, verifies the server chain during the handshake per <see cref="RaTlsClientOptions.Trust"/>
    /// (the fleet anchors for any attested connection) and runs the evidence exchange before
    /// any application data. Any failure closes the connection and throws: a caller never
    /// gets a client whose evidence is missing in a mode that asked for it.
    /// </summary>
    public void Connect()
    {
        if (_ssl is not null) throw new InvalidOperationException("already connected");
        ValidateTrust(_options);
        var publicOnly = _options.Trust == TrustMode.Public;
        _fleetOnly = _options.Trust == TrustMode.Fleet || _options.Attestation != AttestationMode.None;
        _anchors = publicOnly ? null : _options.TrustAnchors
            ?? (_options.CaCertPath is not null ? PrivasysTrustAnchors.FromPemFile(_options.CaCertPath) : PrivasysTrustAnchors.Load());

        _tcp = new TcpClient { SendTimeout = _options.TimeoutMs, ReceiveTimeout = _options.TimeoutMs };
        try
        {
            _tcp.Connect(_host, _port);
            _ssl = new SslStream(_tcp.GetStream(), leaveInnerStreamOpen: false, ValidateCert);

            // ALPN: the Privasys marker first (gateway splice path), then http/1.1 so the
            // enclave's TLS server can negotiate a real HTTP version. Never h2: this client
            // speaks HTTP/1.1 over the raw stream.
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = _options.ServerName ?? _host,
                EnabledSslProtocols = SslProtocols.Tls13,
                ApplicationProtocols = new List<SslApplicationProtocol> { new(RaTlsAlpnProto), SslApplicationProtocol.Http11 },
            };
            if (_fleetOnly)
            {
                // Chain policy for the stack's own build: our anchors, no revocation, no
                // downloads. ValidateCert performs the fleet check independently.
                var chainPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    RevocationMode = X509RevocationMode.NoCheck,
                    DisableCertificateDownloads = true,
                };
                chainPolicy.CustomTrustStore.AddRange(_anchors!);
                sslOptions.CertificateChainPolicy = chainPolicy;
            }
            // Otherwise the stack builds with system trust and checks the hostname against
            // TargetHost: the SslPolicyErrors it reports are the public PKI verdict that
            // ValidateCert consults (alone for Public, after the fleet check for Auto).
            if (_options.ClientCertificate is not null)
                sslOptions.ClientCertificates = new X509Certificate2Collection(_options.ClientCertificate);

            try { _ssl.AuthenticateAsClient(sslOptions); }
            catch (AuthenticationException e)
            {
                throw new RaTlsException(_chainError ?? "TLS connect: " + e.Message, e);
            }
            if (_peerCert is null) throw new RaTlsException("RA-TLS: server presented no certificate");

            Attest(_options.Attestation, _options.Context);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    private bool ValidateCert(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null)
        {
            _chainError = "RA-TLS: server presented no certificate";
            return false;
        }
        _peerCert = CopyCert(certificate);
        _peerChain = new X509Certificate2Collection();
        if (chain is not null)
            foreach (var el in chain.ChainElements)
                _peerChain.Add(CopyCert(el.Certificate));
        var presented = new X509Certificate2Collection();
        foreach (var c in _peerChain)
            if (!c.RawData.AsSpan().SequenceEqual(_peerCert.RawData)) presented.Add(c);

        if (_options.Trust == TrustMode.Public)
        {
            if (errors == SslPolicyErrors.None)
            {
                _trustResolved = TrustMode.Public;
                return true;
            }
            _chainError = "RA-TLS: " + DescribePublicVerdict(errors, chain);
            return false;
        }
        try
        {
            // Fleet: hostname mismatch is not an error, peers are dialled by IP and
            // identified by measurement and app id. The chain is the only handshake-time check.
            RaTlsVerifier.VerifyFleetChain(_peerCert, presented, _anchors!);
            _trustResolved = TrustMode.Fleet;
            return true;
        }
        catch (RaTlsException e)
        {
            if (_fleetOnly)
            {
                _chainError = "RA-TLS: " + e.Message;
                return false;
            }
            // Auto without evidence: the public PKI verdict of the stack's own build is the
            // second chance, on this same connection.
            if (errors == SslPolicyErrors.None)
            {
                _trustResolved = TrustMode.Public;
                return true;
            }
            _chainError = $"RA-TLS: certificate chain reaches neither a Privasys fleet anchor nor a public PKI root for \"{_options.ServerName ?? _host}\" (trust Auto, no evidence requested): {e.Message}; {DescribePublicVerdict(errors, chain)}";
            return false;
        }
    }

    private static string DescribePublicVerdict(SslPolicyErrors errors, X509Chain? chain)
    {
        var statuses = chain is null ? "" : string.Join("; ", chain.ChainStatus.Select(s => $"{s.Status} ({s.StatusInformation.Trim()})"));
        return $"public PKI verification failed: {errors}" + (statuses.Length > 0 ? $" [{statuses}]" : "");
    }

    private static X509Certificate2 CopyCert(X509Certificate cert)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));
#else
        return new X509Certificate2(cert.Export(X509ContentType.Cert));
#endif
    }

    // -- evidence exchange ----------------------------------------------------

    /// <summary>Runs the exchange for <paramref name="mode"/> and stores the result; policy verification is <see cref="VerifyCertificate"/>.</summary>
    private void Attest(AttestationMode mode, byte[]? fixedContext = null)
    {
        if (mode == AttestationMode.None)
        {
            _evidence = null;
            return;
        }
        var spki = RaTlsCertInspector.SpkiDerOf(_peerCert!);
        byte[]? context = null, hctx = null;
        if (mode == AttestationMode.Challenge)
        {
            if (fixedContext is not null && fixedContext.Length != RaTlsAttest.ContextLen)
                throw new RaTlsException($"RaTlsClientOptions.Context must be {RaTlsAttest.ContextLen} bytes");
            context = fixedContext ?? RandomNumberGenerator.GetBytes(RaTlsAttest.ContextLen);
            hctx = ExportHctx(RaTlsAttest.ExporterLabelServer, context);
        }
        var (status, body) = AttestRoundTrip(RaTlsAttest.BuildRequest(mode, spki, context));
        var ev = RaTlsAttest.ParseResponse(status, body, mode, DateTime.UtcNow, context, hctx);
        _evidence = ev;
        if (ev.ClientEvidenceRequired) Present(ev);
    }

    /// <summary>Answers a server that requires client evidence (mutual leg, section 5).</summary>
    private void Present(Evidence ev)
    {
        var source = _options.ClientEvidence
            ?? throw new RaTlsException("server requires client evidence and RaTlsClientOptions.ClientEvidence is not set");
        var clientCert = _options.ClientCertificate
            ?? throw new RaTlsException("server requires client evidence but no client certificate was presented");
        var spki = RaTlsCertInspector.SpkiDerOf(clientCert);
        var hctx = ExportHctx(RaTlsAttest.ExporterLabelClient, ev.ClientContext!);
        var request = new ClientEvidenceRequest(spki, ev.ClientContext!, hctx,
            RaTlsVerifier.ClientReportData(spki, ev.ClientContext!, hctx, null));
        ClientEvidence ce;
        try { ce = source(request); }
        catch (Exception e) when (e is not RaTlsException) { throw new RaTlsException("client evidence: " + e.Message, e); }
        if (ce is null || ce.Quote.Length == 0)
            throw new RaTlsException("client evidence source returned no quote");

        var (status, body) = AttestRoundTrip(RaTlsAttest.BuildPresent(ev.ClientContext!, ce));
        if (_options.Framing == AttestFraming.Raw)
        {
            RaTlsAttest.CheckPresentAck(body);
            return;
        }
        if (status != 204 && status != 200)
            throw new RaTlsException($"client evidence rejected ({status}): {Encoding.UTF8.GetString(body).Trim()}");
    }

    /// <summary>The 32-byte exporter value of this connection for a label and context.</summary>
    private byte[] ExportHctx(string label, byte[] context)
    {
        if (_ssl!.SslProtocol != SslProtocols.Tls13)
            throw new RaTlsException($"exporter needs TLS 1.3, negotiated {_ssl.SslProtocol}");
        var exporter = _options.Exporter ?? throw new NotSupportedException(
            "RA-TLS challenge mode needs the RFC 8446 section 7.5 TLS exporter (keyed by exporter_master_secret) of this connection, " +
            "which System.Net.Security.SslStream does not expose on .NET 8 (nor on .NET 10). Use AttestationMode.Deterministic, " +
            "the default of this SDK, or supply RaTlsClientOptions.Exporter from a TLS stack that exposes the exporter.");
        var hctx = exporter(label, context, RaTlsAttest.HctxLen);
        if (hctx is null || hctx.Length != RaTlsAttest.HctxLen)
            throw new RaTlsException($"exporter returned {hctx?.Length ?? 0} bytes, want {RaTlsAttest.HctxLen}");
        return hctx;
    }

    private (int Status, byte[] Body) AttestRoundTrip(byte[] body)
    {
        if (_options.Framing == AttestFraming.Raw)
        {
            RaTlsAttest.WriteFrame(_ssl!, body);
            return (200, RaTlsAttest.ReadFrame(_ssl!));
        }
        var (status, resp) = HttpDo("POST", RaTlsAttest.AttestPath, body);
        if (resp.Length > RaTlsAttest.MaxFrame)
            throw new RaTlsException($"attest response too large: {resp.Length}");
        return (status, resp);
    }

    /// <summary>
    /// Repeats the evidence exchange with a fresh context and, when a policy was verified
    /// before, verifies the new evidence against it. Long-lived connections call it every few
    /// minutes and drop the connection on error. Not possible on the raw binding: reconnect.
    /// </summary>
    public CertInfo? Reattest()
    {
        if (_options.Attestation == AttestationMode.None)
            throw new RaTlsException("connection was opened with AttestationMode.None");
        if (_options.Framing == AttestFraming.Raw)
            throw new RaTlsException("re-attestation is not possible on the raw binding; reconnect instead");
        Attest(_options.Attestation);
        return _lastPolicy is null ? null : VerifyCertificate(_lastPolicy);
    }

    // -- inspection and verification -----------------------------------------

    /// <summary>
    /// The server's leaf with the evidence of the connection attached UNVERIFIED (Quote,
    /// GpuEvidence, Attestation, Evidence) so measurements can be displayed.
    /// <see cref="VerifyCertificate"/> is what verifies it.
    /// </summary>
    public CertInfo InspectCertificate()
    {
        if (_peerCert is null) return new CertInfo();
        var info = RaTlsCertInspector.Inspect(_peerCert);
        if (_evidence is { } ev)
            info = info with
            {
                Quote = RaTlsCertInspector.QuoteInfoOf(ev),
                GpuEvidence = ev.GpuEvidence,
                Attestation = ev.Mode,
                Evidence = ev,
            };
        return info;
    }

    /// <summary>
    /// Verifies the server's leaf and the evidence obtained for this connection against a
    /// policy (see <see cref="RaTlsVerifier.VerifyEvidence"/>). In None mode only the
    /// certificate extensions are verified and the result carries no evidence.
    /// </summary>
    public CertInfo VerifyCertificate(VerificationPolicy policy)
    {
        if (_peerCert is null) throw new RaTlsException("no peer certificate");
        _lastPolicy = policy;
        return _options.Attestation == AttestationMode.None
            ? RaTlsVerifier.VerifyCertificateExtensions(_peerCert, policy)
            : RaTlsVerifier.VerifyEvidence(_peerCert, _evidence, policy);
    }

    // -- HTTP/1.1 -------------------------------------------------------------

    /// <summary>Sends one HTTP/1.1 request over the connection and returns the status and body (Content-Length or chunked).</summary>
    public (int StatusCode, byte[] Body) HttpDo(string method, string path, byte[]? body = null,
        IReadOnlyDictionary<string, string>? headers = null, bool connectionClose = false)
    {
        SendHttpRequest(method, path, body, headers, connectionClose);
        return RecvHttpResponse();
    }

    private void SendHttpRequest(string method, string path, byte[]? body, IReadOnlyDictionary<string, string>? headers, bool connectionClose)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\nHost: ").Append(_options.ServerName ?? _host).Append("\r\n");
        var hasContentType = false;
        if (headers is not null)
            foreach (var (k, v) in headers)
            {
                if (k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) hasContentType = true;
                sb.Append(k).Append(": ").Append(v).Append("\r\n");
            }
        if (body is { Length: > 0 })
        {
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
            if (!hasContentType) sb.Append("Content-Type: application/json\r\n");
        }
        if (connectionClose) sb.Append("Connection: close\r\n");
        sb.Append("\r\n");
        var ssl = Stream;
        ssl.Write(Encoding.ASCII.GetBytes(sb.ToString()));
        if (body is { Length: > 0 }) ssl.Write(body);
        ssl.Flush();
    }

    private (int StatusCode, byte[] Body) RecvHttpResponse()
    {
        var ssl = Stream;
        var buf = new MemoryStream();
        var tmp = new byte[4096];
        int headerEnd;
        while ((headerEnd = FindHeaderEnd(buf.GetBuffer(), (int)buf.Length)) < 0)
        {
            var n = ssl.Read(tmp, 0, tmp.Length);
            if (n == 0) throw new RaTlsException("connection closed before HTTP headers received");
            buf.Write(tmp, 0, n);
        }
        var raw = buf.GetBuffer();
        var total = (int)buf.Length;
        var headerLines = Encoding.ASCII.GetString(raw, 0, headerEnd).Split("\r\n");
        var bodyStart = headerEnd + 4;

        var parts = headerLines[0].Split(' ', 3);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var statusCode))
            throw new RaTlsException("malformed HTTP status line: " + headerLines[0]);

        // Transfer-Encoding matters as much as Content-Length: Go's http server chunks any
        // body larger than its 2 KiB buffer, so ignoring chunked framing truncates bodies.
        var contentLength = 0;
        var chunked = false;
        foreach (var line in headerLines.Skip(1))
        {
            if (line.StartsWith("content-length:", StringComparison.OrdinalIgnoreCase))
                contentLength = int.Parse(line.Split(':', 2)[1].Trim(), CultureInfo.InvariantCulture);
            else if (line.StartsWith("transfer-encoding:", StringComparison.OrdinalIgnoreCase))
                chunked = line.Split(':', 2)[1].Contains("chunked", StringComparison.OrdinalIgnoreCase);
        }

        var rest = new MemoryStream();
        if (bodyStart < total) rest.Write(raw, bodyStart, total - bodyStart);
        if (chunked) return (statusCode, DecodeChunked(rest, tmp));

        while (rest.Length < contentLength)
        {
            var n = ssl.Read(tmp, 0, tmp.Length);
            if (n == 0) break;
            rest.Write(tmp, 0, n);
        }
        var body = rest.ToArray();
        return (statusCode, body.Length > contentLength ? body[..contentLength] : body);
    }

    /// <summary>Chunked transfer coding (RFC 9112 section 7.1); trailer fields are not expected from our servers.</summary>
    private byte[] DecodeChunked(MemoryStream rest, byte[] tmp)
    {
        var ssl = Stream;
        var body = new MemoryStream();
        var pos = 0;
        while (true)
        {
            int lineEnd;
            while ((lineEnd = FindCrLf(rest.GetBuffer(), (int)rest.Length, pos)) < 0)
            {
                var n = ssl.Read(tmp, 0, tmp.Length);
                if (n == 0) throw new RaTlsException("connection closed inside chunked body");
                rest.Write(tmp, 0, n);
            }
            var sizeLine = Encoding.ASCII.GetString(rest.GetBuffer(), pos, lineEnd - pos);
            var size = Convert.ToInt32(sizeLine.Split(';')[0].Trim(), 16);
            pos = lineEnd + 2;
            while (rest.Length < pos + size + 2)
            {
                var n = ssl.Read(tmp, 0, tmp.Length);
                if (n == 0) throw new RaTlsException("connection closed inside chunked body");
                rest.Write(tmp, 0, n);
            }
            if (size == 0) return body.ToArray();
            body.Write(rest.GetBuffer(), pos, size);
            pos += size + 2;
        }
    }

    private static int FindCrLf(byte[] buf, int len, int from)
    {
        for (var i = from; i <= len - 2; i++)
            if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
        return -1;
    }

    private static int FindHeaderEnd(byte[] buf, int len)
    {
        for (var i = 0; i <= len - 4; i++)
            if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') return i;
        return -1;
    }

    private static IReadOnlyDictionary<string, string>? Bearer(string? token)
        => token is null ? null : new Dictionary<string, string> { ["Authorization"] = "Bearer " + token };

    private Dictionary<string, JsonElement> GetJson(string path, string? authToken, string what)
    {
        var (status, body) = HttpDo("GET", path, headers: Bearer(authToken));
        if (status != 200) throw new RaTlsException($"{what} failed ({status}): {Encoding.UTF8.GetString(body)}");
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body) ?? new();
    }

    /// <summary>GET /healthz, liveness probe (no auth).</summary>
    public Dictionary<string, JsonElement> Healthz() => GetJson("/healthz", null, "healthz");

    /// <summary>GET /readyz, readiness probe (monitoring+).</summary>
    public Dictionary<string, JsonElement> Readyz(string? authToken = null) => GetJson("/readyz", authToken, "readyz");

    /// <summary>POST /data: sends a module command and returns the response bytes.</summary>
    public byte[] SendData(byte[] data, string? authToken = null)
    {
        var (status, body) = HttpDo("POST", "/data", data, Bearer(authToken));
        if (status != 200) throw new RaTlsException($"send_data failed ({status}): {Encoding.UTF8.GetString(body)}");
        return body;
    }

    /// <summary>POST /shutdown: requests a graceful shutdown (manager role).</summary>
    public void Shutdown(string? authToken = null)
    {
        var (status, body) = HttpDo("POST", "/shutdown", headers: Bearer(authToken), connectionClose: true);
        if (status != 200) throw new RaTlsException($"shutdown failed ({status}): {Encoding.UTF8.GetString(body)}");
    }

    // -- raw frames -----------------------------------------------------------

    /// <summary>Writes one u32 big-endian length-prefixed frame (raw binding protocols).</summary>
    public void SendFrame(byte[] payload) => RaTlsAttest.WriteFrame(Stream, payload);

    /// <summary>Reads one u32 big-endian length-prefixed frame.</summary>
    public byte[] ReceiveFrame() => RaTlsAttest.ReadFrame(Stream);

    public void Dispose()
    {
        _ssl?.Dispose();
        _tcp?.Dispose();
        _ssl = null;
        _tcp = null;
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
        Console.WriteLine($"  Not Before   : {info.NotBefore:o}");
        Console.WriteLine($"  Not After    : {info.NotAfter:o}");
        Console.WriteLine($"  Sig Algo     : {info.SignatureAlgorithm}");
        Console.WriteLine($"  PubKey SHA256: {info.PubKeySha256}");
        Console.WriteLine($"  Attestation  : {info.Attestation.ToWire()}");
        if (info.V1Leaf) Console.WriteLine("  ** v1 certificate (evidence inside the certificate): rejected by a v2 verifier **");

        if (info.Quote is { } q)
        {
            Console.WriteLine();
            Console.WriteLine("  ** Attestation evidence **");
            Console.WriteLine($"    Format    : {q.Oid}  ({q.Label})");
            Console.WriteLine($"    Size      : {q.Raw.Length} bytes");
            if (q.IsMock) Console.WriteLine("    ** MOCK QUOTE **");
            if (q.Version.HasValue) Console.WriteLine($"    Version   : {q.Version}");
            if (q.ReportData is not null) Console.WriteLine($"    ReportData: {Hex(q.ReportData)}");
            if (info.Evidence is { } ev)
            {
                Console.WriteLine($"    TEE       : {ev.Tee}");
                Console.WriteLine($"    QuoteTime : {ev.QuoteTimeRaw}");
                if (ev.GpuEvidence is { Length: > 0 }) Console.WriteLine($"    GPU       : {ev.GpuEvidence.Length} bytes of evidence");
            }

            if (q.Oid == Oids.SGXQuote)
            {
                var format = SgxQuoteLayout.DetectFormat(q.Raw);
                var o = SgxQuoteLayout.Offsets(format);
                if (q.Raw.Length >= o.MinSize)
                {
                    Console.WriteLine($"    Format    : {format}");
                    Console.WriteLine($"    MRENCLAVE : {Hex(q.Raw.AsSpan(o.MrEnclaveOff, 32))}");
                    Console.WriteLine($"    MRSIGNER  : {Hex(q.Raw.AsSpan(o.MrSignerOff, 32))}");
                }
            }
            else if (q.Oid == Oids.TDXQuote && q.Raw.Length >= TdxQuoteLayout.MinSize)
            {
                Console.WriteLine($"    MRTD      : {Hex(q.Raw.AsSpan(TdxQuoteLayout.MrTdOff, 48))}");
                Console.WriteLine($"    RTMR1     : {Hex(q.Raw.AsSpan(TdxQuoteLayout.Rtmr1Off, 48))}");
                Console.WriteLine($"    RTMR2     : {Hex(q.Raw.AsSpan(TdxQuoteLayout.Rtmr2Off, 48))}");
            }
            else if (q.Oid == Oids.EvidenceSEVSNPReport && q.Raw.Length >= SevSnpReportLayout.MinSize)
            {
                Console.WriteLine($"    Measurement: {Hex(q.Raw.AsSpan(SevSnpReportLayout.MeasurementOff, 48))}");
                Console.WriteLine($"    HostData   : {Hex(q.Raw.AsSpan(SevSnpReportLayout.HostDataOff, 32))}");
            }
            Console.WriteLine($"    Preview   : {Hex(q.Raw.AsSpan(0, Math.Min(32, q.Raw.Length)))}...");
        }
        else
        {
            Console.WriteLine();
            Console.WriteLine("  No attestation evidence on this connection.");
        }

        if (info.CustomOids.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("  ** Privasys Configuration OIDs **");
            foreach (var ext in info.CustomOids)
                Console.WriteLine($"    {ext.Label} ({ext.Oid}): {Hex(ext.Value)}");
        }

        if (info.QuoteVerification is { } qv)
        {
            Console.WriteLine();
            Console.WriteLine("  ** Quote Verification **");
            Console.WriteLine($"    Status    : {qv.Status.ToStatusString()}");
            if (qv.TcbDate is not null) Console.WriteLine($"    TCB Date  : {qv.TcbDate}");
            if (qv.TcbStatus is not null) Console.WriteLine($"    TCB Status: {qv.TcbStatus}");
            if (qv.AdvisoryIds is { Length: > 0 }) Console.WriteLine($"    Advisories: {string.Join(", ", qv.AdvisoryIds)}");
        }

        if (info.GpuAttestation is { } gpu)
        {
            Console.WriteLine();
            Console.WriteLine("  ** GPU Attestation **");
            Console.WriteLine($"    Verified  : {gpu.Verified}");
            if (gpu.Status is not null) Console.WriteLine($"    Status    : {gpu.Status}");
            if (gpu.GpuUuid is not null) Console.WriteLine($"    GPU UUID  : {gpu.GpuUuid}");
            if (gpu.Driver is not null) Console.WriteLine($"    Driver    : {gpu.Driver}");
        }
    }

    private static string Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(data).ToLowerInvariant();
}
