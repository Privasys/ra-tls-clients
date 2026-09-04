// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Privasys.RaTls.Tests;

/// <summary>Shared helpers: byte patterns, a generated root / intermediate / leaf chain, fake quotes, a stub exporter.</summary>
internal static class TestSupport
{
    public static byte[] Rep(byte b, int n)
    {
        var a = new byte[n];
        Array.Fill(a, b);
        return a;
    }

    public static byte[] Hex(string s) => Convert.FromHexString(s);
    public static string ToHex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    /// <summary>The repository root, found by walking up from the test assembly to tests/vectors/ratls-v2.</summary>
    public static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "tests", "vectors", "ratls-v2"))) return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("repository root (tests/vectors/ratls-v2) not found above " + AppContext.BaseDirectory);
    }

    public static X509Extension PrivasysExt(string oid, byte[] value) => new(new Oid(oid), value, false);
    public static X509Extension PrivasysExt(string oid, string value) => PrivasysExt(oid, Encoding.UTF8.GetBytes(value));

    /// <summary>A minimal raw TDX quote (version 4) carrying reportData and fixed MRTD / RTMR fills.</summary>
    public static byte[] TdxQuoteWith(byte[] reportData, byte mrtd = 0xAA, byte rtmr1 = 0xB1, byte rtmr2 = 0xB2)
    {
        var q = new byte[TdxQuoteLayout.MinSize];
        q[0] = 4;
        q.AsSpan(TdxQuoteLayout.MrTdOff, 48).Fill(mrtd);
        q.AsSpan(TdxQuoteLayout.Rtmr1Off, 48).Fill(rtmr1);
        q.AsSpan(TdxQuoteLayout.Rtmr2Off, 48).Fill(rtmr2);
        reportData.CopyTo(q, TdxQuoteLayout.ReportDataOff);
        return q;
    }

    /// <summary>A minimal SGX DCAP v3 quote carrying reportData and fixed MRENCLAVE / MRSIGNER fills.</summary>
    public static byte[] SgxQuoteWith(byte[] reportData, byte mrenclave = 0xA1, byte mrsigner = 0xA2)
    {
        var q = new byte[SgxQuoteLayout.MinSize];
        q[0] = 3;
        q.AsSpan(SgxQuoteLayout.MrEnclaveOff, 32).Fill(mrenclave);
        q.AsSpan(SgxQuoteLayout.MrSignerOff, 32).Fill(mrsigner);
        reportData.CopyTo(q, SgxQuoteLayout.ReportDataOff);
        return q;
    }

    /// <summary>
    /// A stand-in for the TLS exporter, shared by the loopback client and server so the
    /// challenge flow can be exercised without a TLS stack that exposes exporter_master_secret.
    /// </summary>
    public static byte[] StubExporter(string label, byte[] context, int length)
    {
        var input = Encoding.ASCII.GetBytes(label).Concat(context).ToArray();
        return HMACSHA256.HashData(Encoding.ASCII.GetBytes("stub-exporter"), input)[..length];
    }

    public sealed class Chain : IDisposable
    {
        public X509Certificate2 Root { get; }
        public X509Certificate2 Intermediate { get; }
        public X509Certificate2 Leaf { get; }
        public X509Certificate2Collection Anchors => new(new X509Certificate2(Intermediate.RawData));

        public Chain(X509Certificate2 root, X509Certificate2 intermediate, X509Certificate2 leaf)
        {
            Root = root;
            Intermediate = intermediate;
            Leaf = leaf;
        }

        public void Dispose()
        {
            Root.Dispose();
            Intermediate.Dispose();
            Leaf.Dispose();
        }
    }

    /// <summary>
    /// A self-signed server certificate (SAN 127.0.0.1 and localhost) under no anchor at all:
    /// a host that is not an enclave. Returned as a Chain whose three members are the same
    /// certificate so the FakeServer can serve it.
    /// </summary>
    public static Chain MakeSelfSigned(string subject = "CN=self-signed")
    {
        var now = DateTimeOffset.UtcNow;
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        san.AddDnsName("localhost");
        req.CertificateExtensions.Add(san.Build());
        using var ephemeral = req.CreateSelfSigned(now.AddHours(-1), now.AddHours(24));
        var leaf = new X509Certificate2(ephemeral.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
        return new Chain(new X509Certificate2(leaf.RawData), new X509Certificate2(leaf.RawData), leaf);
    }

    /// <summary>Generates root -> intermediate -> leaf (P-256), the leaf with a persisted private key usable by SslStream.</summary>
    public static Chain MakeChain(IEnumerable<X509Extension>? leafExtensions = null, string leafSubject = "CN=enclave")
    {
        var now = DateTimeOffset.UtcNow;

        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootReq = new CertificateRequest("CN=Test Root CA", rootKey, HashAlgorithmName.SHA256);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        var root = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

        using var interKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var interReq = new CertificateRequest("CN=Test Intermediate CA", interKey, HashAlgorithmName.SHA256);
        interReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        interReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        interReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(interReq.PublicKey, false));
        interReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        var inter = interReq.Create(root, now.AddDays(-1), now.AddDays(20), new byte[] { 2 }).CopyWithPrivateKey(interKey);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest(leafSubject, leafKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2") }, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        san.AddDnsName("localhost");
        leafReq.CertificateExtensions.Add(san.Build());
        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(inter, true, false));
        foreach (var ext in leafExtensions ?? Array.Empty<X509Extension>())
            leafReq.CertificateExtensions.Add(ext);
        var leafNoKey = leafReq.Create(inter, now.AddHours(-1), now.AddHours(24), new byte[] { 3 });
        using var leafEphemeral = leafNoKey.CopyWithPrivateKey(leafKey);
        // SChannel needs a persisted key: round-trip through PFX.
        var leaf = new X509Certificate2(leafEphemeral.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);

        return new Chain(root, inter, leaf);
    }
}
