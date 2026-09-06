// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// The TLS transport under an RaTlsClient connection.
//
// The client needs three things from its TLS stack: a TLS 1.3 handshake whose
// server chain it validates itself (fleet anchors, or the public PKI verdict
// for a connection that requests no evidence), a stream for the evidence
// exchange and the application protocol, and the RFC 8446 section 7.5
// exporter for the challenge binding and the mutual leg. System.Net.Security
// .SslStream offers the first two and no exporter (dotnet/runtime#112529 is
// still a proposal), so this SDK ships two transports:
//
//   - SslStreamTransport (default): the base class library, deterministic mode
//     unless the caller supplies RaTlsClientOptions.Exporter;
//   - Privasys.RaTls.BouncyCastle.BouncyCastleTransport (separate project and
//     package): Bouncy Castle's managed TLS 1.3 client, exporter available, so
//     challenge mode, re-attestation bound to the connection and the mutual
//     leg all work.
//
// A transport authenticates, hands the received chain to the client's
// validator, and exposes the stream. It never decides trust on its own.

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Privasys.RaTls;

/// <summary>
/// The client's chain validator, called by a transport once during the handshake with the
/// server's leaf and the rest of the presented chain. <paramref name="publicErrors"/> and
/// <paramref name="publicChain"/> are the public-PKI verdict of the stack for the target host
/// (system roots, hostname), meaningful only when the connection is not fleet-only; a
/// fleet-only handshake passes <see cref="SslPolicyErrors.None"/> and null. Returns null to
/// accept the chain or the error that rejects it (the transport then fails the handshake
/// with that message).
/// </summary>
public delegate string? ChainValidator(X509Certificate2 leaf, X509Certificate2Collection presented, SslPolicyErrors publicErrors, X509Chain? publicChain);

/// <summary>What a transport needs to run the handshake of one connection.</summary>
public sealed class TlsConnectOptions
{
    /// <summary>TLS SNI value and, for the public verdict, the name the leaf must match.</summary>
    public string TargetHost { get; set; } = "";
    /// <summary>ALPN protocols in preference order (the Privasys marker first, then http/1.1).</summary>
    public IReadOnlyList<string> Alpn { get; set; } = Array.Empty<string>();
    /// <summary>
    /// True when the chain must reach a fleet anchor (any attested mode, or trust Fleet): the
    /// transport skips the public-PKI build and the validator does the fleet check. False for
    /// Auto or Public without evidence, where the stack's public verdict is passed to the validator.
    /// </summary>
    public bool FleetOnly { get; set; }
    /// <summary>The fleet anchors, for a stack that builds the chain itself; null when not fleet-only.</summary>
    public X509Certificate2Collection? Anchors { get; set; }
    /// <summary>Client certificate (with private key) to present when the server asks for one.</summary>
    public X509Certificate2? ClientCertificate { get; set; }
    /// <summary>Read and write timeout in milliseconds.</summary>
    public int TimeoutMs { get; set; } = 10_000;
    /// <summary>The client's validator, called once with the received chain.</summary>
    public ChainValidator Validate { get; set; } = (_, _, _, _) => "no validator";
}

/// <summary>A TLS 1.3 client transport for <see cref="RaTlsClient"/>. One instance serves one connection.</summary>
public interface ITlsTransport : IDisposable
{
    /// <summary>
    /// Runs the handshake over <paramref name="network"/>, validating the server chain through
    /// <see cref="TlsConnectOptions.Validate"/>. Throws <see cref="RaTlsException"/> with the
    /// validator's error when the chain is rejected, or with the stack's message otherwise.
    /// </summary>
    void Connect(Stream network, TlsConnectOptions options);

    /// <summary>The TLS stream, valid after <see cref="Connect"/>.</summary>
    Stream Stream { get; }

    /// <summary>The negotiated protocol version, "Tls13" on every Privasys runtime.</summary>
    string TlsVersion { get; }

    /// <summary>The negotiated cipher suite name.</summary>
    string CipherSuite { get; }

    /// <summary>True when <see cref="ExportKeyingMaterial"/> is available on this transport.</summary>
    bool SupportsExporter { get; }

    /// <summary>
    /// The RFC 8446 section 7.5 exporter of the connection: <paramref name="length"/> bytes
    /// keyed by exporter_master_secret under <paramref name="label"/> and <paramref name="context"/>.
    /// Throws <see cref="NotSupportedException"/> when <see cref="SupportsExporter"/> is false.
    /// </summary>
    byte[] ExportKeyingMaterial(string label, byte[] context, int length);
}

/// <summary>
/// The default transport: <see cref="System.Net.Security.SslStream"/>. Chain validation runs
/// inside the handshake through the stack's callback; the exporter is not available (see the
/// file header), so this transport serves deterministic mode and mode none, and challenge
/// mode only with a caller-supplied <see cref="RaTlsClientOptions.Exporter"/>.
/// </summary>
public sealed class SslStreamTransport : ITlsTransport
{
    private SslStream? _ssl;
    private TlsConnectOptions? _options;
    private string? _error;

    /// <summary>Factory for <see cref="RaTlsClientOptions.Transport"/>.</summary>
    public static ITlsTransport Create() => new SslStreamTransport();

    public Stream Stream => _ssl ?? throw new InvalidOperationException("not connected");

    /// <summary>The underlying <see cref="System.Net.Security.SslStream"/>, for callers that need it.</summary>
    public SslStream SslStream => _ssl ?? throw new InvalidOperationException("not connected");

    public string TlsVersion => _ssl?.SslProtocol.ToString() ?? "";
    public string CipherSuite => _ssl?.NegotiatedCipherSuite.ToString() ?? "";
    public bool SupportsExporter => false;

    public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
        => throw new NotSupportedException("System.Net.Security.SslStream exposes no RFC 8446 exporter; use the Bouncy Castle transport (Privasys.RaTls.BouncyCastle) or supply RaTlsClientOptions.Exporter");

    public void Connect(Stream network, TlsConnectOptions options)
    {
        if (_ssl is not null) throw new InvalidOperationException("already connected");
        _options = options;
        _ssl = new SslStream(network, leaveInnerStreamOpen: false, Validate);
        _ssl.ReadTimeout = options.TimeoutMs;
        _ssl.WriteTimeout = options.TimeoutMs;
        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = options.TargetHost,
            EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = options.Alpn.Select(a => new SslApplicationProtocol(a)).ToList(),
        };
        if (options.FleetOnly)
        {
            // Chain policy for the stack's own build: our anchors, no revocation, no
            // downloads. The validator performs the fleet check independently.
            var chainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true,
            };
            if (options.Anchors is not null) chainPolicy.CustomTrustStore.AddRange(options.Anchors);
            sslOptions.CertificateChainPolicy = chainPolicy;
        }
        // Otherwise the stack builds with system trust and checks the hostname against
        // TargetHost: the SslPolicyErrors it reports are the public PKI verdict the validator
        // consults.
        if (options.ClientCertificate is not null)
            sslOptions.ClientCertificates = new X509Certificate2Collection(options.ClientCertificate);
        try { _ssl.AuthenticateAsClient(sslOptions); }
        catch (AuthenticationException e)
        {
            throw new RaTlsException(_error ?? "TLS connect: " + e.Message, e);
        }
    }

    private bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is null)
        {
            _error = "RA-TLS: server presented no certificate";
            return false;
        }
        var leaf = CopyCert(certificate);
        var presented = new X509Certificate2Collection();
        if (chain is not null)
            foreach (var el in chain.ChainElements)
            {
                var c = CopyCert(el.Certificate);
                if (!c.RawData.AsSpan().SequenceEqual(leaf.RawData)) presented.Add(c);
            }
        var fleetErrors = _options!.FleetOnly ? SslPolicyErrors.None : errors;
        _error = _options.Validate(leaf, presented, fleetErrors, _options.FleetOnly ? null : chain);
        return _error is null;
    }

    private static X509Certificate2 CopyCert(X509Certificate cert)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));
#else
        return new X509Certificate2(cert.Export(X509ContentType.Cert));
#endif
    }

    public void Dispose()
    {
        _ssl?.Dispose();
        _ssl = null;
    }
}
