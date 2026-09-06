// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// The Bouncy Castle transport for RaTlsClient: a managed TLS 1.3 client that
// exposes the RFC 8446 section 7.5 exporter, which System.Net.Security.SslStream
// does not. With it the .NET SDK runs challenge mode (the default of the Go,
// Rust and TypeScript SDKs), re-attestation bound to the connection, and the
// mutual leg (client evidence).
//
//   var options = new RaTlsClientOptions().UseBouncyCastle();   // Challenge
//   using var client = new RaTlsClient(host, 443, options);
//   client.Connect();
//
// Bouncy Castle destroys exporter_master_secret as soon as the handshake
// completes (TlsProtocol.CleanupHandshake), and re-attestation and the mutual
// leg need the exporter afterwards, so the transport extracts the secret in
// NotifyHandshakeComplete and runs the exporter itself (Tls13Exporter), the
// same derivation the shared vectors check.

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcCertificate = Org.BouncyCastle.Tls.Certificate;

namespace Privasys.RaTls.BouncyCastle;

/// <summary>Wires the Bouncy Castle transport into <see cref="RaTlsClientOptions"/>.</summary>
public static class BouncyCastleOptions
{
    /// <summary>
    /// Uses <see cref="BouncyCastleTransport"/> for the connection and sets the attestation
    /// mode (default <see cref="AttestationMode.Challenge"/>, the Level 3 binding).
    /// </summary>
    public static RaTlsClientOptions UseBouncyCastle(this RaTlsClientOptions options, AttestationMode attestation = AttestationMode.Challenge)
    {
        options.Transport = BouncyCastleTransport.Create;
        options.Attestation = attestation;
        return options;
    }
}

/// <summary>Bridges .NET private keys to Bouncy Castle key parameters.</summary>
public static class BouncyCastleKeys
{
    /// <summary>
    /// The Bouncy Castle private key of a .NET <see cref="AsymmetricAlgorithm"/>. A plaintext
    /// PKCS#8 export is used when the platform allows it; a Windows CNG key marked exportable
    /// only exports encrypted, so the fallback is an encrypted PKCS#8 that Bouncy Castle
    /// decrypts in process.
    /// </summary>
    public static AsymmetricKeyParameter FromDotNet(AsymmetricAlgorithm key)
    {
        try
        {
            return PrivateKeyFactory.CreateKey(key.ExportPkcs8PrivateKey());
        }
        catch (CryptographicException)
        {
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToCharArray();
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 2048);
            var encrypted = key.ExportEncryptedPkcs8PrivateKey(password, pbe);
            try { return PrivateKeyFactory.DecryptKey(password, encrypted); }
            finally { Array.Clear(password); CryptographicOperations.ZeroMemory(encrypted); }
        }
    }
}

/// <summary>
/// <see cref="ITlsTransport"/> over Bouncy Castle's <see cref="TlsClientProtocol"/>: TLS 1.3
/// only, ALPN and SNI as the SDK requires, chain validation delegated to the client's
/// validator (fleet anchors, or the public PKI verdict built with <see cref="X509Chain"/> and
/// system trust when no evidence is requested), client certificates for the mutual leg, and
/// the exporter for the life of the connection.
/// </summary>
public sealed class BouncyCastleTransport : ITlsTransport
{
    private TlsClientProtocol? _protocol;
    private Client? _client;

    /// <summary>Factory for <see cref="RaTlsClientOptions.Transport"/>.</summary>
    public static ITlsTransport Create() => new BouncyCastleTransport();

    public Stream Stream => _protocol?.Stream ?? throw new InvalidOperationException("not connected");
    public string TlsVersion => _client?.Version ?? "";
    public string CipherSuite => _client?.Suite ?? "";
    public bool SupportsExporter => true;

    public void Connect(Stream network, TlsConnectOptions options)
    {
        if (_protocol is not null) throw new InvalidOperationException("already connected");
        _client = new Client(options);
        _protocol = new TlsClientProtocol(network);
        try { _protocol.Connect(_client); }
        catch (Exception e) when (e is TlsException or IOException)
        {
            throw new RaTlsException(_client.Error ?? "TLS connect: " + e.Message, e);
        }
        if (_client.Error is not null) throw new RaTlsException(_client.Error);
        if (_client.ExporterMasterSecret is null) throw new RaTlsException("TLS connect: handshake completed without an exporter secret");
    }

    public byte[] ExportKeyingMaterial(string label, byte[] context, int length)
    {
        var c = _client ?? throw new InvalidOperationException("not connected");
        if (c.ExporterMasterSecret is null) throw new InvalidOperationException("not connected");
        return Tls13Exporter.Export(c.Hash, c.ExporterMasterSecret, label, context, length);
    }

    public void Dispose()
    {
        try { _protocol?.Close(); } catch (Exception) { }
        _protocol = null;
        if (_client?.ExporterMasterSecret is { } ems) CryptographicOperations.ZeroMemory(ems);
        _client = null;
    }

    /// <summary>The Bouncy Castle peer: version, ALPN, SNI, authentication, credentials and the exporter secret.</summary>
    private sealed class Client : DefaultTlsClient, TlsAuthentication
    {
        private readonly TlsConnectOptions _o;

        public string? Error;
        public string Version = "";
        public string Suite = "";
        public string Hash = "sha256";
        public byte[]? ExporterMasterSecret;

        public Client(TlsConnectOptions o) : base(new BcTlsCrypto()) { _o = o; }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();

        protected override IList<ProtocolName> GetProtocolNames()
            => _o.Alpn.Select(a => a == "http/1.1" ? ProtocolName.Http_1_1 : ProtocolName.AsUtf8Encoding(a)).ToList();

        protected override IList<ServerName> GetSniServerNames()
        {
            // No SNI for an IP literal, as the other stacks do.
            if (string.IsNullOrEmpty(_o.TargetHost) || IPAddress.TryParse(_o.TargetHost, out _)) return null!;
            return new List<ServerName> { new(NameType.host_name, Encoding.ASCII.GetBytes(_o.TargetHost)) };
        }

        public override TlsAuthentication GetAuthentication() => this;

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            var sp = m_context.SecurityParameters;
            Version = m_context.ServerVersion.Equals(ProtocolVersion.TLSv13) ? "Tls13" : m_context.ServerVersion.ToString();
            Suite = SuiteName(sp.CipherSuite);
            Hash = sp.PrfCryptoHashAlgorithm == CryptoHashAlgorithm.sha384 ? "sha384" : "sha256";
            // Bouncy Castle destroys the secret right after this callback: keep it for the
            // exporter (re-attestation, client evidence) and zero it on Dispose.
            ExporterMasterSecret = sp.ExporterMasterSecret.Extract();
        }

        // -- TlsAuthentication ---------------------------------------------------

        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            var list = serverCertificate.Certificate?.GetCertificateList() ?? Array.Empty<TlsCertificate>();
            if (list.Length == 0)
            {
                Error = "RA-TLS: server presented no certificate";
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
            var leaf = Load(list[0].GetEncoded());
            var presented = new X509Certificate2Collection();
            for (var i = 1; i < list.Length; i++) presented.Add(Load(list[i].GetEncoded()));

            X509Chain? chain = null;
            var errors = SslPolicyErrorsNone;
            try
            {
                if (!_o.FleetOnly)
                {
                    // The public-PKI verdict the stack would give: system roots, no
                    // revocation, no downloads, then the hostname.
                    chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads = true;
                    chain.ChainPolicy.ExtraStore.AddRange(presented);
                    if (!chain.Build(leaf)) errors |= System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors;
                    if (!string.IsNullOrEmpty(_o.TargetHost) && !leaf.MatchesHostname(_o.TargetHost))
                        errors |= System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch;
                }
                Error = _o.Validate(leaf, presented, errors, chain);
            }
            finally
            {
                chain?.Dispose();
            }
            if (Error is not null) throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest)
        {
            var cert = _o.ClientCertificate;
            if (cert is null) return null;
            var crypto = (BcTlsCrypto)Crypto;
            AsymmetricKeyParameter key;
            int scheme;
            if (cert.GetECDsaPrivateKey() is { } ec)
            {
                using (ec) key = BouncyCastleKeys.FromDotNet(ec);
                scheme = ec.KeySize switch
                {
                    384 => SignatureScheme.ecdsa_secp384r1_sha384,
                    521 => SignatureScheme.ecdsa_secp521r1_sha512,
                    _ => SignatureScheme.ecdsa_secp256r1_sha256,
                };
            }
            else if (cert.GetRSAPrivateKey() is { } rsa)
            {
                using (rsa) key = BouncyCastleKeys.FromDotNet(rsa);
                scheme = SignatureScheme.rsa_pss_rsae_sha256;
            }
            else
            {
                Error = "RA-TLS: client certificate has no usable private key (ECDSA or RSA)";
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            var wanted = SignatureScheme.GetSignatureAndHashAlgorithm(scheme);
            var offered = certificateRequest.SupportedSignatureAlgorithms;
            if (offered is not null && !offered.Any(a => a.Equals(wanted)))
            {
                Error = $"RA-TLS: server does not accept {SignatureScheme.GetName(scheme)} for the client certificate";
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            var entries = new[] { new CertificateEntry(new BcTlsCertificate(crypto, cert.RawData), null) };
            var bcCert = new BcCertificate(certificateRequest.GetCertificateRequestContext(), entries);
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), crypto, key, bcCert, wanted);
        }

        private const System.Net.Security.SslPolicyErrors SslPolicyErrorsNone = System.Net.Security.SslPolicyErrors.None;

        private static X509Certificate2 Load(byte[] der)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(der);
#else
            return new X509Certificate2(der);
#endif
        }

        private static string SuiteName(int suite) => suite switch
        {
            Org.BouncyCastle.Tls.CipherSuite.TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            Org.BouncyCastle.Tls.CipherSuite.TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            Org.BouncyCastle.Tls.CipherSuite.TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => $"0x{suite:X4}",
        };
    }
}
