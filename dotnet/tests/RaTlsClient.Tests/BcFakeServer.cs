// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using BcCertificate = Org.BouncyCastle.Tls.Certificate;

namespace Privasys.RaTls.Tests;

/// <summary>
/// A loopback RA-TLS v2 server on Bouncy Castle's TLS 1.3 stack, with the real exporter: it
/// answers deterministic and challenge requests with a fake TDX quote whose report_data
/// follows the recipes, optionally requires client evidence and verifies the present message
/// as a runtime would (section 5), serves /healthz (chunked) and /data, and echoes frames on
/// the raw binding.
/// </summary>
internal sealed class BcFakeServer : IDisposable
{
    private readonly TestSupport.Chain _chain;
    private readonly TcpListener _listener;
    private Task? _loop;
    private Peer? _peer;

    public BcFakeServer(TestSupport.Chain chain, AttestFraming framing = AttestFraming.Http, bool requireClientEvidence = false)
    {
        _chain = chain;
        Framing = framing;
        RequireClientEvidence = requireClientEvidence;
        _listener = new TcpListener(IPAddress.Loopback, 0);
    }

    public AttestFraming Framing { get; }
    public bool RequireClientEvidence { get; }
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>Overrides the attest handler: receives the parsed request, returns status and body.</summary>
    public Func<JsonElement, (int Status, string Body)>? Handler { get; set; }

    public string RecordedTag { get; private set; } = "none";
    public int AttestCount { get; private set; }
    public Exception? Error { get; private set; }
    /// <summary>The verdict of the last present message, null until one arrived.</summary>
    public bool? Presented { get; private set; }
    /// <summary>The client leaf presented in the handshake, if any.</summary>
    public byte[]? ClientLeafDer => _peer?.ClientLeaf;

    /// <summary>This connection's exporter, for tests that compare both ends.</summary>
    public byte[] Export(string label, byte[] context) => _peer!.Export(label, context);

    public void Start()
    {
        _listener.Start();
        _loop = Task.Run(async () =>
        {
            try
            {
                using var tcp = await _listener.AcceptTcpClientAsync();
                tcp.ReceiveTimeout = 10_000;
                tcp.SendTimeout = 10_000;
                _peer = new Peer(_chain, RequireClientEvidence);
                var protocol = new TlsServerProtocol(tcp.GetStream());
                protocol.Accept(_peer);
                Serve(protocol.Stream);
            }
            catch (Exception e) { Error = e; }
        });
    }

    private void Serve(Stream s)
    {
        byte[]? pendingClientContext = null;
        if (Framing == AttestFraming.Raw)
        {
            var (_, body, ctx) = HandleAttest(RaTlsAttest.ReadFrame(s));
            RaTlsAttest.WriteFrame(s, Encoding.UTF8.GetBytes(body));
            if (ctx is not null)
            {
                var ok = VerifyPresent(RaTlsAttest.ReadFrame(s), ctx);
                RaTlsAttest.WriteFrame(s, Encoding.UTF8.GetBytes(ok ? "{\"v\":2}" : "{\"v\":2,\"error\":\"client evidence rejected\"}"));
                if (!ok) return;
            }
            while (true)
            {
                byte[] frame;
                try { frame = RaTlsAttest.ReadFrame(s); } catch (Exception) { return; }
                RaTlsAttest.WriteFrame(s, frame);
            }
        }

        while (true)
        {
            string method, path;
            byte[] body;
            try { (method, path, body) = FakeServer.ReadHttpRequest(s); } catch (Exception) { return; }
            if (method == "POST" && path == RaTlsAttest.AttestPath)
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("mode", out var m) && m.GetString() == "present")
                {
                    if (pendingClientContext is not null && VerifyPresent(body, pendingClientContext))
                        FakeServer.WriteHttpResponse(s, 204, Array.Empty<byte>(), chunked: false);
                    else
                        FakeServer.WriteHttpResponse(s, 403, Encoding.UTF8.GetBytes("{\"v\":2,\"error\":\"client evidence rejected\"}"), chunked: false);
                    continue;
                }
                var (status, resp, ctx) = HandleAttest(body);
                pendingClientContext = ctx;
                FakeServer.WriteHttpResponse(s, status, Encoding.UTF8.GetBytes(resp), chunked: false);
            }
            else if (method == "GET" && path == "/healthz")
            {
                var resp = Encoding.UTF8.GetBytes($"{{\"status\":\"ok\",\"attestation\":\"{RecordedTag}\"}}");
                FakeServer.WriteHttpResponse(s, 200, resp, chunked: true, extraHeader: $"{RaTlsClient.AttestationHeader}: {RecordedTag}");
            }
            else if (method == "POST" && path == "/data")
            {
                FakeServer.WriteHttpResponse(s, 200, body, chunked: false);
            }
            else
            {
                FakeServer.WriteHttpResponse(s, 404, Encoding.UTF8.GetBytes("not found"), chunked: false);
            }
        }
    }

    private (int Status, string Body, byte[]? ClientContext) HandleAttest(byte[] body)
    {
        using var doc = JsonDocument.Parse(body);
        var req = doc.RootElement;
        if (Handler is not null)
        {
            var (hs, hb) = Handler(req);
            return (hs, hb, null);
        }
        var spki = _chain.Leaf.PublicKey.ExportSubjectPublicKeyInfo();
        if (req.GetProperty("leaf").GetString() != RaTlsAttest.LeafId(spki))
            return (404, "{\"v\":2,\"error\":\"unknown leaf\"}", null);
        var mode = req.GetProperty("mode").GetString();
        byte[] binding;
        var quoteTime = DateTime.UtcNow.ToString(RaTlsAttest.QuoteTimeLayout, System.Globalization.CultureInfo.InvariantCulture);
        if (mode == "deterministic")
        {
            binding = Encoding.ASCII.GetBytes(quoteTime);
        }
        else if (mode == "challenge")
        {
            var ctx = Base64Url.Decode(req.GetProperty("context").GetString()!);
            if (ctx.Length != RaTlsAttest.ContextLen) return (400, "{\"v\":2,\"error\":\"context length\"}", null);
            binding = ctx.Concat(_peer!.Export(RaTlsAttest.ExporterLabelServer, ctx)).ToArray();
        }
        else
        {
            return (400, "{\"v\":2,\"error\":\"bad mode\"}", null);
        }
        var rd = SHA512.HashData(SHA256.HashData(spki).Concat(binding).ToArray());
        AttestCount++;
        RecordedTag = mode!;
        var clientContext = RequireClientEvidence ? RandomNumberGenerator.GetBytes(RaTlsAttest.ContextLen) : null;
        var resp = JsonSerializer.Serialize(new
        {
            v = 2,
            mode,
            tee = "tdx",
            quote = Base64Url.Encode(TestSupport.TdxQuoteWith(rd)),
            gpu_evidence = (string?)null,
            quote_time = quoteTime,
            client_evidence = clientContext is null ? "none" : "required",
            client_context = clientContext is null ? null : Base64Url.Encode(clientContext),
        });
        return (200, resp, clientContext);
    }

    /// <summary>Section 5 as a runtime does it: echoed context, and report_data predicted from the presented client leaf and this connection's exporter under the client label.</summary>
    private bool VerifyPresent(byte[] body, byte[] clientContext)
    {
        Presented = false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var req = doc.RootElement;
            if (req.GetProperty("v").GetInt32() != 2 || req.GetProperty("mode").GetString() != "present") return false;
            if (!Base64Url.Decode(req.GetProperty("context").GetString()!).AsSpan().SequenceEqual(clientContext)) return false;
            if (_peer?.ClientLeaf is null) return false;
            using var clientLeaf = new X509Certificate2(_peer.ClientLeaf);
            var spki = clientLeaf.PublicKey.ExportSubjectPublicKeyInfo();
            var hctx = _peer.Export(RaTlsAttest.ExporterLabelClient, clientContext);
            byte[]? gpu = req.TryGetProperty("gpu_evidence", out var g) && g.ValueKind == JsonValueKind.String ? Base64Url.Decode(g.GetString()!) : null;
            var want = RaTlsVerifier.ClientReportData(spki, clientContext, hctx, gpu);
            var got = RaTlsVerifier.QuoteReportData(req.GetProperty("tee").GetString()!, Base64Url.Decode(req.GetProperty("quote").GetString()!));
            Presented = want.AsSpan().SequenceEqual(got);
            return Presented.Value;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _listener.Stop();
        try { _loop?.Wait(TimeSpan.FromSeconds(5)); } catch (Exception) { }
    }

    /// <summary>The Bouncy Castle server peer: TLS 1.3, the test chain, an optional client certificate request, and the exporter secret kept after the handshake.</summary>
    private sealed class Peer : DefaultTlsServer
    {
        private readonly TestSupport.Chain _chain;
        private readonly bool _requireClient;
        private byte[]? _ems;
        private string _hash = "sha256";

        public byte[]? ClientLeaf;

        public Peer(TestSupport.Chain chain, bool requireClient) : base(new BcTlsCrypto())
        {
            _chain = chain;
            _requireClient = requireClient;
        }

        public byte[] Export(string label, byte[] context) => Tls13Exporter.Export(_hash, _ems ?? throw new InvalidOperationException("no handshake"), label, context, RaTlsAttest.HctxLen);

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();

        protected override IList<ProtocolName> GetProtocolNames() => new List<ProtocolName> { ProtocolName.Http_1_1, ProtocolName.AsUtf8Encoding(RaTlsClient.RaTlsAlpnProto) };

        public override TlsCredentials GetCredentials()
        {
            var crypto = (BcTlsCrypto)Crypto;
            using var ecdsa = _chain.Leaf.GetECDsaPrivateKey()!;
            var key = Privasys.RaTls.BouncyCastle.BouncyCastleKeys.FromDotNet(ecdsa);
            var entries = new List<CertificateEntry> { new(new BcTlsCertificate(crypto, _chain.Leaf.RawData), null) };
            if (!_chain.Intermediate.RawData.AsSpan().SequenceEqual(_chain.Leaf.RawData))
                entries.Add(new CertificateEntry(new BcTlsCertificate(crypto, _chain.Intermediate.RawData), null));
            var cert = new BcCertificate(Array.Empty<byte>(), entries.ToArray());
            var alg = SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), crypto, key, cert, alg);
        }

        public override Org.BouncyCastle.Tls.CertificateRequest? GetCertificateRequest()
        {
            if (!_requireClient) return null;
            var algs = new List<SignatureAndHashAlgorithm> { SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256) };
            return new Org.BouncyCastle.Tls.CertificateRequest(Array.Empty<byte>(), algs, null, null);
        }

        public override void NotifyClientCertificate(BcCertificate clientCertificate)
        {
            if (clientCertificate is { IsEmpty: false }) ClientLeaf = clientCertificate.GetCertificateAt(0).GetEncoded();
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            var sp = m_context.SecurityParameters;
            _hash = sp.PrfCryptoHashAlgorithm == CryptoHashAlgorithm.sha384 ? "sha384" : "sha256";
            _ems = sp.ExporterMasterSecret.Extract();
        }
    }
}
