// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Privasys.RaTls.Tests;

/// <summary>
/// A loopback RA-TLS v2 server: TLS 1.3 with a generated leaf, the attest endpoint (HTTP and
/// raw bindings) answering with a fake TDX quote whose report_data follows the recipes, a
/// chunked /healthz that echoes the connection tag, and a frame echo on the raw binding.
/// </summary>
internal sealed class FakeServer : IDisposable
{
    private readonly TestSupport.Chain _chain;
    private readonly TcpListener _listener;
    private Task? _loop;

    public FakeServer(TestSupport.Chain chain, AttestFraming framing = AttestFraming.Http)
    {
        _chain = chain;
        Framing = framing;
        _listener = new TcpListener(IPAddress.Loopback, 0);
    }

    public AttestFraming Framing { get; }
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public X509Certificate2 Leaf => _chain.Leaf;

    /// <summary>Overrides the attest handler: receives the parsed request, returns status and body.</summary>
    public Func<JsonElement, (int Status, string Body)>? Handler { get; set; }

    /// <summary>The tag recorded for the connection, as the runtime would (none until a response is served).</summary>
    public string RecordedTag { get; private set; } = "none";
    public int AttestCount { get; private set; }
    public Exception? Error { get; private set; }

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
                Serve(tcp);
            }
            catch (Exception e) { Error = e; }
        });
    }

    private void Serve(TcpClient tcp)
    {
        using var ssl = new SslStream(tcp.GetStream(), false);
        // A self-signed chain (TestSupport.MakeSelfSigned) has no intermediate to send.
        var extra = new X509Certificate2Collection();
        if (!_chain.Intermediate.RawData.AsSpan().SequenceEqual(_chain.Leaf.RawData)) extra.Add(_chain.Intermediate);
        ssl.AuthenticateAsServer(new SslServerAuthenticationOptions
        {
            ServerCertificateContext = SslStreamCertificateContext.Create(_chain.Leaf, extra, offline: true),
            EnabledSslProtocols = SslProtocols.Tls13,
            ApplicationProtocols = new List<SslApplicationProtocol> { new(RaTlsClient.RaTlsAlpnProto), SslApplicationProtocol.Http11 },
        });

        if (Framing == AttestFraming.Raw)
        {
            var (_, body) = HandleAttest(RaTlsAttest.ReadFrame(ssl));
            RaTlsAttest.WriteFrame(ssl, Encoding.UTF8.GetBytes(body));
            // Then the "protocol": echo frames until the peer closes.
            while (true)
            {
                byte[] frame;
                try { frame = RaTlsAttest.ReadFrame(ssl); } catch (Exception) { return; }
                RaTlsAttest.WriteFrame(ssl, frame);
            }
        }

        while (true)
        {
            string method, path;
            byte[] body;
            try { (method, path, body) = ReadHttpRequest(ssl); } catch (Exception) { return; }
            if (method == "POST" && path == RaTlsAttest.AttestPath)
            {
                var (status, resp) = HandleAttest(body);
                WriteHttpResponse(ssl, status, Encoding.UTF8.GetBytes(resp), chunked: false);
            }
            else if (method == "GET" && path == "/healthz")
            {
                var resp = Encoding.UTF8.GetBytes($"{{\"status\":\"ok\",\"attestation\":\"{RecordedTag}\"}}");
                WriteHttpResponse(ssl, 200, resp, chunked: true, extraHeader: $"{RaTlsClient.AttestationHeader}: {RecordedTag}");
            }
            else if (method == "POST" && path == "/data")
            {
                WriteHttpResponse(ssl, 200, body, chunked: false);
            }
            else
            {
                WriteHttpResponse(ssl, 404, Encoding.UTF8.GetBytes("not found"), chunked: false);
            }
        }
    }

    private (int, string) HandleAttest(byte[] body)
    {
        using var doc = JsonDocument.Parse(body);
        var req = doc.RootElement;
        if (Handler is not null) return Handler(req);

        var spki = _chain.Leaf.PublicKey.ExportSubjectPublicKeyInfo();
        if (req.GetProperty("leaf").GetString() != RaTlsAttest.LeafId(spki))
            return (404, "{\"v\":2,\"error\":\"unknown leaf\"}");
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
            if (ctx.Length != RaTlsAttest.ContextLen) return (400, "{\"v\":2,\"error\":\"context length\"}");
            var hctx = TestSupport.StubExporter(RaTlsAttest.ExporterLabelServer, ctx, RaTlsAttest.HctxLen);
            binding = ctx.Concat(hctx).ToArray();
        }
        else
        {
            return (400, "{\"v\":2,\"error\":\"bad mode\"}");
        }
        var rd = SHA512.HashData(SHA256.HashData(spki).Concat(binding).ToArray());
        var quote = TestSupport.TdxQuoteWith(rd);
        AttestCount++;
        RecordedTag = mode;
        var resp = JsonSerializer.Serialize(new
        {
            v = 2,
            mode,
            tee = "tdx",
            quote = Base64Url.Encode(quote),
            gpu_evidence = (string?)null,
            quote_time = quoteTime,
            client_evidence = "none",
            client_context = (string?)null,
        });
        return (200, resp);
    }

    internal static (string Method, string Path, byte[] Body) ReadHttpRequest(Stream s)
    {
        var buf = new MemoryStream();
        var one = new byte[1];
        while (true)
        {
            if (s.Read(one, 0, 1) == 0) throw new IOException("closed");
            buf.WriteByte(one[0]);
            var b = buf.GetBuffer();
            var n = (int)buf.Length;
            if (n >= 4 && b[n - 4] == '\r' && b[n - 3] == '\n' && b[n - 2] == '\r' && b[n - 1] == '\n') break;
        }
        var lines = Encoding.ASCII.GetString(buf.ToArray()).Split("\r\n");
        var parts = lines[0].Split(' ');
        var contentLength = 0;
        foreach (var line in lines.Skip(1))
            if (line.StartsWith("content-length:", StringComparison.OrdinalIgnoreCase))
                contentLength = int.Parse(line.Split(':', 2)[1].Trim());
        var body = new byte[contentLength];
        if (contentLength > 0) s.ReadExactly(body);
        return (parts[0], parts[1], body);
    }

    internal static void WriteHttpResponse(Stream s, int status, byte[] body, bool chunked, string? extraHeader = null)
    {
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 ").Append(status).Append(status == 200 ? " OK" : status == 404 ? " Not Found" : " Error").Append("\r\n");
        sb.Append("Content-Type: application/json\r\n");
        if (extraHeader is not null) sb.Append(extraHeader).Append("\r\n");
        if (chunked) sb.Append("Transfer-Encoding: chunked\r\n");
        else sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
        sb.Append("\r\n");
        var head = Encoding.ASCII.GetBytes(sb.ToString());
        s.Write(head);
        if (chunked)
        {
            // Two chunks, to exercise the decoder across a boundary.
            var half = body.Length / 2;
            foreach (var part in new[] { body[..half], body[half..] })
            {
                s.Write(Encoding.ASCII.GetBytes(part.Length.ToString("x") + "\r\n"));
                s.Write(part);
                s.Write(Encoding.ASCII.GetBytes("\r\n"));
            }
            s.Write(Encoding.ASCII.GetBytes("0\r\n\r\n"));
        }
        else
        {
            s.Write(body);
        }
        s.Flush();
    }

    public void Dispose()
    {
        _listener.Stop();
        try { _loop?.Wait(TimeSpan.FromSeconds(5)); } catch (Exception) { }
    }
}
