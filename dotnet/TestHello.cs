// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Test script for enclave-os-mini: connect, inspect cert, send HelloWorld.
//
// Usage:
//   dotnet run -- [--host HOST] [--port PORT] [--ca-cert CA.pem]
//
// Examples:
//   dotnet run -- --host 141.94.219.130
//   dotnet run -- --host 141.94.219.130 --ca-cert /path/to/ca.pem

using EnclaveOsMini.Client;

string host = "127.0.0.1";
int port = 443;
string? caCert = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--host": host = args[++i]; break;
        case "--port": port = int.Parse(args[++i]); break;
        case "--ca-cert": caCert = args[++i]; break;
    }
}

Console.WriteLine($"Connecting to {host}:{port} ...");
if (caCert != null)
    Console.WriteLine($"CA certificate: {caCert}");

using var client = new RaTlsClient(host, port, caCertPath: caCert);
client.Connect();

Console.WriteLine($"TLS handshake complete: {client.TlsVersion}");
Console.WriteLine($"Cipher: {client.CipherSuite}");

// ---- Certificate inspection ----
Console.WriteLine("\n--- Certificate inspection (RA-TLS) ---");
var info = client.InspectCertificate();
RaTlsPrinter.PrintCertInfo(info);

// ---- HelloWorld test ----
Console.WriteLine("\n--- HelloWorld RPC test ---");
var resp = client.SendData("hello"u8);
var respStr = System.Text.Encoding.UTF8.GetString(resp);
Console.WriteLine("Sent: Data(hello)");
Console.WriteLine($"Received: Data({respStr})");

if (respStr == "world")
{
    Console.WriteLine("\nSUCCESS: HelloWorld module responded correctly!");
    Environment.Exit(0);
}
else
{
    Console.WriteLine($"\nUNEXPECTED: got {respStr}");
    Environment.Exit(1);
}
