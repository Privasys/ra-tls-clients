#!/usr/bin/env npx ts-node
// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

/**
 * Test script for enclave-os-mini: connect, inspect cert, send HelloWorld.
 *
 * Usage:
 *   npx ts-node test_hello.ts [--host HOST] [--port PORT] [--ca-cert CA.pem]
 *
 * Or compile first:
 *   tsc --esModuleInterop --module commonjs ratls_client.ts test_hello.ts
 *   node test_hello.js --host 141.94.219.130
 */

import { RaTlsClient, printCertInfo } from "./ratls_client";

function parseArgs(): { host: string; port: number; caCert?: string } {
  const args = process.argv.slice(2);
  let host = "127.0.0.1";
  let port = 8443;
  let caCert: string | undefined;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--host":
        host = args[++i];
        break;
      case "--port":
        port = parseInt(args[++i], 10);
        break;
      case "--ca-cert":
        caCert = args[++i];
        break;
    }
  }

  return { host, port, caCert };
}

async function main() {
  const { host, port, caCert } = parseArgs();

  console.log(`Connecting to ${host}:${port} ...`);
  if (caCert) console.log(`CA certificate: ${caCert}`);

  const client = new RaTlsClient(host, port, { caCert });
  await client.connect();

  console.log(`TLS handshake complete: ${client.tlsVersion}`);
  const cipher = client.cipher;
  if (cipher) {
    console.log(`Cipher: ${cipher.name}  (${cipher.version})`);
  }

  // ---- Certificate inspection ----
  console.log("\n--- Certificate inspection (RA-TLS) ---");
  const info = client.inspectCertificate();
  printCertInfo(info);

  // ---- HelloWorld test ----
  console.log("\n--- HelloWorld RPC test ---");
  const resp = await client.sendData(Buffer.from("hello"));
  console.log(`Sent: Data(hello)`);
  console.log(`Received: Data(${resp.toString()})`);

  if (resp.toString() === "world") {
    console.log("\nSUCCESS: HelloWorld module responded correctly!");
    client.close();
    process.exit(0);
  } else {
    console.log(`\nUNEXPECTED: got ${resp.toString()}`);
    client.close();
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
