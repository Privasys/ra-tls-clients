// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

/**
 * RA-TLS client connector for enclave-os-mini.
 *
 * Provides:
 *   - TLS connection with optional CA certificate verification
 *   - RA-TLS certificate inspection (SGX / TDX quote extraction)
 *   - Length-delimited framing (4-byte big-endian prefix)
 *   - Typed request/response helpers matching the Rust protocol
 *
 * Dependencies: none beyond Node.js built-ins (tls, net, crypto, fs).
 *
 * Usage:
 *   import { RaTlsClient, printCertInfo } from "./ratls_client";
 *   const client = new RaTlsClient("141.94.219.130", 443, { caCert: "ca.pem" });
 *   await client.connect();
 *   const info = client.inspectCertificate();
 *   const resp = await client.sendData(Buffer.from("hello"));
 *   client.close();
 */

import * as tls from "tls";
import * as fs from "fs";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
//  RA-TLS OIDs
// ---------------------------------------------------------------------------

export const RATLS_OIDS: Record<string, string> = {
  "1.2.840.113741.1.13.1.0": "SGX Quote",
  "1.2.840.113741.1.5.5.1.6": "TDX Quote",
};

// ---------------------------------------------------------------------------
//  Certificate inspection result
// ---------------------------------------------------------------------------

export interface QuoteInfo {
  oid: string;
  label: string;
  critical: boolean;
  raw: Buffer;
  isMock: boolean;
  version?: number;
  reportData?: Buffer;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  pubkeySha256: string;
  extensions: string[];
  quote?: QuoteInfo;
}

// ---------------------------------------------------------------------------
//  Framing helpers
// ---------------------------------------------------------------------------

export function encodeFrame(payload: Buffer): Buffer {
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

export function decodeFrame(buf: Buffer): { payload: Buffer; rest: Buffer } | null {
  if (buf.length < 4) return null;
  const length = buf.readUInt32BE(0);
  if (buf.length < 4 + length) return null;
  return {
    payload: buf.subarray(4, 4 + length),
    rest: buf.subarray(4 + length),
  };
}

// ---------------------------------------------------------------------------
//  ASN.1 / OID utilities
// ---------------------------------------------------------------------------

function encodeOidBytes(components: number[]): Buffer {
  const result: number[] = [];
  result.push(40 * components[0] + components[1]);
  for (let i = 2; i < components.length; i++) {
    let c = components[i];
    if (c < 128) {
      result.push(c);
    } else {
      const parts: number[] = [];
      while (c > 0) {
        parts.push(c & 0x7f);
        c >>= 7;
      }
      parts.reverse();
      for (let j = 0; j < parts.length; j++) {
        result.push(j < parts.length - 1 ? parts[j] | 0x80 : parts[j]);
      }
    }
  }
  return Buffer.from(result);
}

function decodeAsn1Length(data: Buffer, offset: number): { length: number; consumed: number } | null {
  if (offset >= data.length) return null;
  const first = data[offset];
  if (first < 0x80) return { length: first, consumed: 1 };
  const numBytes = first & 0x7f;
  if (numBytes === 0 || offset + 1 + numBytes > data.length) return null;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | data[offset + 1 + i];
  }
  return { length, consumed: 1 + numBytes };
}

function tryExtractOctetString(data: Buffer, offset: number): Buffer | null {
  for (let i = offset; i < Math.min(offset + 20, data.length); i++) {
    if (data[i] === 0x04) {
      const r = decodeAsn1Length(data, i + 1);
      if (r && i + 1 + r.consumed + r.length <= data.length) {
        const start = i + 1 + r.consumed;
        return data.subarray(start, start + r.length);
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

function parseQuote(oid: string, critical: boolean, raw: Buffer): QuoteInfo {
  const label = RATLS_OIDS[oid] ?? "Unknown";
  const q: QuoteInfo = { oid, label, critical, raw, isMock: false };

  if (raw.subarray(0, 11).toString() === "MOCK_QUOTE:") {
    q.isMock = true;
    q.reportData = raw.subarray(11, Math.min(75, raw.length));
  } else if (label === "SGX Quote" && raw.length >= 4) {
    q.version = raw.readUInt16LE(0);
    if (raw.length >= 432) {
      q.reportData = raw.subarray(368, 432);
    }
  } else if (label === "TDX Quote" && raw.length >= 4) {
    q.version = raw.readUInt16LE(0);
  }

  return q;
}

export function inspectDerCertificate(der: Buffer): CertInfo {
  const info: CertInfo = {
    subject: "",
    issuer: "",
    serialNumber: "",
    validFrom: "",
    validTo: "",
    pubkeySha256: "",
    extensions: [],
  };

  // Compute SHA-256 of the full DER cert as a basic fingerprint
  info.pubkeySha256 = crypto.createHash("sha256").update(der).digest("hex");

  // Manual ASN.1 scan for known RA-TLS OIDs
  const oidMap: Record<string, { bytes: Buffer; oid: string }> = {
    "SGX Quote": {
      bytes: encodeOidBytes([1, 2, 840, 113741, 1, 13, 1, 0]),
      oid: "1.2.840.113741.1.13.1.0",
    },
    "TDX Quote": {
      bytes: encodeOidBytes([1, 2, 840, 113741, 1, 5, 5, 1, 6]),
      oid: "1.2.840.113741.1.5.5.1.6",
    },
  };

  for (const [, { bytes, oid }] of Object.entries(oidMap)) {
    const idx = der.indexOf(bytes);
    if (idx >= 0) {
      const raw = tryExtractOctetString(der, idx + bytes.length);
      if (raw) {
        info.quote = parseQuote(oid, false, raw);
      }
    }
  }

  return info;
}

// ---------------------------------------------------------------------------
//  RA-TLS Client
// ---------------------------------------------------------------------------

export interface RaTlsClientOptions {
  /** Path to a PEM CA certificate for chain verification. */
  caCert?: string;
  /** Socket timeout in milliseconds (default: 10000). */
  timeout?: number;
}

export class RaTlsClient {
  private host: string;
  private port: number;
  private caCert?: string;
  private timeout: number;
  private socket?: tls.TLSSocket;

  constructor(host: string, port = 443, opts: RaTlsClientOptions = {}) {
    this.host = host;
    this.port = port;
    this.caCert = opts.caCert;
    this.timeout = opts.timeout ?? 10_000;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const options: tls.ConnectionOptions = {
        host: this.host,
        port: this.port,
        rejectUnauthorized: !!this.caCert,
        timeout: this.timeout,
      };

      if (this.caCert) {
        options.ca = fs.readFileSync(this.caCert);
      }

      this.socket = tls.connect(options, () => {
        resolve();
      });

      this.socket.on("error", reject);
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = undefined;
  }

  get tlsVersion(): string {
    return this.socket?.getProtocol() ?? "";
  }

  get cipher(): tls.CipherNameAndProtocol | undefined {
    return this.socket?.getCipher();
  }

  inspectCertificate(): CertInfo {
    if (!this.socket) throw new Error("Not connected");
    const cert = this.socket.getPeerCertificate(true);
    if (!cert?.raw) return { subject: "", issuer: "", serialNumber: "", validFrom: "", validTo: "", pubkeySha256: "", extensions: [] };

    const info = inspectDerCertificate(cert.raw);
    info.subject = cert.subject ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(", ") : "";
    info.issuer = cert.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(", ") : "";
    info.serialNumber = cert.serialNumber ?? "";
    info.validFrom = cert.valid_from ?? "";
    info.validTo = cert.valid_to ?? "";
    return info;
  }

  // -- Protocol -----------------------------------------------------------

  private sendFrame(payload: Buffer): void {
    if (!this.socket) throw new Error("Not connected");
    this.socket.write(encodeFrame(payload));
  }

  private recvFrame(): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      if (!this.socket) return reject(new Error("Not connected"));
      let buf = Buffer.alloc(0);

      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        const result = decodeFrame(buf);
        if (result) {
          this.socket!.off("data", onData);
          this.socket!.off("error", onError);
          resolve(result.payload);
        }
      };

      const onError = (err: Error) => {
        this.socket!.off("data", onData);
        reject(err);
      };

      this.socket.on("data", onData);
      this.socket.on("error", onError);
    });
  }

  async ping(): Promise<boolean> {
    this.sendFrame(Buffer.from(JSON.stringify("Ping")));
    const resp = JSON.parse((await this.recvFrame()).toString());
    return resp === "Pong";
  }

  async sendData(data: Buffer): Promise<Buffer> {
    const req = JSON.stringify({ Data: Array.from(data) });
    this.sendFrame(Buffer.from(req));
    const resp = JSON.parse((await this.recvFrame()).toString());
    if (resp.Data) return Buffer.from(resp.Data);
    if (resp.Error) throw new Error(Buffer.from(resp.Error).toString("utf-8"));
    throw new Error(`Unexpected response: ${JSON.stringify(resp)}`);
  }
}

// ---------------------------------------------------------------------------
//  Pretty-print helper
// ---------------------------------------------------------------------------

export function printCertInfo(info: CertInfo): void {
  console.log(`  Subject      : ${info.subject}`);
  console.log(`  Issuer       : ${info.issuer}`);
  console.log(`  Serial       : ${info.serialNumber}`);
  console.log(`  Valid From   : ${info.validFrom}`);
  console.log(`  Valid To     : ${info.validTo}`);
  console.log(`  Cert SHA256  : ${info.pubkeySha256}`);

  if (info.quote) {
    const q = info.quote;
    console.log();
    console.log(`  ** RA-TLS Extension found! **`);
    console.log(`    OID       : ${q.oid}  (${q.label})`);
    console.log(`    Critical  : ${q.critical}`);
    console.log(`    Size      : ${q.raw.length} bytes`);
    if (q.isMock) console.log(`    ** MOCK QUOTE **`);
    if (q.version !== undefined) console.log(`    Version   : ${q.version}`);
    if (q.reportData) console.log(`    ReportData: ${q.reportData.toString("hex")}`);
    console.log(`    Preview   : ${q.raw.subarray(0, 32).toString("hex")}...`);
  } else {
    console.log();
    console.log(`  No RA-TLS extension found.`);
  }
}
