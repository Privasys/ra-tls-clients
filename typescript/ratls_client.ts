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

// Privasys configuration OIDs (PEN 1337)
export const OID_CONFIG_MERKLE_ROOT = "1.3.6.1.4.1.1337.1.1";
export const OID_EGRESS_CA_HASH = "1.3.6.1.4.1.1337.2.1";
export const OID_WASM_APPS_HASH = "1.3.6.1.4.1.1337.2.3";

export const PRIVASYS_OIDS: Record<string, string> = {
  [OID_CONFIG_MERKLE_ROOT]: "Config Merkle Root",
  [OID_EGRESS_CA_HASH]: "Egress CA Hash",
  [OID_WASM_APPS_HASH]: "WASM Apps Hash",
};

export const ALL_OIDS: Record<string, string> = { ...RATLS_OIDS, ...PRIVASYS_OIDS };

// ---------------------------------------------------------------------------
//  DCAP quote byte-offset constants
// ---------------------------------------------------------------------------

// SGX DCAP Quote v3: QuoteHeader(48) + ReportBody(384)
const SGX_QUOTE_MIN_SIZE = 432;
const SGX_QUOTE_MRENCLAVE_OFF = 112;
const SGX_QUOTE_MRENCLAVE_END = 144;
const SGX_QUOTE_MRSIGNER_OFF = 176;
const SGX_QUOTE_MRSIGNER_END = 208;
const SGX_QUOTE_REPORT_DATA_OFF = 368;
const SGX_QUOTE_REPORT_DATA_END = 432;

// TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584)
const TDX_QUOTE_MIN_SIZE = 632;
const TDX_QUOTE_MRTD_OFF = 184;
const TDX_QUOTE_MRTD_END = 232;
const TDX_QUOTE_REPORT_DATA_OFF = 568;
const TDX_QUOTE_REPORT_DATA_END = 632;

// ---------------------------------------------------------------------------
//  RA-TLS verification types
// ---------------------------------------------------------------------------

export enum TeeType {
  Sgx = "sgx",
  Tdx = "tdx",
}

export enum ReportDataMode {
  Skip = "skip",
  Deterministic = "deterministic",
  ChallengeResponse = "challenge-response",
}

export interface ExpectedOid {
  oid: string;
  expectedValue: Buffer;
}

export interface VerificationPolicy {
  tee: TeeType;
  mrEnclave?: Buffer;
  mrSigner?: Buffer;
  mrTd?: Buffer;
  reportData: ReportDataMode;
  nonce?: Buffer;
  expectedOids?: ExpectedOid[];
}

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

export interface OidExtension {
  oid: string;
  label: string;
  value: Buffer;
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
  customOids: OidExtension[];
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
    if (raw.length >= TDX_QUOTE_MIN_SIZE) {
      q.reportData = raw.subarray(TDX_QUOTE_REPORT_DATA_OFF, TDX_QUOTE_REPORT_DATA_END);
    }
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
    customOids: [],
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

  // Scan for Privasys configuration OIDs
  const privasysOidMap: Record<string, { bytes: Buffer; oid: string }> = {
    "Config Merkle Root": {
      bytes: encodeOidBytes([1, 3, 6, 1, 4, 1, 1337, 1, 1]),
      oid: OID_CONFIG_MERKLE_ROOT,
    },
    "Egress CA Hash": {
      bytes: encodeOidBytes([1, 3, 6, 1, 4, 1, 1337, 2, 1]),
      oid: OID_EGRESS_CA_HASH,
    },
    "WASM Apps Hash": {
      bytes: encodeOidBytes([1, 3, 6, 1, 4, 1, 1337, 2, 3]),
      oid: OID_WASM_APPS_HASH,
    },
  };

  for (const [label, { bytes, oid }] of Object.entries(privasysOidMap)) {
    const idx = der.indexOf(bytes);
    if (idx >= 0) {
      const value = tryExtractOctetString(der, idx + bytes.length);
      if (value) {
        info.customOids.push({ oid, label, value });
      }
    }
  }

  return info;
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

/**
 * Verify an RA-TLS certificate against a policy.
 * Returns the CertInfo on success.
 * Throws an Error on any verification failure.
 */
export function verifyRaTlsCert(der: Buffer, policy: VerificationPolicy): CertInfo {
  const info = inspectDerCertificate(der);

  // 1. Quote must be present
  if (!info.quote) throw new Error("no RA-TLS attestation quote in certificate");
  if (info.quote.isMock) throw new Error("certificate contains a MOCK quote");

  // 2. Correct TEE type
  if (policy.tee === TeeType.Sgx && info.quote.oid !== "1.2.840.113741.1.13.1.0") {
    throw new Error(`expected SGX quote, found ${info.quote.oid}`);
  }
  if (policy.tee === TeeType.Tdx && info.quote.oid !== "1.2.840.113741.1.5.5.1.6") {
    throw new Error(`expected TDX quote, found ${info.quote.oid}`);
  }

  // 3. Measurement registers
  verifyMeasurements(info.quote.raw, policy);

  // 4. ReportData
  verifyReportData(der, info.quote.raw, policy);

  // 5. Custom OID values
  verifyExpectedOids(info.customOids, policy.expectedOids ?? []);

  return info;
}

function verifyMeasurements(raw: Buffer, policy: VerificationPolicy): void {
  if (policy.tee === TeeType.Sgx) {
    if (raw.length < SGX_QUOTE_MIN_SIZE) {
      throw new Error(`SGX quote too small: ${raw.length} < ${SGX_QUOTE_MIN_SIZE}`);
    }
    if (policy.mrEnclave) {
      const actual = raw.subarray(SGX_QUOTE_MRENCLAVE_OFF, SGX_QUOTE_MRENCLAVE_END);
      if (!actual.equals(policy.mrEnclave)) {
        throw new Error(
          `MRENCLAVE mismatch: got ${actual.toString("hex")}, expected ${policy.mrEnclave.toString("hex")}`
        );
      }
    }
    if (policy.mrSigner) {
      const actual = raw.subarray(SGX_QUOTE_MRSIGNER_OFF, SGX_QUOTE_MRSIGNER_END);
      if (!actual.equals(policy.mrSigner)) {
        throw new Error(
          `MRSIGNER mismatch: got ${actual.toString("hex")}, expected ${policy.mrSigner.toString("hex")}`
        );
      }
    }
  } else {
    if (raw.length < TDX_QUOTE_MIN_SIZE) {
      throw new Error(`TDX quote too small: ${raw.length} < ${TDX_QUOTE_MIN_SIZE}`);
    }
    if (policy.mrTd) {
      const actual = raw.subarray(TDX_QUOTE_MRTD_OFF, TDX_QUOTE_MRTD_END);
      if (!actual.equals(policy.mrTd)) {
        throw new Error(
          `MRTD mismatch: got ${actual.toString("hex")}, expected ${policy.mrTd.toString("hex")}`
        );
      }
    }
  }
}

function verifyReportData(der: Buffer, raw: Buffer, policy: VerificationPolicy): void {
  if (policy.reportData === ReportDataMode.Skip) return;

  let binding: Buffer;
  if (policy.reportData === ReportDataMode.Deterministic) {
    if (policy.tee === TeeType.Sgx) return; // Not applicable for SGX
    // TDX: parse NotBefore from DER cert (simplified — use the validFrom from Node TLS or manual)
    // For now, trust the caller to supply a nonce instead, or use X509Certificate
    try {
      const x509 = new crypto.X509Certificate(der);
      const nb = new Date(x509.validFrom);
      const y = nb.getUTCFullYear();
      const m = String(nb.getUTCMonth() + 1).padStart(2, "0");
      const d = String(nb.getUTCDate()).padStart(2, "0");
      const h = String(nb.getUTCHours()).padStart(2, "0");
      const min = String(nb.getUTCMinutes()).padStart(2, "0");
      binding = Buffer.from(`${y}-${m}-${d}T${h}:${min}Z`);
    } catch {
      throw new Error("Cannot parse NotBefore for deterministic ReportData verification");
    }
  } else if (policy.reportData === ReportDataMode.ChallengeResponse) {
    if (!policy.nonce) throw new Error("ChallengeResponse mode requires a nonce");
    binding = policy.nonce;
  } else {
    return;
  }

  // Build pubkey input
  let pubkeyInput: Buffer;
  try {
    const x509 = new crypto.X509Certificate(der);
    const spkiDer = Buffer.from(
      x509.publicKey.export({ type: "spki", format: "der" })
    );
    if (policy.tee === TeeType.Sgx) {
      // SGX: raw EC point (last 65 bytes of SPKI)
      pubkeyInput = spkiDer.length >= 65 ? spkiDer.subarray(spkiDer.length - 65) : spkiDer;
    } else {
      // TDX: full SPKI DER
      pubkeyInput = spkiDer;
    }
  } catch {
    throw new Error("Cannot extract public key for ReportData verification");
  }

  const expected = computeReportDataHash(pubkeyInput, binding);

  // Get actual ReportData
  let actual: Buffer;
  if (policy.tee === TeeType.Sgx) {
    if (raw.length < SGX_QUOTE_REPORT_DATA_END) throw new Error("quote too small for ReportData");
    actual = raw.subarray(SGX_QUOTE_REPORT_DATA_OFF, SGX_QUOTE_REPORT_DATA_END);
  } else {
    if (raw.length < TDX_QUOTE_REPORT_DATA_END) throw new Error("quote too small for ReportData");
    actual = raw.subarray(TDX_QUOTE_REPORT_DATA_OFF, TDX_QUOTE_REPORT_DATA_END);
  }

  if (!actual.equals(expected)) {
    throw new Error(
      `ReportData mismatch:\n  got:      ${actual.toString("hex")}\n  expected: ${expected.toString("hex")}`
    );
  }
}

function verifyExpectedOids(actual: OidExtension[], expected: ExpectedOid[]): void {
  for (const exp of expected) {
    const found = actual.find((e) => e.oid === exp.oid);
    if (!found) {
      throw new Error(
        `expected OID ${exp.oid} (${ALL_OIDS[exp.oid] ?? "Unknown"}) not found in certificate`
      );
    }
    if (!found.value.equals(exp.expectedValue)) {
      throw new Error(
        `${ALL_OIDS[exp.oid] ?? exp.oid} mismatch: got ${found.value.toString("hex")}, expected ${exp.expectedValue.toString("hex")}`
      );
    }
  }
}

/** Compute SHA-512( SHA-256(pubkey) || binding ). */
function computeReportDataHash(pubkeyInput: Buffer, binding: Buffer): Buffer {
  const pkHash = crypto.createHash("sha256").update(pubkeyInput).digest();
  return crypto.createHash("sha512").update(Buffer.concat([pkHash, binding])).digest();
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
    if (!cert?.raw) return { subject: "", issuer: "", serialNumber: "", validFrom: "", validTo: "", pubkeySha256: "", extensions: [], customOids: [] };

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

  /** Verify the server's leaf certificate against a policy. */
  verifyCertificate(policy: VerificationPolicy): CertInfo {
    if (!this.socket) throw new Error("Not connected");
    const cert = this.socket.getPeerCertificate(true);
    if (!cert?.raw) throw new Error("no peer certificate");
    return verifyRaTlsCert(cert.raw, policy);
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

    // Display measurement registers
    if (q.oid === "1.2.840.113741.1.13.1.0" && q.raw.length >= SGX_QUOTE_MIN_SIZE) {
      console.log(`    MRENCLAVE : ${q.raw.subarray(SGX_QUOTE_MRENCLAVE_OFF, SGX_QUOTE_MRENCLAVE_END).toString("hex")}`);
      console.log(`    MRSIGNER  : ${q.raw.subarray(SGX_QUOTE_MRSIGNER_OFF, SGX_QUOTE_MRSIGNER_END).toString("hex")}`);
    } else if (q.oid === "1.2.840.113741.1.5.5.1.6" && q.raw.length >= TDX_QUOTE_MIN_SIZE) {
      console.log(`    MRTD      : ${q.raw.subarray(TDX_QUOTE_MRTD_OFF, TDX_QUOTE_MRTD_END).toString("hex")}`);
    }

    console.log(`    Preview   : ${q.raw.subarray(0, 32).toString("hex")}...`);
  } else {
    console.log();
    console.log(`  No RA-TLS extension found.`);
  }

  if (info.customOids.length > 0) {
    console.log();
    console.log(`  ** Privasys Configuration OIDs **`);
    for (const ext of info.customOids) {
      console.log(`    ${ext.label} (${ext.oid}): ${ext.value.toString("hex")}`);
    }
  }
}
