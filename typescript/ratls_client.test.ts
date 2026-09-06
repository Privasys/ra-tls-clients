// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// RA-TLS v2 tests: the shared vectors (tests/vectors/ratls-v2), message
// parsing and rejections, the exporter step through a pure HKDF-Expand-Label
// implementation, certificate checks against a throwaway test chain, and a
// loopback server that speaks both bindings. Run with `npm test`.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as tls from "node:tls";
import * as net from "node:net";
import {
  ATTEST_PATH,
  ATTESTATION_HEADER,
  AttestError,
  AttestationMode,
  CONTEXT_LEN,
  EXPORTER_LABEL_CLIENT,
  EXPORTER_LABEL_SERVER,
  Framing,
  MAX_FRAME,
  OID_ATTESTED_DEPENDENCY_SET,
  OID_IMAGE_PROFILE,
  OID_WORKLOAD_APP_ID,
  OID_WORKLOAD_CODE_HASH,
  PROTOCOL_VERSION,
  RaTlsClient,
  TeeType,
  TrustMode,
  appIdFromCert,
  buildAttestRequest,
  checkQuoteTime,
  clientReportData,
  decodeFrame,
  encodeDependencySet,
  encodeFrame,
  expectedReportData,
  foldIdentityHex,
  inspectDerCertificate,
  leafId,
  parseAttestResponse,
  parsePemCertificates,
  privasysTrustAnchors,
  publicTrustRoots,
  quoteReportData,
  spkiDerOf,
  verifyCertificateExtensions,
  verifyEvidence,
  verifyFleetChain,
  verifyPublicChain,
  platformAllowed,
  platformIdOf,
  platformIdentityFromQuote,
  reconcilePlatformIdentity,
  QuoteVerificationStatus,
  type QuoteVerificationResult,
  type ClientEvidence,
  type Evidence,
  type RaTlsClientOptions,
  type VerificationPolicy,
} from "./ratls_client.ts";

const hex = (s: string): Buffer => Buffer.from(s, "hex");
const sha256 = (b: Buffer | string): Buffer => crypto.createHash("sha256").update(b).digest();

// ---------------------------------------------------------------------------
//  Shared vectors: report_data
// ---------------------------------------------------------------------------

interface ReportDataVector {
  name: string;
  mode: "deterministic" | "challenge";
  spki_der: string;
  quote_time?: string;
  context?: string;
  hctx?: string;
  gpu_evidence?: string;
  report_data: string;
}

const vectorsPath = new URL("../tests/vectors/ratls-v2/report_data.json", import.meta.url);
const reportDataVectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as ReportDataVector[];

describe("report_data vectors", () => {
  assert.ok(reportDataVectors.length >= 4, "vector file holds the four cases");
  for (const v of reportDataVectors) {
    test(v.name, () => {
      const ev = {
        mode: v.mode as AttestationMode,
        quoteTimeRaw: v.quote_time ?? "",
        context: v.context ? hex(v.context) : undefined,
        hctx: v.hctx ? hex(v.hctx) : undefined,
        gpuEvidence: v.gpu_evidence ? hex(v.gpu_evidence) : undefined,
      };
      assert.equal(expectedReportData(hex(v.spki_der), ev).toString("hex"), v.report_data);
    });
  }

  test("the GPU fold is SHA-256(gpu_evidence) appended to the binding", () => {
    const v = reportDataVectors.find((x) => x.name === "deterministic-gpu")!;
    const binding = Buffer.concat([Buffer.from(v.quote_time!, "ascii"), sha256(hex(v.gpu_evidence!))]);
    const want = crypto.createHash("sha512").update(Buffer.concat([sha256(hex(v.spki_der)), binding])).digest();
    assert.equal(want.toString("hex"), v.report_data);
  });

  test("clientReportData is the challenge recipe with the client's SPKI", () => {
    const v = reportDataVectors.find((x) => x.name === "challenge-gpu")!;
    assert.equal(
      clientReportData(hex(v.spki_der), hex(v.context!), hex(v.hctx!), hex(v.gpu_evidence!)).toString("hex"),
      v.report_data,
    );
  });

  test("a mode without a binding is rejected", () => {
    assert.throws(() => expectedReportData(hex(reportDataVectors[0].spki_der), { mode: AttestationMode.None, quoteTimeRaw: "" }), /no report_data/);
    assert.throws(() => expectedReportData(hex(reportDataVectors[0].spki_der), { mode: AttestationMode.Deterministic, quoteTimeRaw: "" }), /quote_time/);
    assert.throws(
      () => expectedReportData(hex(reportDataVectors[0].spki_der), { mode: AttestationMode.Challenge, quoteTimeRaw: "", context: Buffer.alloc(31), hctx: Buffer.alloc(32) }),
      /32-byte context/,
    );
  });
});

// ---------------------------------------------------------------------------
//  Exporter: RFC 8446 section 7.5 without a TLS stack
// ---------------------------------------------------------------------------

function hkdfExpand(hash: string, prk: Buffer, info: Buffer, len: number): Buffer {
  const blocks: Buffer[] = [];
  let t = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(blocks).length < len; i++) {
    t = crypto.createHmac(hash, prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    blocks.push(t);
  }
  return Buffer.concat(blocks).subarray(0, len);
}

// HKDF-Expand-Label(Secret, Label, Context, Length) with the "tls13 " prefix.
function hkdfExpandLabel(hash: string, secret: Buffer, label: string, context: Buffer, len: number): Buffer {
  const l = Buffer.from(`tls13 ${label}`, "ascii");
  const info = Buffer.concat([Buffer.from([len >> 8, len & 0xff]), Buffer.from([l.length]), l, Buffer.from([context.length]), context]);
  return hkdfExpand(hash, secret, info, len);
}

// TLS-Exporter(label, context, len) =
//   HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""), "exporter", Hash(context), len)
function tlsExporter(hash: string, exporterMasterSecret: Buffer, label: string, context: Buffer, len: number): Buffer {
  const hashLen = crypto.createHash(hash).digest().length;
  const derived = hkdfExpandLabel(hash, exporterMasterSecret, label, crypto.createHash(hash).update("").digest(), hashLen);
  return hkdfExpandLabel(hash, derived, "exporter", crypto.createHash(hash).update(context).digest(), len);
}

// Captured from a Node.js (OpenSSL) TLS 1.3 loopback: the EXPORTER_SECRET
// keylog line and the socket's exportKeyingMaterial outputs for the v2 labels
// with a 32-byte 0xC0 context and with an empty context, for both hash suites.
const exporterVectors = [
  {
    cipher: "TLS_AES_128_GCM_SHA256", hash: "sha256",
    secret: "6d9008a8a213ec31322625f166674f53339e9543a464c3ace911e3fb0546332c",
    server: "296aa8a29592f0b7f398283a4ff21758843829c3ed1ea840a26a6f600e18adb1",
    client: "677306a7cc48bc03c5b6c9ce25099ddfad20e76bfca09828098bd21fb3f5e417",
    empty: "f23eabe5d79a0d037c0b6ba63b1766c33942c2523ad95ddbf864f0095bb043c5",
  },
  {
    cipher: "TLS_AES_256_GCM_SHA384", hash: "sha384",
    secret: "f98d59e0e99e7e5d0ab05b9c94b73411bf92eb57eb3f2cb83a83860694fd8bbc3929c94c44116ebbbc7e9ad44728d2c1",
    server: "6e9a442f5f3384c918748bd6fd724e16e6cec01860272baad5278699a0bceb38",
    client: "ee446992a4bce647ec13678411accf60e14fce1238d6ff17bbd44e8f01ff46b4",
    empty: "f42dc6e4a470848055ac60cb1d534ab35d7b4865d16169528c5e54e253ece852",
  },
];

describe("exporter", () => {
  const ctx = Buffer.alloc(CONTEXT_LEN, 0xc0);
  for (const v of exporterVectors) {
    test(`${v.cipher}: server label`, () => {
      assert.equal(tlsExporter(v.hash, hex(v.secret), EXPORTER_LABEL_SERVER, ctx, 32).toString("hex"), v.server);
    });
    test(`${v.cipher}: client label`, () => {
      assert.equal(tlsExporter(v.hash, hex(v.secret), EXPORTER_LABEL_CLIENT, ctx, 32).toString("hex"), v.client);
    });
    test(`${v.cipher}: empty context`, () => {
      assert.equal(tlsExporter(v.hash, hex(v.secret), EXPORTER_LABEL_SERVER, Buffer.alloc(0), 32).toString("hex"), v.empty);
    });
  }
  test("the labels are the ones of the spec", () => {
    assert.equal(EXPORTER_LABEL_SERVER, "EXPORTER-privasys-ratls-attest-v2");
    assert.equal(EXPORTER_LABEL_CLIENT, "EXPORTER-privasys-ratls-attest-v2-client");
  });

  // The shared vector file (Go reference against an OpenSSL server), when present.
  interface ExporterVector {
    name: string; hash: string; exporter_master_secret: string; label: string; context: string;
    length: number; hctx: string; client_label: string; client_hctx: string;
  }
  const sharedPath = new URL("../tests/vectors/ratls-v2/exporter.json", import.meta.url);
  const shared = fs.existsSync(sharedPath)
    ? (JSON.parse(fs.readFileSync(sharedPath, "utf8")) as { vectors: ExporterVector[] }).vectors
    : [];
  test("shared exporter.json vectors", { skip: shared.length === 0 && "tests/vectors/ratls-v2/exporter.json not present" }, () => {
    for (const v of shared) {
      assert.equal(v.label, EXPORTER_LABEL_SERVER);
      assert.equal(v.client_label, EXPORTER_LABEL_CLIENT);
      const ems = hex(v.exporter_master_secret);
      assert.equal(tlsExporter(v.hash, ems, v.label, hex(v.context), v.length).toString("hex"), v.hctx, v.name);
      assert.equal(tlsExporter(v.hash, ems, v.client_label, hex(v.context), v.length).toString("hex"), v.client_hctx, `${v.name} client`);
    }
  });
});

// ---------------------------------------------------------------------------
//  Messages
// ---------------------------------------------------------------------------

const vectorSpki = hex(reportDataVectors[0].spki_der);
const b64u = (b: Buffer): string => b.toString("base64url");
const fakeQuote = Buffer.alloc(632, 0x11);

function response(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 2, mode: "challenge", tee: "tdx", quote: b64u(fakeQuote), gpu_evidence: null,
    quote_time: "2026-09-04T10:15Z", client_evidence: "none", client_context: null,
    ...overrides,
  });
}

describe("messages", () => {
  test("request bodies", () => {
    const det = JSON.parse(buildAttestRequest(AttestationMode.Deterministic, vectorSpki));
    assert.deepEqual(det, { v: 2, mode: "deterministic", leaf: leafId(vectorSpki) });
    // SHA-256 of the vector SPKI, as in the Go and Rust report_data tests.
    assert.equal(leafId(vectorSpki), hex("5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3").toString("base64url"));
    const ctx = Buffer.alloc(CONTEXT_LEN, 0xc0);
    const ch = JSON.parse(buildAttestRequest(AttestationMode.Challenge, vectorSpki, ctx));
    assert.deepEqual(ch, { v: 2, mode: "challenge", leaf: leafId(vectorSpki), context: b64u(ctx) });
    assert.ok(!ch.context.includes("="), "base64url without padding");
    assert.throws(() => buildAttestRequest(AttestationMode.Challenge, vectorSpki, Buffer.alloc(31)), /32 bytes/);
    assert.throws(() => buildAttestRequest(AttestationMode.None, vectorSpki), /mode none/);
  });

  test("a canonical challenge response parses", () => {
    const p = parseAttestResponse(200, response(), AttestationMode.Challenge);
    assert.equal(p.tee, "tdx");
    assert.ok(p.quote.equals(fakeQuote));
    assert.equal(p.gpuEvidence, undefined);
    assert.equal(p.quoteTimeRaw, "2026-09-04T10:15Z");
    assert.equal(p.clientEvidenceRequired, false);
  });

  test("a deterministic tdx-gpu response with padded base64 parses", () => {
    const gpu = Buffer.from("PGAE\x01 gpu evidence envelope", "latin1");
    const p = parseAttestResponse(200, response({ mode: "deterministic", tee: "tdx-gpu", gpu_evidence: gpu.toString("base64url") + "==" }), AttestationMode.Deterministic);
    assert.equal(p.tee, "tdx-gpu");
    assert.ok(p.gpuEvidence!.equals(gpu));
  });

  test("client_evidence required carries a 32-byte client_context", () => {
    const cc = crypto.randomBytes(32);
    const p = parseAttestResponse(200, response({ client_evidence: "required", client_context: b64u(cc) }), AttestationMode.Challenge);
    assert.equal(p.clientEvidenceRequired, true);
    assert.ok(p.clientContext!.equals(cc));
  });

  const rejections: [string, number, string, AttestationMode, RegExp][] = [
    ["wrong version", 200, response({ v: 1 }), AttestationMode.Challenge, /version 1, want 2/],
    ["mode echo differs from the request", 200, response({ mode: "deterministic" }), AttestationMode.Challenge, /mode "deterministic", requested "challenge"/],
    ["unknown tee", 200, response({ tee: "sev" }), AttestationMode.Challenge, /unknown tee "sev"/],
    ["quote not base64url", 200, response({ quote: "not/base64+url" }), AttestationMode.Challenge, /quote is not base64url/],
    ["empty quote", 200, response({ quote: "" }), AttestationMode.Challenge, /quote is not base64url/],
    ["gpu_evidence not base64url", 200, response({ gpu_evidence: "a+b" }), AttestationMode.Challenge, /gpu_evidence is not base64url/],
    ["quote_time malformed", 200, response({ quote_time: "2026-09-04T10:15:00Z" }), AttestationMode.Challenge, /quote_time/],
    ["quote_time month out of range", 200, response({ quote_time: "2026-13-04T10:15Z" }), AttestationMode.Challenge, /quote_time/],
    ["client_evidence unknown", 200, response({ client_evidence: "optional" }), AttestationMode.Challenge, /unknown client_evidence "optional"/],
    ["client_evidence required without context", 200, response({ client_evidence: "required" }), AttestationMode.Challenge, /without a client_context/],
    ["client_context wrong length", 200, response({ client_evidence: "required", client_context: b64u(Buffer.alloc(16)) }), AttestationMode.Challenge, /32-byte base64url/],
    ["error field on the raw binding", 200, JSON.stringify({ v: 2, error: "quote provider unavailable" }), AttestationMode.Challenge, /attest failed \(200\): quote provider unavailable/],
    ["404 (gateway terminate path)", 404, "not found", AttestationMode.Challenge, /no RA-TLS v2 evidence endpoint/],
    ["503 quote provider", 503, JSON.stringify({ error: "quote provider unavailable" }), AttestationMode.Challenge, /attest failed \(503\): quote provider unavailable/],
    ["not JSON", 200, "<html>", AttestationMode.Challenge, /attest response/],
  ];
  for (const [name, status, body, mode, want] of rejections) {
    test(`rejects: ${name}`, () => {
      assert.throws(() => parseAttestResponse(status, body, mode), (e: unknown) => e instanceof AttestError && want.test(e.message) && e.status === status);
    });
  }
});

// ---------------------------------------------------------------------------
//  quote_time, quote layout, framing
// ---------------------------------------------------------------------------

describe("quote_time", () => {
  const now = new Date(Date.UTC(2026, 8, 4, 10, 20));
  test("fresh, at the age limit, and slightly ahead are accepted", () => {
    assert.equal(checkQuoteTime("2026-09-04T10:15Z", now).toISOString(), "2026-09-04T10:15:00.000Z");
    checkQuoteTime("2026-09-03T10:15Z", now); // 24 hours plus 5 minutes
    checkQuoteTime("2026-09-04T10:25Z", now); // 5 minutes of skew
  });
  test("too old, in the future, and malformed are rejected", () => {
    assert.throws(() => checkQuoteTime("2026-09-03T10:14Z", now), /older than 24 hours/);
    assert.throws(() => checkQuoteTime("2026-09-04T10:26Z", now), /in the future/);
    assert.throws(() => checkQuoteTime("2026-09-04 10:15Z", now), /not YYYY-MM-DDTHH:MMZ/);
    assert.throws(() => checkQuoteTime("", now), /not YYYY-MM-DDTHH:MMZ/);
  });
});

describe("quote report_data extraction", () => {
  test("SGX DCAP v3 and raw report", () => {
    const dcap = Buffer.alloc(432, 0); dcap.writeUInt16LE(3, 0); dcap.fill(0xaa, 368, 432);
    assert.ok(quoteReportData("sgx", dcap).equals(Buffer.alloc(64, 0xaa)));
    const raw = Buffer.alloc(432, 0); raw.fill(0xbb, 320, 384);
    assert.ok(quoteReportData("sgx", raw).equals(Buffer.alloc(64, 0xbb)));
    assert.throws(() => quoteReportData("sgx", Buffer.alloc(100)), /too small/);
  });
  test("TDX, tdx-gpu and SEV-SNP", () => {
    const tdx = Buffer.alloc(632, 0); tdx.fill(0xcc, 568, 632);
    assert.ok(quoteReportData("tdx", tdx).equals(Buffer.alloc(64, 0xcc)));
    assert.ok(quoteReportData("tdx-gpu", tdx).equals(Buffer.alloc(64, 0xcc)));
    assert.throws(() => quoteReportData("tdx", Buffer.alloc(600)), /too small/);
    const snp = Buffer.alloc(0x4a0, 0); snp.fill(0xdd, 0x50, 0x90);
    assert.ok(quoteReportData("sev-snp", snp).equals(Buffer.alloc(64, 0xdd)));
    assert.throws(() => quoteReportData("nvidia-gpu", tdx), /unknown evidence family/);
  });
});

describe("raw framing", () => {
  test("round trip, partial frame, oversize", () => {
    const payload = Buffer.from('{"v":2}');
    const frame = encodeFrame(payload);
    assert.equal(frame.readUInt32BE(0), payload.length);
    const d = decodeFrame(Buffer.concat([frame, Buffer.from("tail")]))!;
    assert.ok(d.payload.equals(payload));
    assert.equal(d.rest.toString(), "tail");
    assert.equal(decodeFrame(frame.subarray(0, 5)), null);
    assert.equal(decodeFrame(Buffer.alloc(2)), null);
    assert.throws(() => encodeFrame(Buffer.alloc(MAX_FRAME + 1)), /too large/);
    const big = Buffer.alloc(4); big.writeUInt32BE(MAX_FRAME + 1, 0);
    assert.throws(() => decodeFrame(big), /too large/);
  });
});

// ---------------------------------------------------------------------------
//  Test chain: root -> intermediate -> leaves (throwaway keys, test only)
// ---------------------------------------------------------------------------

const TEST_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIIBxDCCAWmgAwIBAgIUYoY5VoTo7PDYRae/WglwnP6qd1EwCgYIKoZIzj0EAwIw
LzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEVMBMGA1UEAwwMVGVzdCBSb290IENB
MB4XDTI2MDkwMzIyNDEzMFoXDTQ2MDgyOTIyNDEzMFowLzEWMBQGA1UECgwNUHJp
dmFzeXMgVGVzdDEVMBMGA1UEAwwMVGVzdCBSb290IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEMCkQjDojZjGFSyFfVVTk3IsaEFlTLD61wCjofNjSGpGQxLSg
gQTyMxLEy6bNd7F0QUtLMx1Eq4bwLFv6Reom96NjMGEwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNHoB0l8MDLDdzZ6tho+HIhBeZ+g
MB8GA1UdIwQYMBaAFNHoB0l8MDLDdzZ6tho+HIhBeZ+gMAoGCCqGSM49BAMCA0kA
MEYCIQCSrTImu8j2HGNprJiUA4C2LlxR9ElUfxJUFcV98EBI6gIhANI/tB0F78kt
SSMjcBFcpe7DqhO9UG+yAgo7fNBpfWM+
-----END CERTIFICATE-----
`;

const TEST_INT_PEM = `-----BEGIN CERTIFICATE-----
MIIBzjCCAXSgAwIBAgIUJzpQxvUXIvsr2a42hqdWoitrVrEwCgYIKoZIzj0EAwIw
LzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEVMBMGA1UEAwwMVGVzdCBSb290IENB
MB4XDTI2MDkwMzIyNDEzMFoXDTQ2MDgyOTIyNDEzMFowNzEWMBQGA1UECgwNUHJp
dmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATR08rSX+rzkqk9JSbNIRL9h+FkLzV+IrAydZjf
l6QgbvkRYpPLm+TG6qBTjN/OivzGI6MraNwivxtCLAXbWCwDo2YwZDASBgNVHRMB
Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUo97Wc5XDoLk+
6u1owtYk9xqHsIAwHwYDVR0jBBgwFoAU0egHSXwwMsN3Nnq2Gj4ciEF5n6AwCgYI
KoZIzj0EAwIDSAAwRQIgAYlVC6kjlDBH3bvUuRbeGfasnSEysYuiAFsS+fcPld4C
IQD7fZ4+YdASXdBDIVWuV/Y+MGatiItSSM8h97Kyy+AvWw==
-----END CERTIFICATE-----
`;

// Server leaf: Image Profile "production", app id 0123..ef, code digest, and an
// empty dependency set (OID 7.1 = 00000000).
const TEST_LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIICeTCCAiCgAwIBAgIUfUggqUJUTiNkvZseSvZA61cMUa4wCgYIKoZIzj0EAwIw
NzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1l
ZGlhdGUgQ0EwHhcNMjYwOTAzMjI1OTQ5WhcNNDYwODI5MjI1OTQ5WjAnMRYwFAYD
VQQKDA1Qcml2YXN5cyBUZXN0MQ0wCwYDVQQDDARsZWFmMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE8mCYAdUnf3Wp8tx7pL1goYTJBmAaPzVMexefNcCqtkPAA1To
QFVcRx76VFCgoc5Yg+fdglJUSklhY6UusRO7EaOCARgwggEUMAkGA1UdEwQCMAAw
DgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwGAYKKwYBBAGD/U4BAgQKcHJvZHVj
dGlvbjAeBgorBgEEAYP9TgQBBBABI0VniavN7wEjRWeJq83vMC4GCisGAQQBg/1O
BAIEIAARIjNEVWZ3iJmqu8zd7v8AESIzRFVmd4iZqrvM3e7/MBIGCisGAQQBg/1O
BwEEBAAAAAAwHQYDVR0OBBYEFGVs/nZ/hGvbn3MIImRTkpFeIuR1MB8GA1UdIwQY
MBaAFKPe1nOVw6C5PurtaMLWJPcah7CAMAoGCCqGSM49BAMCA0cAMEQCIEZanrse
0gRCVeW08t25qU1AISjgC4Tf9WKZAMH/6yRnAiAQOC4qOWAzrKT02JnrMPxyeSSe
1jYiEoj3DXoZ63W/ZQ==
-----END CERTIFICATE-----
`;

const TEST_LEAF_KEY_PEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGcB19WyRZHU/MvdWxfw0tPD9KuAX6rVxbpuguZnfo/xoAoGCCqGSM49
AwEHoUQDQgAE8mCYAdUnf3Wp8tx7pL1goYTJBmAaPzVMexefNcCqtkPAA1ToQFVc
Rx76VFCgoc5Yg+fdglJUSklhY6UusRO7EQ==
-----END EC PRIVATE KEY-----
`;

// Image Profile "dev".
const TEST_DEV_LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIICLzCCAdagAwIBAgIUfUggqUJUTiNkvZseSvZA61cMUa8wCgYIKoZIzj0EAwIw
NzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1l
ZGlhdGUgQ0EwHhcNMjYwOTAzMjI1OTUwWhcNNDYwODI5MjI1OTUwWjAqMRYwFAYD
VQQKDA1Qcml2YXN5cyBUZXN0MRAwDgYDVQQDDAdkZXZsZWFmMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEkhBdlRlMap7tQbhb9zhSlvEpwVeNZpULjrY35f84NPGr
xkyJBYt7aBaRQEX2v3sFh+Fz/52bxDrv3JFprQYvUKOBzDCByTAJBgNVHRMEAjAA
MA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
GgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0MBEGCisGAQQBg/1OAQIEA2RldjAe
BgorBgEEAYP9TgQBBBABI0VniavN7wEjRWeJq83vMB0GA1UdDgQWBBRlBaP1FeYe
Xcev4PruVQazp4hKkjAfBgNVHSMEGDAWgBSj3tZzlcOguT7q7WjC1iT3GoewgDAK
BggqhkjOPQQDAgNHADBEAiBNVHp7kSN/cjLoQP3F4Dev+jYsLKFn0pENeGLHaDZm
QQIgNlP+0GO3+woEbH91O3AhfjPK04xT8z/bWLj0fnp2jEc=
-----END CERTIFICATE-----
`;

// Client identity for the mutual leg: app id fedc..10.
const TEST_CLIENT_LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIICFDCCAbqgAwIBAgIUfUggqUJUTiNkvZseSvZA61cMUbAwCgYIKoZIzj0EAwIw
NzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1l
ZGlhdGUgQ0EwHhcNMjYwOTAzMjI1OTUwWhcNNDYwODI5MjI1OTUwWjAtMRYwFAYD
VQQKDA1Qcml2YXN5cyBUZXN0MRMwEQYDVQQDDApjbGllbnRsZWFmMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEtL4OVEoOirmyG24EaQnz9eTPgWRcKhvwY9yZNvJq
QjVn3sRYEDN4ZMayfzSCeDCe9ibMJnsTQzWAmqq9tiNgd6OBrTCBqjAJBgNVHRME
AjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAYBgorBgEE
AYP9TgECBApwcm9kdWN0aW9uMB4GCisGAQQBg/1OBAEEEP7cuph2VDIQ/ty6mHZU
MhAwHQYDVR0OBBYEFBLk7nfZahUrMdVPf6on+B14DGtaMB8GA1UdIwQYMBaAFKPe
1nOVw6C5PurtaMLWJPcah7CAMAoGCCqGSM49BAMCA0gAMEUCIQDZ4e1m+ED4gDzY
roCE0808eNAk7bDtz3D/4yTvx6NfxwIgc5/J11lKKj0un8Czo9p5Upld6zZDGFH9
5ct7D2bPRyk=
-----END CERTIFICATE-----
`;

const TEST_CLIENT_KEY_PEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK/leXXxIbzVb/uqjbWqopnkGrCQpG5EiG2vRvugyOzGoAoGCCqGSM49
AwEHoUQDQgAEtL4OVEoOirmyG24EaQnz9eTPgWRcKhvwY9yZNvJqQjVn3sRYEDN4
ZMayfzSCeDCe9ibMJnsTQzWAmqq9tiNgdw==
-----END EC PRIVATE KEY-----
`;

// A v1 leaf: carries the Intel TDX quote OID as a certificate extension.
const TEST_V1_LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIIB8TCCAZagAwIBAgIUfUggqUJUTiNkvZseSvZA61cMUbEwCgYIKoZIzj0EAwIw
NzEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEdMBsGA1UEAwwUVGVzdCBJbnRlcm1l
ZGlhdGUgQ0EwHhcNMjYwOTAzMjI1OTUwWhcNNDYwODI5MjI1OTUwWjApMRYwFAYD
VQQKDA1Qcml2YXN5cyBUZXN0MQ8wDQYDVQQDDAZ2MWxlYWYwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAShRApTQiejvcHlhfxrgXe3pj2Sq5QRBnzxGMDuvVK1pUUn
UiH74+CO8PxV55nM0P8KFwAUghgSjFS5+Je+63nUo4GNMIGKMAkGA1UdEwQCMAAw
DgYDVR0PAQH/BAQDAgeAMBMGCyqGSIb4TQEFBQEGBAQEAAAAMBgGCisGAQQBg/1O
AQIECnByb2R1Y3Rpb24wHQYDVR0OBBYEFHfLNafuq+Pz6BKMfY9UsS6qBIqYMB8G
A1UdIwQYMBaAFKPe1nOVw6C5PurtaMLWJPcah7CAMAoGCCqGSM49BAMCA0kAMEYC
IQCU7Mh8jHymODyOpQ6TMyN5iNzvA4YYxLVv5Ys90FKQRAIhAL+m8sGg+2NJ6sYP
EZJaucNy2UJRAAQceumOL4PFV8JU
-----END CERTIFICATE-----
`;

// A self-signed server certificate (CN=self-signed, SAN localhost and
// 127.0.0.1) that is neither under the test fleet anchor nor under a public
// root: a stand-in for a host that is not an enclave.
const TEST_SELF_SIGNED_PEM = `-----BEGIN CERTIFICATE-----
MIIBijCCATCgAwIBAgIULW7NS54zpR5KqZ108XPrQmeUUHowCgYIKoZIzj0EAwIw
LjEWMBQGA1UECgwNUHJpdmFzeXMgVGVzdDEUMBIGA1UEAwwLc2VsZi1zaWduZWQw
HhcNMjYwOTAzMDk1NTA4WhcNNDYwODMwMDk1NTA4WjAuMRYwFAYDVQQKDA1Qcml2
YXN5cyBUZXN0MRQwEgYDVQQDDAtzZWxmLXNpZ25lZDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLR8MHIhc9j8L19xcl91P8rJ+4A8qVI2H2Nvdj+RJ74WTNzQEVwz
ZboXtq0+P78stUc6FwM9ATZV+dY/wNmz64qjLDAqMAwGA1UdEwEB/wQCMAAwGgYD
VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIQCwKAnE
cKY0yjazozbjZCsxOu6MS7DeLanD9/spHYxsGwIgcl0A2JjnaZ9/FmC7uAzHnWgD
PEPdw2pMu9/tGtIm+kM=
-----END CERTIFICATE-----
`;

const TEST_SELF_SIGNED_KEY_PEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKvaWRMFa1K5ibm9JE0gXXHhOfLnMIwQ9fLuEAdMqGRgoAoGCCqGSM49
AwEHoUQDQgAEtHwwciFz2PwvX3FyX3U/ysn7gDypUjYfY292P5EnvhZM3NARXDNl
uhe2rT4/vyy1RzoXAz0BNlX51j/A2bPrig==
-----END EC PRIVATE KEY-----
`;

const derOf = (pem: string): Buffer => Buffer.from(parsePemCertificates(pem)[0].raw);
const leafDer = derOf(TEST_LEAF_PEM);
const intDer = derOf(TEST_INT_PEM);
const rootDer = derOf(TEST_ROOT_PEM);
const TEST_APP_ID = hex("0123456789abcdef0123456789abcdef");
const TEST_CODE_HASH = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
const NOW = new Date(Date.UTC(2030, 0, 1));

describe("certificate inspection", () => {
  test("v2 leaf: Privasys extensions, SPKI fingerprint, no evidence", () => {
    const info = inspectDerCertificate(leafDer);
    assert.equal(info.v1Leaf, false);
    assert.equal(info.attestation, AttestationMode.None);
    assert.equal(info.quote, undefined);
    assert.equal(info.spkiDer.length, 91);
    assert.equal(info.pubkeySha256, sha256(spkiDerOf(leafDer)).toString("hex"));
    assert.ok(info.subject.includes("CN=leaf"));
    const byOid = Object.fromEntries(info.customOids.map((e) => [e.oid, e]));
    assert.equal(byOid[OID_IMAGE_PROFILE].value.toString(), "production");
    assert.equal(byOid[OID_IMAGE_PROFILE].label, "Image Profile");
    assert.ok(byOid[OID_WORKLOAD_APP_ID].value.equals(TEST_APP_ID));
    assert.ok(byOid[OID_WORKLOAD_CODE_HASH].value.equals(TEST_CODE_HASH));
    assert.ok(byOid[OID_ATTESTED_DEPENDENCY_SET].value.equals(Buffer.alloc(4)));
    assert.equal(appIdFromCert(info), "0123456789abcdef0123456789abcdef");
    assert.ok(info.extensions.includes("2.5.29.17"), "standard extensions are listed too");
  });

  test("v1 leaf is flagged and rejected", () => {
    const info = inspectDerCertificate(derOf(TEST_V1_LEAF_PEM));
    assert.equal(info.v1Leaf, true);
    assert.equal(info.quote?.oid, "1.2.840.113741.1.5.5.1.6");
    assert.throws(() => verifyCertificateExtensions(derOf(TEST_V1_LEAF_PEM), { tee: TeeType.Tdx }), /v1 RA-TLS certificate/);
  });

  test("image profile: production passes, dev fails closed unless allowed", () => {
    verifyCertificateExtensions(leafDer, { tee: TeeType.Tdx });
    assert.throws(() => verifyCertificateExtensions(derOf(TEST_DEV_LEAF_PEM), { tee: TeeType.Tdx }), /"dev" image/);
    verifyCertificateExtensions(derOf(TEST_DEV_LEAF_PEM), { tee: TeeType.Tdx, allowDebugImages: true });
  });

  test("expected OIDs: present verbatim, mismatch, missing", () => {
    verifyCertificateExtensions(leafDer, { tee: TeeType.Tdx, expectedOids: [{ oid: OID_WORKLOAD_APP_ID, expectedValue: TEST_APP_ID }] });
    assert.throws(
      () => verifyCertificateExtensions(leafDer, { tee: TeeType.Tdx, expectedOids: [{ oid: OID_WORKLOAD_APP_ID, expectedValue: Buffer.alloc(16) }] }),
      /Workload App ID \(1.3.6.1.4.1.65230.4.1\) mismatch/,
    );
    assert.throws(
      () => verifyCertificateExtensions(derOf(TEST_DEV_LEAF_PEM), { tee: TeeType.Tdx, allowDebugImages: true, expectedOids: [{ oid: OID_WORKLOAD_CODE_HASH, expectedValue: TEST_CODE_HASH }] }),
      /expected OID 1.3.6.1.4.1.65230.4.2 \(Workload Code Digest\) not found/,
    );
  });

  test("dependency set: canonical encoding compared against OID 7.1", () => {
    verifyCertificateExtensions(leafDer, { tee: TeeType.Tdx, dependencySet: { entries: [] } });
    const set = { entries: [{ appId: "ab", measurements: [{ sgx: "FF" }], requiredOids: [] }] };
    assert.throws(() => verifyCertificateExtensions(leafDer, { tee: TeeType.Tdx, dependencySet: set }), /Attested Dependency Set .* mismatch/);
  });
});

describe("dependency set encoding", () => {
  test("is independent of declaration order and lowercases hex", () => {
    const a = encodeDependencySet({ entries: [
      { appId: "bb", measurements: [{ tdx: { mrtd: "AA", rtmr1: "BB", rtmr2: "CC" } }, { sgx: "11" }], requiredOids: [{ oid: "1.2", expectedValue: Buffer.from("y") }, { oid: "1.1", expectedValue: Buffer.from("x") }], foldedIdentity: "ABCD" },
      { appId: "aa", measurements: [], requiredOids: [] },
    ] });
    const b = encodeDependencySet({ entries: [
      { appId: "aa", measurements: [], requiredOids: [] },
      { appId: "bb", measurements: [{ sgx: "11" }, { tdx: { mrtd: "aa", rtmr1: "bb", rtmr2: "cc" } }], requiredOids: [{ oid: "1.1", expectedValue: Buffer.from("x") }, { oid: "1.2", expectedValue: Buffer.from("y") }], foldedIdentity: "abcd" },
    ] });
    assert.ok(a.equals(b));
    // u32 count, then "aa" entry: str, 0 measurements, 0 oids, "" folded.
    assert.equal(a.subarray(0, 4).readUInt32BE(0), 2);
    assert.equal(a.subarray(4, 10).toString("hex"), "00000002" + "6161");
    assert.equal(a.subarray(10, 22).toString("hex"), "00000000" + "00000000" + "00000000");
    assert.equal(encodeDependencySet({ entries: [] }).toString("hex"), "00000000");
  });
  test("fold identity is stable", () => {
    const f1 = foldIdentityHex(["SGX:AA"], [], { entries: [] });
    const f2 = foldIdentityHex(["sgx:aa"], [], { entries: [] });
    assert.equal(f1, f2);
    assert.equal(f1.length, 64);
    assert.notEqual(f1, foldIdentityHex(["sgx:ab"], [], { entries: [] }));
  });
});

describe("fleet chain", () => {
  const intAnchor = parsePemCertificates(TEST_INT_PEM);
  const rootAnchor = parsePemCertificates(TEST_ROOT_PEM);
  test("leaf + intermediate reaches an intermediate anchor", () => {
    verifyFleetChain([leafDer, intDer], intAnchor, NOW);
  });
  test("leaf + intermediate reaches a root anchor; leaf + intermediate + root too", () => {
    verifyFleetChain([leafDer, intDer], rootAnchor, NOW);
    verifyFleetChain([leafDer, intDer, rootDer], rootAnchor, NOW);
    verifyFleetChain([leafDer, intDer, rootDer], intAnchor, NOW);
  });
  test("a leaf alone does not reach a root anchor", () => {
    assert.throws(() => verifyFleetChain([leafDer], rootAnchor, NOW), /does not reach a trusted Privasys fleet anchor/);
  });
  test("the embedded Privasys anchors do not accept the test chain", () => {
    assert.equal(privasysTrustAnchors().length, 2);
    assert.throws(() => verifyFleetChain([leafDer, intDer, rootDer], privasysTrustAnchors(), NOW), /does not reach/);
  });
  test("validity is enforced", () => {
    assert.throws(() => verifyFleetChain([leafDer, intDer], intAnchor, new Date(Date.UTC(2020, 0, 1))), /not valid at/);
  });
  test("an empty chain is rejected", () => {
    assert.throws(() => verifyFleetChain([], intAnchor, NOW), /no certificate/);
  });
});

describe("public chain", () => {
  const roots = parsePemCertificates(TEST_ROOT_PEM);
  test("a chain to a root with a matching DNS or IP identity passes", () => {
    verifyPublicChain([leafDer, intDer], "localhost", { now: NOW, roots });
    verifyPublicChain([leafDer, intDer], "127.0.0.1", { now: NOW, roots });
    verifyPublicChain([leafDer, intDer, rootDer], "localhost", { now: NOW, roots });
  });
  test("identity mismatch, a missing root and validity are rejected", () => {
    assert.throws(() => verifyPublicChain([leafDer, intDer], "other.test", { now: NOW, roots }), /not valid for "other.test"/);
    assert.throws(() => verifyPublicChain([leafDer, intDer], "10.0.0.1", { now: NOW, roots }), /not valid for "10.0.0.1"/);
    assert.throws(() => verifyPublicChain([leafDer], "localhost", { now: NOW, roots }), /does not reach a public PKI root/);
    assert.throws(() => verifyPublicChain([leafDer, intDer], "localhost", { now: new Date(Date.UTC(2020, 0, 1)), roots }), /not valid at/);
    assert.throws(() => verifyPublicChain([derOf(TEST_SELF_SIGNED_PEM)], "localhost", { now: NOW, roots }), /does not reach a public PKI root/);
  });
  test("the bundled store is the default and does not hold the test root", () => {
    assert.ok(publicTrustRoots().length > 50, "Node ships a root store");
    assert.throws(() => verifyPublicChain([leafDer, intDer, rootDer], "localhost", { now: NOW }), /does not reach a public PKI root/);
  });
});

// ---------------------------------------------------------------------------
//  verifyEvidence with fabricated quotes
// ---------------------------------------------------------------------------

const MRTD = Buffer.alloc(48, 0xab);
const RTMR1 = Buffer.alloc(48, 0xc1);
const RTMR2 = Buffer.alloc(48, 0xc2);
const MRENCLAVE = Buffer.alloc(32, 0xe1);
const MRSIGNER = Buffer.alloc(32, 0xe2);

/** A TDX-shaped quote whose measurement registers and report_data are set. */
function fakeTdxQuote(reportData: Buffer): Buffer {
  const q = Buffer.alloc(632, 0);
  q.writeUInt16LE(4, 0);
  MRTD.copy(q, 184); RTMR1.copy(q, 424); RTMR2.copy(q, 472);
  reportData.copy(q, 568);
  return q;
}

function fakeSgxQuote(reportData: Buffer): Buffer {
  const q = Buffer.alloc(432, 0);
  q.writeUInt16LE(3, 0);
  MRENCLAVE.copy(q, 112); MRSIGNER.copy(q, 176);
  reportData.copy(q, 368);
  return q;
}

function evidenceFor(spki: Buffer, mode: AttestationMode, opts: { gpu?: Buffer; tee?: Evidence["tee"]; quoteTimeRaw?: string; quoteFactory?: (rd: Buffer) => Buffer } = {}): Evidence {
  const quoteTimeRaw = opts.quoteTimeRaw ?? "2026-09-04T10:15Z";
  const context = mode === AttestationMode.Challenge ? crypto.randomBytes(32) : undefined;
  const hctx = mode === AttestationMode.Challenge ? crypto.randomBytes(32) : undefined;
  const partial = { mode, quoteTimeRaw, context, hctx, gpuEvidence: opts.gpu };
  const rd = expectedReportData(spki, partial);
  return {
    ...partial,
    tee: opts.tee ?? (opts.gpu ? "tdx-gpu" : "tdx"),
    quote: (opts.quoteFactory ?? fakeTdxQuote)(rd),
    quoteTime: new Date(),
    clientEvidenceRequired: false,
  };
}

describe("verifyEvidence", () => {
  const spki = spkiDerOf(leafDer);
  const tdxPolicy: VerificationPolicy = { tee: TeeType.Tdx, mrTd: MRTD, rtmr1: RTMR1, rtmr2: RTMR2, expectedOids: [{ oid: OID_WORKLOAD_APP_ID, expectedValue: TEST_APP_ID }] };

  test("deterministic and challenge evidence verify against the leaf", async () => {
    for (const mode of [AttestationMode.Deterministic, AttestationMode.Challenge]) {
      const info = await verifyEvidence(leafDer, evidenceFor(spki, mode), tdxPolicy);
      assert.equal(info.attestation, mode);
      assert.equal(info.quote?.label, "TDX Quote");
      assert.equal(info.quote?.version, 4);
      assert.equal(info.evidence?.mode, mode);
    }
  });

  test("tdx-gpu evidence folds the GPU evidence; missing gpu_evidence fails", async () => {
    const gpu = Buffer.from("PGAE\x01 gpu evidence envelope", "latin1");
    const info = await verifyEvidence(leafDer, evidenceFor(spki, AttestationMode.Challenge, { gpu }), tdxPolicy);
    assert.ok(info.gpuEvidence?.equals(gpu));
    const ev = evidenceFor(spki, AttestationMode.Challenge, { gpu });
    ev.gpuEvidence = undefined;
    await assert.rejects(verifyEvidence(leafDer, ev, tdxPolicy), /tdx-gpu evidence without gpu_evidence/);
  });

  test("SGX evidence against an SGX policy", async () => {
    const ev = evidenceFor(spki, AttestationMode.Deterministic, { tee: "sgx", quoteFactory: fakeSgxQuote });
    const info = await verifyEvidence(leafDer, ev, { tee: TeeType.Sgx, mrEnclave: MRENCLAVE, mrSigner: MRSIGNER });
    assert.equal(info.quote?.label, "SGX Quote");
    await assert.rejects(verifyEvidence(leafDer, ev, { tee: TeeType.Sgx, mrEnclave: Buffer.alloc(32) }), /MRENCLAVE mismatch/);
  });

  test("report_data is predicted, never taken from the peer", async () => {
    const other = spkiDerOf(derOf(TEST_DEV_LEAF_PEM));
    await assert.rejects(verifyEvidence(leafDer, evidenceFor(other, AttestationMode.Deterministic), tdxPolicy), /report_data mismatch \(deterministic mode\)/);
    const ev = evidenceFor(spki, AttestationMode.Challenge);
    ev.hctx = crypto.randomBytes(32); // a different connection
    await assert.rejects(verifyEvidence(leafDer, ev, tdxPolicy), /report_data mismatch \(challenge mode\)/);
    const det = evidenceFor(spki, AttestationMode.Deterministic);
    det.quoteTimeRaw = "2026-09-04T10:16Z";
    await assert.rejects(verifyEvidence(leafDer, det, tdxPolicy), /report_data mismatch/);
  });

  test("policy failures name the step", async () => {
    const ev = evidenceFor(spki, AttestationMode.Challenge);
    await assert.rejects(verifyEvidence(leafDer, ev, { ...tdxPolicy, mrTd: Buffer.alloc(48) }), /MRTD mismatch/);
    await assert.rejects(verifyEvidence(leafDer, ev, { ...tdxPolicy, rtmr2: Buffer.alloc(48) }), /RTMR2 mismatch/);
    await assert.rejects(verifyEvidence(leafDer, ev, { tee: TeeType.Sgx }), /expected sgx evidence, got tdx/);
    await assert.rejects(verifyEvidence(leafDer, ev, { tee: TeeType.NvidiaGpu }), /not a primary evidence family/);
    await assert.rejects(verifyEvidence(leafDer, ev, { ...tdxPolicy, expectedOids: [{ oid: OID_WORKLOAD_APP_ID, expectedValue: Buffer.alloc(16) }] }), /Workload App ID .* mismatch/);
    await assert.rejects(verifyEvidence(leafDer, undefined, tdxPolicy), /no attestation evidence/);
    await assert.rejects(verifyEvidence(derOf(TEST_V1_LEAF_PEM), ev, tdxPolicy), /v1 RA-TLS certificate/);
    const mock = { ...ev, quote: Buffer.from("MOCK_QUOTE:" + "0".repeat(700)) };
    await assert.rejects(verifyEvidence(leafDer, mock, tdxPolicy), /MOCK quote/);
    const short = { ...ev, quote: ev.quote.subarray(0, 600) };
    await assert.rejects(verifyEvidence(leafDer, short, tdxPolicy), /TDX quote too small/);
  });
});

// ---------------------------------------------------------------------------
//  Loopback server: both bindings, mutual leg, re-attestation, tag
// ---------------------------------------------------------------------------

interface MockOptions {
  framing?: Framing;
  requireClientEvidence?: boolean;
  /** Tamper with the response body before it is sent. */
  tamper?: (resp: Record<string, unknown>) => void;
  requestCert?: boolean;
  quoteTimeRaw?: string;
  /** Server certificate chain and key (default: the test leaf under the test intermediate). */
  cert?: string;
  key?: string;
}

interface MockServer {
  port: number;
  close(): void;
  attestCount: number;
  lastTag: string;
  presentOk: boolean;
}

/** Read one HTTP/1.1 request (headers + Content-Length body) from a buffer. */
function parseHttpRequest(buf: Buffer): { method: string; path: string; body: Buffer; consumed: number } | null {
  const idx = buf.indexOf("\r\n\r\n");
  if (idx < 0) return null;
  const lines = buf.subarray(0, idx).toString("latin1").split("\r\n");
  const [method, path] = lines[0].split(" ");
  let len = 0;
  for (const l of lines.slice(1)) if (l.toLowerCase().startsWith("content-length:")) len = parseInt(l.split(":")[1], 10);
  if (buf.length < idx + 4 + len) return null;
  return { method, path, body: buf.subarray(idx + 4, idx + 4 + len), consumed: idx + 4 + len };
}

function httpReply(status: number, body: string, headers: Record<string, string> = {}): Buffer {
  const reason = { 200: "OK", 204: "No Content", 400: "Bad Request", 403: "Forbidden", 404: "Not Found" }[status] ?? "X";
  let h = `HTTP/1.1 ${status} ${reason}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n`;
  for (const [k, v] of Object.entries(headers)) h += `${k}: ${v}\r\n`;
  return Buffer.from(h + "\r\n" + body, "latin1");
}

/** An in-process RA-TLS v2 server built on the test chain, serving fake TDX quotes. */
async function startMockServer(opts: MockOptions = {}): Promise<MockServer> {
  const state: MockServer = { port: 0, close: () => {}, attestCount: 0, lastTag: "none", presentOk: false };
  const framing = opts.framing ?? Framing.Http;
  const sockets = new Set<tls.TLSSocket>();
  const server = tls.createServer({
    cert: opts.cert ?? TEST_LEAF_PEM + TEST_INT_PEM,
    key: opts.key ?? TEST_LEAF_KEY_PEM,
    minVersion: "TLSv1.3",
    ALPNProtocols: ["privasys-ratls/1", "http/1.1"],
    requestCert: opts.requestCert ?? false,
    rejectUnauthorized: opts.requestCert ?? false,
    ca: [TEST_ROOT_PEM, TEST_INT_PEM],
  }, (sock) => {
    sockets.add(sock);
    sock.on("close", () => sockets.delete(sock));
    let buf = Buffer.alloc(0);
    let tag = "none";
    let pendingClientContext: Buffer | undefined;

    const handle = (body: Buffer): { status: number; body: string } => {
      let req: Record<string, unknown>;
      try { req = JSON.parse(body.toString("utf8")); } catch { return { status: 400, body: JSON.stringify({ v: 2, error: "malformed" }) }; }
      if (req.mode === "present") {
        // Mutual leg: verify exactly as a client verifies a server response.
        const peer = sock.getPeerCertificate();
        const spki = spkiDerOf(Buffer.from(peer.raw));
        const cc = Buffer.from(String(req.context), "base64url");
        const hctx = Buffer.from(sock.exportKeyingMaterial(32, EXPORTER_LABEL_CLIENT, cc));
        const quote = Buffer.from(String(req.quote), "base64url");
        const ok = pendingClientContext !== undefined && cc.equals(pendingClientContext)
          && quoteReportData("tdx", quote).equals(clientReportData(spki, cc, hctx));
        state.presentOk = ok;
        if (!ok) return { status: 403, body: JSON.stringify({ v: 2, error: "client evidence rejected" }) };
        return { status: 204, body: framing === Framing.Raw ? JSON.stringify({ v: 2 }) : "" };
      }
      if (req.v !== 2) return { status: 400, body: JSON.stringify({ v: 2, error: "bad version" }) };
      const spki = spkiDerOf(leafDer);
      if (req.leaf !== leafId(spki)) return { status: 404, body: JSON.stringify({ v: 2, error: "unknown leaf" }) };
      const mode = String(req.mode) as AttestationMode;
      const quoteTimeRaw = opts.quoteTimeRaw ?? new Date().toISOString().slice(0, 16) + "Z";
      let context: Buffer | undefined;
      let hctx: Buffer | undefined;
      if (mode === "challenge") {
        context = Buffer.from(String(req.context), "base64url");
        if (context.length !== 32) return { status: 400, body: JSON.stringify({ v: 2, error: "context length" }) };
        hctx = Buffer.from(sock.exportKeyingMaterial(32, EXPORTER_LABEL_SERVER, context));
      }
      const rd = expectedReportData(spki, { mode, quoteTimeRaw, context, hctx });
      const resp: Record<string, unknown> = {
        v: 2, mode, tee: "tdx", quote: fakeTdxQuote(rd).toString("base64url"), gpu_evidence: null,
        quote_time: quoteTimeRaw, client_evidence: "none", client_context: null,
      };
      if (opts.requireClientEvidence) {
        pendingClientContext = crypto.randomBytes(32);
        resp.client_evidence = "required";
        resp.client_context = pendingClientContext.toString("base64url");
      }
      opts.tamper?.(resp);
      state.attestCount++;
      tag = mode;
      state.lastTag = tag;
      return { status: 200, body: JSON.stringify(resp) };
    };

    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (framing === Framing.Raw) {
          const f = decodeFrame(buf);
          if (!f) return;
          buf = Buffer.from(f.rest);
          const r = handle(Buffer.from(f.payload));
          sock.write(encodeFrame(Buffer.from(r.body)));
          continue;
        }
        const r = parseHttpRequest(buf);
        if (!r) return;
        buf = Buffer.from(buf.subarray(r.consumed));
        if (r.method === "POST" && r.path === ATTEST_PATH) {
          const a = handle(r.body);
          sock.write(httpReply(a.status, a.body));
        } else if (r.path === "/healthz") {
          // The workload sees the tag as a request header; echoed here so the test can read it.
          sock.write(httpReply(200, JSON.stringify({ status: "ok", attestation: tag }), { [ATTESTATION_HEADER]: tag }));
        } else if (r.path === "/big") {
          const body = JSON.stringify({ blob: "x".repeat(5000) });
          sock.write(Buffer.from(`HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`));
        } else {
          sock.write(httpReply(404, JSON.stringify({ error: "not found" })));
        }
      }
    });
    sock.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  state.port = (server.address() as net.AddressInfo).port;
  state.close = () => { for (const s of sockets) s.destroy(); server.close(); };
  return state;
}

const loopbackPolicy: VerificationPolicy = {
  tee: TeeType.Tdx, mrTd: MRTD, rtmr1: RTMR1, rtmr2: RTMR2,
  expectedOids: [{ oid: OID_WORKLOAD_APP_ID, expectedValue: TEST_APP_ID }],
  dependencySet: { entries: [] },
};

describe("loopback", () => {
  test("challenge mode over HTTP: handshake, evidence, verification, then application traffic", async () => {
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), serverName: "app.test" });
      await c.connect();
      assert.equal(c.tlsVersion, "TLSv1.3");
      assert.equal(c.alpnProtocol, "privasys-ratls/1");
      assert.equal(c.attestationMode, AttestationMode.Challenge);
      assert.equal(c.attestationTag, "challenge");
      assert.equal(c.evidence?.context?.length, CONTEXT_LEN);
      assert.equal(c.peerCertificatesDer().length, 2);
      const unverified = c.inspectCertificate();
      assert.equal(unverified.attestation, AttestationMode.Challenge);
      const info = await c.verifyCertificate(loopbackPolicy);
      assert.equal(info.attestation, AttestationMode.Challenge);
      assert.ok(info.quote?.reportData?.equals(expectedReportData(info.spkiDer, c.evidence!)));
      const health = await c.healthz();
      assert.equal(health.attestation, "challenge");
      const raw = await c.httpDo("GET", "/healthz");
      assert.equal(raw.headers[ATTESTATION_HEADER.toLowerCase()], "challenge");
      const big = await c.httpDo("GET", "/big");
      assert.equal((JSON.parse(big.body.toString()) as { blob: string }).blob.length, 5000, "chunked bodies are decoded");
      await c.reattest();
      assert.equal(srv.attestCount, 2);
      c.close();
    } finally {
      srv.close();
    }
  });

  test("deterministic mode binds quote_time; a stale quote_time is rejected", async () => {
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.Deterministic });
      await c.connect();
      assert.equal(c.attestationTag, "deterministic");
      assert.equal(c.evidence?.quoteTimeRaw.length, 17);
      await c.verifyCertificate(loopbackPolicy);
      c.close();
    } finally {
      srv.close();
    }
    const stale = await startMockServer({ quoteTimeRaw: "2020-01-01T00:00Z" });
    try {
      const c = new RaTlsClient("127.0.0.1", stale.port, { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.Deterministic });
      await assert.rejects(c.connect(), /older than 24 hours/);
    } finally {
      stale.close();
    }
  });

  test("a relaying verifier fixes the challenge context", async () => {
    const fixed = Buffer.alloc(CONTEXT_LEN, 0x5a);
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), context: fixed });
      await c.connect();
      assert.ok(c.evidence?.context?.equals(fixed));
      await c.verifyCertificate(loopbackPolicy);
      await c.reattest();
      assert.ok(c.evidence?.context?.equals(fixed), "the fixed context is reused on re-attestation");
      c.close();
    } finally {
      srv.close();
    }
    assert.throws(() => new RaTlsClient("127.0.0.1", 1, { context: Buffer.alloc(16) }), /options.context must be 32 bytes/);
  });

  test("mode none: certificate only, tagged none", async () => {
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.None });
      await c.connect();
      assert.equal(c.evidence, undefined);
      assert.equal(c.attestationTag, "none");
      const info = await c.verifyCertificate(loopbackPolicy);
      assert.equal(info.attestation, AttestationMode.None);
      assert.equal((await c.healthz()).attestation, "none");
      await assert.rejects(c.reattest(), /AttestationMode.None/);
      c.close();
    } finally {
      srv.close();
    }
  });

  test("raw binding: one frame each way, re-attestation refused", async () => {
    const srv = await startMockServer({ framing: Framing.Raw });
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), framing: Framing.Raw });
      await c.connect();
      await c.verifyCertificate(loopbackPolicy);
      assert.equal(c.attestationTag, "challenge");
      await assert.rejects(c.reattest(), /raw binding/);
      c.close();
    } finally {
      srv.close();
    }
  });

  test("mutual leg: client evidence presented and verified by the server", async () => {
    const srv = await startMockServer({ requestCert: true, requireClientEvidence: true });
    try {
      let seen: { context: Buffer; reportData: Buffer } | undefined;
      const source = async (req: { spkiDer: Buffer; context: Buffer; hctx: Buffer; reportData: Buffer }): Promise<ClientEvidence> => {
        seen = { context: req.context, reportData: req.reportData };
        assert.ok(req.reportData.equals(clientReportData(req.spkiDer, req.context, req.hctx)));
        return { tee: "tdx", quote: fakeTdxQuote(req.reportData), quoteTime: "2026-09-04T10:15Z" };
      };
      const c = new RaTlsClient("127.0.0.1", srv.port, {
        caCert: Buffer.from(TEST_INT_PEM),
        clientCert: { cert: TEST_CLIENT_LEAF_PEM + TEST_INT_PEM, key: TEST_CLIENT_KEY_PEM },
        clientEvidence: source,
      });
      await c.connect();
      assert.ok(seen, "the source was called");
      assert.equal(c.evidence?.clientEvidenceRequired, true);
      assert.ok(c.evidence?.clientContext?.equals(seen!.context));
      assert.equal(srv.presentOk, true);
      await c.verifyCertificate(loopbackPolicy);
      c.close();
    } finally {
      srv.close();
    }
  });

  test("mutual leg without a source or a client certificate fails closed", async () => {
    const srv = await startMockServer({ requireClientEvidence: true });
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM) });
      await assert.rejects(c.connect(), /options.clientEvidence is not set/);
      const source = async (): Promise<ClientEvidence> => ({ tee: "tdx", quote: Buffer.alloc(632), quoteTime: "2026-09-04T10:15Z" });
      const d = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), clientEvidence: source });
      await assert.rejects(d.connect(), /no client certificate was presented/);
    } finally {
      srv.close();
    }
  });

  test("a tampered response fails the connection at the named step", async () => {
    const cases: [string, MockOptions["tamper"], RegExp][] = [
      ["mode echo", (r) => { r.mode = "deterministic"; }, /mode "deterministic", requested "challenge"/],
      ["version", (r) => { r.v = 3; }, /version 3, want 2/],
      ["tee", (r) => { r.tee = "sgx"; }, /expected tdx evidence, got sgx/],
      ["report_data", (r) => { const q = Buffer.from(String(r.quote), "base64url"); q[600] ^= 1; r.quote = q.toString("base64url"); }, /report_data mismatch \(challenge mode\)/],
    ];
    for (const [name, tamper, want] of cases) {
      const srv = await startMockServer({ tamper });
      try {
        const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM) });
        if (name === "mode echo" || name === "version") {
          await assert.rejects(c.connect(), want);
        } else {
          await c.connect();
          await assert.rejects(c.verifyCertificate(loopbackPolicy), want);
          c.close();
        }
      } finally {
        srv.close();
      }
    }
  });

  test("a chain that does not reach the configured anchors is refused before any request", async () => {
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port); // embedded Privasys anchors
      await assert.rejects(c.connect(), /does not reach a trusted Privasys fleet anchor/);
      assert.equal(c.trustResolved, undefined);
      assert.equal(srv.attestCount, 0);
    } finally {
      srv.close();
    }
  });

  test("trust option validation: public never carries an attested mode or a fleet CA", () => {
    assert.throws(() => new RaTlsClient("127.0.0.1", 1, { trust: TrustMode.Public }), /trust "public" cannot be combined with attestation mode "challenge"/);
    assert.throws(() => new RaTlsClient("127.0.0.1", 1, { trust: TrustMode.Public, attestation: AttestationMode.Deterministic }), /attestation mode "deterministic"/);
    assert.throws(() => new RaTlsClient("127.0.0.1", 1, { trust: TrustMode.Public, attestation: AttestationMode.None, caCert: Buffer.from(TEST_INT_PEM) }), /caCert .*trust "public"/);
    assert.throws(() => new RaTlsClient("127.0.0.1", 1, { trust: "system" as TrustMode }), /unknown trust mode "system"/);
    const c = new RaTlsClient("127.0.0.1", 1, { trust: TrustMode.Public, attestation: AttestationMode.None });
    assert.equal(c.trustMode, TrustMode.Public);
    assert.equal(c.trustResolved, undefined);
    assert.equal(new RaTlsClient("127.0.0.1", 1).trustMode, TrustMode.Auto);
    assert.equal(new RaTlsClient("127.0.0.1", 1, { trust: TrustMode.Fleet }).trustMode, TrustMode.Fleet);
  });

  test("auto without evidence: a leaf under the fleet anchor passes and resolves to fleet", async () => {
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.None });
      await c.connect();
      assert.equal(c.trustMode, TrustMode.Auto);
      assert.equal(c.trustResolved, TrustMode.Fleet);
      assert.equal((await c.healthz()).attestation, "none");
      assert.equal(srv.attestCount, 0);
      c.close();
      const f = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.None, trust: TrustMode.Fleet });
      await f.connect();
      assert.equal(f.trustResolved, TrustMode.Fleet);
      f.close();
    } finally {
      srv.close();
    }
  });

  test("auto without evidence: a chain that reaches neither the fleet nor a public root is refused", async () => {
    const srv = await startMockServer();
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { attestation: AttestationMode.None }); // embedded anchors, bundled roots
      await assert.rejects(c.connect(), /reaches neither a Privasys fleet anchor nor a public PKI root for "127.0.0.1"/);
      assert.equal(c.trustResolved, undefined);
      assert.equal(srv.attestCount, 0);
    } finally {
      srv.close();
    }
  });

  test("a self-signed server is refused in every attested mode, in fleet, and in auto without evidence", async () => {
    const srv = await startMockServer({ cert: TEST_SELF_SIGNED_PEM, key: TEST_SELF_SIGNED_KEY_PEM });
    try {
      const fleetCases: RaTlsClientOptions[] = [
        {},                                                                   // challenge, embedded anchors
        { attestation: AttestationMode.Deterministic },
        { caCert: Buffer.from(TEST_INT_PEM) },                                // challenge, caller CA
        { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.Deterministic, trust: TrustMode.Auto },
        { attestation: AttestationMode.None, trust: TrustMode.Fleet },
        { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.None, trust: TrustMode.Fleet },
      ];
      for (const opts of fleetCases) {
        const c = new RaTlsClient("127.0.0.1", srv.port, opts);
        await assert.rejects(c.connect(), /does not reach a trusted Privasys fleet anchor/, JSON.stringify(opts));
      }
      // Auto without evidence: fleet fails, then the public walk fails too.
      const auto = new RaTlsClient("127.0.0.1", srv.port, { attestation: AttestationMode.None });
      await assert.rejects(auto.connect(), /reaches neither a Privasys fleet anchor nor a public PKI root/);
      const autoCa = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM), attestation: AttestationMode.None });
      await assert.rejects(autoCa.connect(), /reaches neither/);
      // Public only: Node's own verifier at the handshake.
      const pub = new RaTlsClient("127.0.0.1", srv.port, { attestation: AttestationMode.None, trust: TrustMode.Public });
      await assert.rejects(pub.connect(), /TLS connect: .*self.signed/i);
      assert.equal(srv.attestCount, 0);
    } finally {
      srv.close();
    }
  });

  test("the request is the first application data and names the leaf", async () => {
    const srv = await startMockServer({ tamper: (r) => { r.quote_time = "2026-09-04T10:15"; } });
    try {
      const c = new RaTlsClient("127.0.0.1", srv.port, { caCert: Buffer.from(TEST_INT_PEM) });
      await assert.rejects(c.connect(), /quote_time/);
      assert.equal(srv.attestCount, 1);
      assert.equal(PROTOCOL_VERSION, 2);
    } finally {
      srv.close();
    }
  });
});

// ---------------------------------------------------------------------------
//  Platform allow-list
// ---------------------------------------------------------------------------

describe("platform allow-list", () => {
  const PIID = "c055fc7b49bd4185dda796bf1795af32";
  const PPID = "414afbe506e8ac361add41f3133aab6f";
  const result = (piid: string, ppid: string, chipId: string): QuoteVerificationResult => ({
    status: QuoteVerificationStatus.Ok, advisoryIds: [], tcbStatus: "", platformInstanceId: piid, ppid, fmspc: "", chipId, platformFromQuote: false,
  });

  test("platformIdOf precedence", () => {
    assert.equal(platformIdOf(result(PIID, "aa", "cc")), PIID);
    assert.equal(platformIdOf(result("", "aa", "cc")), "aa");
    assert.equal(platformIdOf(result("", "", "cc")), "cc");
    assert.equal(platformIdOf(result("", "", "")), "");
  });

  test("platformAllowed semantics", () => {
    const r = result(PIID, PPID, "");
    platformAllowed(r, []);
    platformAllowed(r);
    for (const ok of [PIID, PIID.toUpperCase(), "c055fc7b-49bd-4185-dda7-96bf1795af32"]) platformAllowed(r, ["deadbeef", ok]);
    // The PPID does not stand in for a reported Platform Instance ID.
    assert.throws(() => platformAllowed(r, [PPID]), /not in allowedPlatformIds/);
    assert.throws(() => platformAllowed(result("", "", ""), [PIID]), /no platform identity/);
  });

  test("a list without a verifier is refused before anything is looked at", async () => {
    const ev: Evidence = { mode: AttestationMode.Deterministic, tee: "tdx", quote: Buffer.alloc(0), quoteTime: new Date("2026-09-04T10:15:00Z"), quoteTimeRaw: "2026-09-04T10:15Z", clientEvidenceRequired: false };
    await assert.rejects(
      verifyEvidence(leafDer, ev, { tee: TeeType.Tdx, allowedPlatformIds: [PIID] }),
      /allowedPlatformIds needs quoteVerification/,
    );
  });
});

describe("platform identity read from the quote (tests/vectors/ratls-v2/platform.json)", () => {
  const vector = JSON.parse(fs.readFileSync(new URL("../tests/vectors/ratls-v2/platform.json", import.meta.url), "utf8")) as {
    pck_leaf_pem: string; ppid: string; platform_instance_id: string; fmspc: string; platform_id: string;
    sev_snp: { report_size: number; chip_id_offset: number; chip_id: string };
  };
  const quoteWithChain = () => Buffer.concat([Buffer.alloc(632, 0x11), Buffer.from(vector.pck_leaf_pem), Buffer.alloc(8, 0x22)]);
  const result = (piid: string, ppid: string): QuoteVerificationResult => ({
    status: QuoteVerificationStatus.Ok, advisoryIds: [], tcbStatus: "", platformInstanceId: piid, ppid, fmspc: "", chipId: "", platformFromQuote: false,
  });

  test("reads PPID, FMSPC and Platform Instance ID from the PCK leaf", () => {
    const p = platformIdentityFromQuote("tdx", quoteWithChain());
    assert.ok(p);
    assert.deepEqual([p.ppid, p.platformInstanceId, p.fmspc, platformIdOf(p)], [vector.ppid, vector.platform_instance_id, vector.fmspc, vector.platform_id]);
    assert.equal(platformIdentityFromQuote("sgx", Buffer.from("no chain here")), undefined);
    assert.throws(() => platformIdentityFromQuote("tdx", Buffer.from(privasysTrustAnchors()[0].toString())), /not a PCK certificate/);
  });

  test("reads CHIP_ID from an SEV-SNP report", () => {
    const report = Buffer.alloc(vector.sev_snp.report_size);
    Buffer.from(vector.sev_snp.chip_id, "hex").copy(report, vector.sev_snp.chip_id_offset);
    const p = platformIdentityFromQuote("sev-snp", report);
    assert.equal(p?.chipId, vector.sev_snp.chip_id);
    assert.equal(platformIdOf(p!), vector.sev_snp.chip_id);
    assert.throws(() => platformIdentityFromQuote("sev-snp", report.subarray(0, 100)), /too small/);
  });

  test("the quote's identity is authoritative and cross-checked with the server's", () => {
    const quote = quoteWithChain();
    const agreeing = result(vector.platform_instance_id, vector.ppid);
    reconcilePlatformIdentity(agreeing, "tdx", quote);
    assert.equal(agreeing.platformFromQuote, true);
    assert.equal(agreeing.fmspc, vector.fmspc);
    const old = result("", "");
    reconcilePlatformIdentity(old, "tdx", quote);
    assert.equal(platformIdOf(old), vector.platform_id);
    platformAllowed(old, [vector.platform_id]);
    assert.throws(() => platformAllowed(old, ["0000"]), /not in allowedPlatformIds/);
    const liar = result("c055fc7b49bd4185dda796bf1795af32", vector.ppid);
    assert.throws(() => reconcilePlatformIdentity(liar, "tdx", quote), /platform identity mismatch/);
    const opaque = result("c055fc7b49bd4185dda796bf1795af32", "");
    reconcilePlatformIdentity(opaque, "tdx", Buffer.from("opaque"));
    assert.equal(opaque.platformFromQuote, false);
  });
});
