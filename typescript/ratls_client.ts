// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

/**
 * RA-TLS v2 client for the Privasys enclave runtimes (docs/ratls-v2.md).
 *
 * The certificate identifies the enclave: leaf key, chain to the Privasys
 * intermediate CA of its environment and the v2 Privasys extensions
 * (docs/oids.md). It carries no attestation evidence. After the TLS 1.3
 * handshake, and before any application data, the client asks the server for
 * evidence on the same connection (POST /__privasys/attest, or one raw
 * length-prefixed frame) and checks that the quote's report_data commits to
 * the leaf key and, in challenge mode, to an RFC 8446 section 7.5 exporter
 * value that only the two ends of this connection can derive.
 *
 * Chain check (TrustMode): an attested connection must chain to a Privasys
 * fleet anchor (or the caller CA). With no evidence requested the default
 * trust mode Auto also accepts the public PKI roots with hostname
 * verification, so a host that is not an enclave (privasys.id, the identity
 * provider) is reachable through the same client.
 *
 * Dependencies: Node.js built-ins only (tls, crypto, fs). TypeScript is kept
 * to erasable syntax so the file runs under Node's type stripping.
 *
 * Usage:
 *   import { RaTlsClient, TeeType, printCertInfo } from "./ratls_client.ts";
 *   const client = new RaTlsClient("141.94.219.130", 443, { serverName: "app.example" });
 *   await client.connect();                      // handshake + evidence exchange
 *   const info = await client.verifyCertificate({ tee: TeeType.Tdx, mrTd });
 *   printCertInfo(info);
 *   const resp = await client.sendData(Buffer.from("hello"), authToken);
 *   client.close();
 */

import * as tls from "node:tls";
import * as net from "node:net";
import * as fs from "node:fs";
import * as crypto from "node:crypto";
import {
  OID_ATTESTED_DEPENDENCY_SET,
  OID_EVIDENCE_SEV_SNP_REPORT,
  OID_IMAGE_PROFILE,
  OID_PRIVASYS_ARC_PREFIX,
  OID_SGX_QUOTE,
  OID_TDX_QUOTE,
  OID_WORKLOAD_APP_ID,
  oidLabel,
} from "./oids_gen.ts";

// The OID constants of scheme v2 are generated from oids.json; re-export them
// so callers import one module.
export * from "./oids_gen.ts";

// ---------------------------------------------------------------------------
//  Protocol constants
// ---------------------------------------------------------------------------

/** Reserved path of the evidence endpoint on every RA-TLS v2 server (HTTP binding). */
export const ATTEST_PATH = "/__privasys/attest";
/** The "v" field of every attest message. */
export const PROTOCOL_VERSION = 2;
/** Exporter label keying the server evidence of a connection. */
export const EXPORTER_LABEL_SERVER = "EXPORTER-privasys-ratls-attest-v2";
/** Exporter label keying the client evidence of a connection (mutual leg). */
export const EXPORTER_LABEL_CLIENT = "EXPORTER-privasys-ratls-attest-v2-client";
/** Length of a challenge context in bytes. */
export const CONTEXT_LEN = 32;
/** Length of the exporter output in bytes. */
export const HCTX_LEN = 32;
/** Largest raw-binding frame accepted, in bytes. */
export const MAX_FRAME = 65536;
/** Length of the ASCII quote_time, "YYYY-MM-DDTHH:MMZ". */
export const QUOTE_TIME_LEN = 17;
/**
 * Request header through which the runtime exposes the connection tag to the
 * workload: "none", "deterministic" or "challenge". A workload that requires
 * attested callers checks this header; it never trusts the caller's word.
 */
export const ATTESTATION_HEADER = "X-Privasys-Attestation";
/**
 * ALPN token advertised first by every RA-TLS client. The platform gateway
 * splices connections that advertise it straight to the enclave instead of
 * terminating them with its public certificate. "http/1.1" follows so the
 * enclave's HTTP server can negotiate a real protocol; "h2" is never offered
 * because this client speaks HTTP/1.1 over the raw socket.
 */
export const RATLS_ALPN_PROTO = "privasys-ratls/1";

// A deterministic quote_time is accepted within the runtime's 24-hour cache
// lifetime plus 5 minutes of skew, and rejected in the future beyond that skew.
const QUOTE_MAX_AGE_MS = (24 * 60 + 5) * 60 * 1000;
const QUOTE_SKEW_MS = 5 * 60 * 1000;

// ---------------------------------------------------------------------------
//  Quote byte-offset constants
// ---------------------------------------------------------------------------

// SGX DCAP Quote v3: QuoteHeader(48) + ReportBody(384).
export const SGX_QUOTE_MIN_SIZE = 432;
const SGX_QUOTE_MRENCLAVE_OFF = 112;
const SGX_QUOTE_MRENCLAVE_END = 144;
const SGX_QUOTE_MRSIGNER_OFF = 176;
const SGX_QUOTE_MRSIGNER_END = 208;
const SGX_QUOTE_REPORT_DATA_OFF = 368;
const SGX_QUOTE_REPORT_DATA_END = 432;

// SGX raw Report (sgx_create_report): no QuoteHeader, just ReportBody(432).
export const SGX_REPORT_SIZE = 432;
const SGX_REPORT_MRENCLAVE_OFF = 64;
const SGX_REPORT_MRENCLAVE_END = 96;
const SGX_REPORT_MRSIGNER_OFF = 128;
const SGX_REPORT_MRSIGNER_END = 160;
const SGX_REPORT_REPORT_DATA_OFF = 320;
const SGX_REPORT_REPORT_DATA_END = 384;

// TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584). MRTD alone (the TD
// firmware) does not identify the guest build; RTMR1 and RTMR2 carry the
// kernel/initrd and command line, so a full identity is MRTD + RTMR1 + RTMR2.
export const TDX_QUOTE_MIN_SIZE = 632;
const TDX_QUOTE_MRTD_OFF = 184;
const TDX_QUOTE_MRTD_END = 232;
const TDX_QUOTE_RTMR1_OFF = 424;
const TDX_QUOTE_RTMR1_END = 472;
const TDX_QUOTE_RTMR2_OFF = 472;
const TDX_QUOTE_RTMR2_END = 520;
const TDX_QUOTE_REPORT_DATA_OFF = 568;
const TDX_QUOTE_REPORT_DATA_END = 632;

// AMD SEV-SNP attestation report (0x4A0 = 1184 bytes).
export const SEV_SNP_REPORT_MIN_SIZE = 0x4a0;
const SEV_SNP_REPORT_DATA_OFF = 0x050;
const SEV_SNP_REPORT_DATA_END = 0x090;
const SEV_SNP_MEASUREMENT_OFF = 0x090;
const SEV_SNP_MEASUREMENT_END = 0x0c0;
const SEV_SNP_HOST_DATA_OFF = 0x0c0;
const SEV_SNP_HOST_DATA_END = 0x0e0;

/** Format of an SGX attestation blob. */
export const SgxQuoteFormat = {
  /** Full DCAP Quote v3 (48-byte header + report body + signature). */
  DcapV3: "dcap-v3",
  /** Raw SGX Report from sgx_create_report (no header). */
  RawReport: "raw-report",
} as const;
export type SgxQuoteFormat = (typeof SgxQuoteFormat)[keyof typeof SgxQuoteFormat];

/**
 * Detect whether an SGX blob is a DCAP Quote v3 or a raw Report. A DCAP quote
 * starts with a 2-byte little-endian version equal to 3; a raw Report starts
 * with CPUSVN[16], which never decodes to 3.
 */
export function detectSgxFormat(raw: Buffer): SgxQuoteFormat {
  if (raw.length >= 4 && raw.readUInt16LE(0) === 3) return SgxQuoteFormat.DcapV3;
  return SgxQuoteFormat.RawReport;
}

interface SgxOffsets {
  mreOff: number; mreEnd: number; mrsOff: number; mrsEnd: number;
  rdOff: number; rdEnd: number; minSize: number;
}

function sgxOffsets(format: SgxQuoteFormat): SgxOffsets {
  if (format === SgxQuoteFormat.DcapV3) {
    return {
      mreOff: SGX_QUOTE_MRENCLAVE_OFF, mreEnd: SGX_QUOTE_MRENCLAVE_END,
      mrsOff: SGX_QUOTE_MRSIGNER_OFF, mrsEnd: SGX_QUOTE_MRSIGNER_END,
      rdOff: SGX_QUOTE_REPORT_DATA_OFF, rdEnd: SGX_QUOTE_REPORT_DATA_END, minSize: SGX_QUOTE_MIN_SIZE,
    };
  }
  return {
    mreOff: SGX_REPORT_MRENCLAVE_OFF, mreEnd: SGX_REPORT_MRENCLAVE_END,
    mrsOff: SGX_REPORT_MRSIGNER_OFF, mrsEnd: SGX_REPORT_MRSIGNER_END,
    rdOff: SGX_REPORT_REPORT_DATA_OFF, rdEnd: SGX_REPORT_REPORT_DATA_END, minSize: SGX_REPORT_SIZE,
  };
}

// ---------------------------------------------------------------------------
//  Modes and TEE families
// ---------------------------------------------------------------------------

/** Target TEE family of a verification policy. */
export const TeeType = {
  Sgx: "sgx",
  Tdx: "tdx",
  SevSnp: "sev-snp",
  NvidiaGpu: "nvidia-gpu",
} as const;
export type TeeType = (typeof TeeType)[keyof typeof TeeType];

/**
 * What the client asks the server for after the handshake. Challenge is the
 * default and the safe choice.
 */
export const AttestationMode = {
  /** A quote bound to this connection through the TLS exporter and a fresh context. */
  Challenge: "challenge",
  /** The runtime's cached quote, bound to the leaf key and a minute timestamp only. */
  Deterministic: "deterministic",
  /** No request: the server tags the connection "none"; only the certificate is checked. */
  None: "none",
} as const;
export type AttestationMode = (typeof AttestationMode)[keyof typeof AttestationMode];

/** Carrier of the attest messages on the connection. */
export const Framing = {
  /** POST /__privasys/attest as an HTTP/1.1 request. */
  Http: "http",
  /** One u32 big-endian length-prefixed JSON frame in each direction (KMIP, raft). */
  Raw: "raw",
} as const;
export type Framing = (typeof Framing)[keyof typeof Framing];

/**
 * Which verifier the server chain must satisfy at the handshake.
 *
 * - Fleet: the Privasys fleet anchors, or the caller CA when one is given,
 *   without hostname verification (peers are dialled by IP; the identity is
 *   the evidence plus the app identity in the certificate).
 * - Public: the platform's public PKI roots with ordinary hostname
 *   verification, for a host that is not an enclave (the identity provider,
 *   for example). Only valid with AttestationMode.None: an attested
 *   connection must chain to the fleet.
 * - Auto (default): Fleet whenever evidence is requested (Challenge or
 *   Deterministic); with AttestationMode.None the chain is accepted when it
 *   satisfies Fleet or Public. An attested mode is never downgraded to Public.
 */
export const TrustMode = {
  Auto: "auto",
  Fleet: "fleet",
  Public: "public",
} as const;
export type TrustMode = (typeof TrustMode)[keyof typeof TrustMode];

/** The verifier a connection actually satisfied: Fleet or Public. */
export type ResolvedTrust = typeof TrustMode.Fleet | typeof TrustMode.Public;

/** Evidence family named by the "tee" field of an attest message. */
export type EvidenceTee = "sgx" | "tdx" | "tdx-gpu" | "sev-snp";

function teeTypeOf(tee: string): TeeType | undefined {
  switch (tee) {
    case "sgx": return TeeType.Sgx;
    case "tdx": case "tdx-gpu": return TeeType.Tdx;
    case "sev-snp": return TeeType.SevSnp;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
//  Verification types
// ---------------------------------------------------------------------------

/** An expected X.509 extension OID and its exact value. */
export interface ExpectedOid {
  oid: string;
  expectedValue: Buffer;
}

/** Verdict of the quote verification service. */
export const QuoteVerificationStatus = {
  Ok: "OK",
  TcbOutOfDate: "TCB_OUT_OF_DATE",
  ConfigurationNeeded: "CONFIGURATION_NEEDED",
  SwHardeningNeeded: "SW_HARDENING_NEEDED",
  ConfigurationAndSwHardeningNeeded: "CONFIGURATION_AND_SW_HARDENING_NEEDED",
  TcbRevoked: "TCB_REVOKED",
  TcbExpired: "TCB_EXPIRED",
  Unrecognized: "UNRECOGNIZED",
} as const;
export type QuoteVerificationStatus = (typeof QuoteVerificationStatus)[keyof typeof QuoteVerificationStatus];

/** Intel's platform TCB status as reported in the server's "tcbStatus" field. */
export const TcbStatus = {
  UpToDate: "UpToDate",
  SwHardeningNeeded: "SWHardeningNeeded",
  ConfigurationNeeded: "ConfigurationNeeded",
  ConfigurationAndSwHardeningNeeded: "ConfigurationAndSWHardeningNeeded",
  OutOfDate: "OutOfDate",
  OutOfDateConfigurationNeeded: "OutOfDateConfigurationNeeded",
  Revoked: "Revoked",
} as const;
export type TcbStatus = (typeof TcbStatus)[keyof typeof TcbStatus];

// Accepted without any relaxation; mirrors the attestation server's floor so
// the relying party enforces it even if the server does not.
const SECURE_TCB_FLOOR: ReadonlySet<string> = new Set([TcbStatus.UpToDate, TcbStatus.SwHardeningNeeded]);

/**
 * Accept a reported TCB status: Revoked never, the secure floor always, any
 * other value only when listed in `acceptable`. An empty status (a server that
 * does not report one) is accepted.
 */
export function tcbStatusAcceptable(status: string, acceptable: readonly string[] = []): void {
  if (status === "") return;
  if (status === TcbStatus.Revoked) throw new Error("TCB status Revoked is never acceptable");
  if (SECURE_TCB_FLOOR.has(status) || acceptable.includes(status)) return;
  throw new Error(`TCB status "${status}" not accepted: not in the secure floor and not in the configured acceptable set`);
}

/** Remote quote verification through an attestation server. */
export interface QuoteVerificationConfig {
  /** URL of the quote verification endpoint (POST). */
  endpoint: string;
  /** Optional Bearer token for the service. */
  token?: string;
  /** Verdicts accepted in addition to "OK". */
  acceptedStatuses?: QuoteVerificationStatus[];
  /**
   * Enforce the reported Intel tcbStatus against the secure floor plus
   * `acceptableTcbStatuses`. Opt-in so that a server that newly reports the
   * field does not silently start rejecting previously accepted platforms.
   */
  enforceTcbStatus?: boolean;
  /** Relaxations of the secure floor, consulted only with enforceTcbStatus. Revoked is never accepted. */
  acceptableTcbStatuses?: TcbStatus[];
  /** Request timeout in seconds (default 10). */
  timeoutSecs?: number;
}

/** Result of remote quote verification. */
export interface QuoteVerificationResult {
  status: QuoteVerificationStatus;
  tcbDate?: string;
  advisoryIds: string[];
  /** Intel's platform TCB status when the server reports it. */
  tcbStatus: string;
}

/** The attestation server's NVIDIA GPU verdict for a tdx-gpu connection. */
export interface GpuAttestationResult {
  verified: boolean;
  status: string;
  message: string;
  error: string;
  gpuUuid: string;
  driver: string;
  vbios: string;
  ccEnvironment: string;
  /** True only when firmware/VBIOS measurements matched a signed NVIDIA RIM. */
  measurementsVerified: boolean;
}

/** What a connection must prove. Absent registers are not checked. */
export interface VerificationPolicy {
  /** Expected TEE family. A tdx-gpu connection is verified with TeeType.Tdx. */
  tee: TeeType;
  /** Expected SGX MRENCLAVE (32 bytes). */
  mrEnclave?: Buffer;
  /** Expected SGX MRSIGNER (32 bytes). */
  mrSigner?: Buffer;
  /** Expected TDX MRTD (48 bytes). */
  mrTd?: Buffer;
  /** Expected TDX RTMR1 and RTMR2 (48 bytes each); with MRTD they pin the guest build. */
  rtmr1?: Buffer;
  rtmr2?: Buffer;
  /** Expected SEV-SNP MEASUREMENT (48 bytes). */
  measurement?: Buffer;
  /** Expected SEV-SNP HOST_DATA (32 bytes). */
  hostData?: Buffer;
  /** Extension values the certificate must carry verbatim. */
  expectedOids?: ExpectedOid[];
  /**
   * Attested dependency set the certificate must carry (OID 7.1), compared
   * against its canonical encoding (see encodeDependencySet).
   */
  dependencySet?: DependencySet;
  /** Remote quote verification (signature, collateral, TCB, GPU verdict). */
  quoteVerification?: QuoteVerificationConfig;
  /**
   * Accept certificates whose Image Profile (OID 1.2) is not "production",
   * for example "dev" images built with SSH and debug tooling. Fail-closed:
   * any other value counts as a debug image. Certificates without the
   * extension are accepted either way.
   */
  allowDebugImages?: boolean;
}

// ---------------------------------------------------------------------------
//  Evidence
// ---------------------------------------------------------------------------

/** The evidence a server returned for a connection. Verified only by verifyEvidence. */
export interface Evidence {
  /** Mode the evidence was requested in. */
  mode: AttestationMode;
  /** Evidence family: "sgx", "tdx", "tdx-gpu". */
  tee: EvidenceTee;
  /** Raw DCAP quote. */
  quote: Buffer;
  /** NVIDIA CC evidence bundle, absent without a GPU. */
  gpuEvidence?: Buffer;
  /** Minute the quote was minted, parsed from quoteTimeRaw. */
  quoteTime: Date;
  /** The 17-byte ASCII quote_time, an input of report_data in deterministic mode. */
  quoteTimeRaw: string;
  /** The client's 32-byte context (challenge mode). */
  context?: Buffer;
  /** This connection's exporter output for context (challenge mode). Never travels. */
  hctx?: Buffer;
  /** The server asked for client evidence (mutual leg) with this client_context. */
  clientEvidenceRequired: boolean;
  clientContext?: Buffer;
}

/** What a ClientEvidenceSource receives when the server requires client evidence. */
export interface ClientEvidenceRequest {
  /** DER SubjectPublicKeyInfo of the client certificate this connection presented. */
  spkiDer: Buffer;
  /** Server-chosen 32-byte client_context. */
  context: Buffer;
  /** This connection's exporter output under EXPORTER_LABEL_CLIENT. */
  hctx: Buffer;
  /**
   * The value the quote must carry: SHA-512(SHA-256(spkiDer) || context || hctx).
   * A source that returns GPU evidence recomputes it with the fold (clientReportData).
   */
  reportData: Buffer;
}

/** What a ClientEvidenceSource returns. */
export interface ClientEvidence {
  tee: EvidenceTee;
  quote: Buffer;
  gpuEvidence?: Buffer;
  quoteTime: string;
}

/**
 * Produces this client's own evidence on a mutual leg. An enclave runtime
 * implements it with its quote provider; a container asks its manager.
 */
export type ClientEvidenceSource = (req: ClientEvidenceRequest) => Promise<ClientEvidence>;

// ---------------------------------------------------------------------------
//  Messages
// ---------------------------------------------------------------------------

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

function b64Encode(b: Buffer): string {
  return b.toString("base64url");
}

/** Strict base64url decode (padding tolerated); null on any other character. */
function b64Decode(s: string): Buffer | null {
  const t = s.replace(/=+$/, "");
  if (!B64URL_RE.test(t)) return null;
  return Buffer.from(t, "base64url");
}

/** Error raised by the evidence exchange, carrying the HTTP status when there is one. */
export class AttestError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = "AttestError";
    this.status = status;
  }
}

/** The "leaf" field: SHA-256 of the SPKI DER of the received leaf, base64url. */
export function leafId(spkiDer: Buffer): string {
  return b64Encode(sha256(spkiDer));
}

/** Build the attest request body for a mode; context is required in challenge mode. */
export function buildAttestRequest(mode: AttestationMode, spkiDer: Buffer, context?: Buffer): string {
  if (mode === AttestationMode.None) throw new Error("ratls: no attest request in mode none");
  const req: Record<string, unknown> = { v: PROTOCOL_VERSION, mode, leaf: leafId(spkiDer) };
  if (mode === AttestationMode.Challenge) {
    if (!context || context.length !== CONTEXT_LEN) throw new Error(`ratls: challenge context must be ${CONTEXT_LEN} bytes`);
    req.context = b64Encode(context);
  }
  return JSON.stringify(req);
}

/** The parsed attest response before quote_time freshness and policy checks. */
export interface ParsedAttestResponse {
  tee: EvidenceTee;
  quote: Buffer;
  gpuEvidence?: Buffer;
  quoteTimeRaw: string;
  clientEvidenceRequired: boolean;
  clientContext?: Buffer;
}

/**
 * Parse and validate an attest response: status, error field, version, mode
 * echo, tee, base64url bodies, quote_time syntax, client_evidence fields.
 * Throws AttestError naming the rejection. Freshness of quote_time is
 * checkQuoteTime, applied by the client with its own clock.
 */
export function parseAttestResponse(status: number, body: Buffer | string, requestedMode: AttestationMode): ParsedAttestResponse {
  const text = typeof body === "string" ? body : body.toString("utf8");
  let resp: Record<string, unknown>;
  try {
    resp = JSON.parse(text) as Record<string, unknown>;
    if (!resp || typeof resp !== "object") throw new Error("not an object");
  } catch (e) {
    if (status === 404) throw new AttestError(`ratls: server has no RA-TLS v2 evidence endpoint (${ATTEST_PATH}): ${text.trim()}`, status);
    if (status !== 200) throw new AttestError(`ratls: attest failed (${status}): ${text.trim()}`, status);
    throw new AttestError(`ratls: attest response: ${(e as Error).message}`, status);
  }
  const errField = typeof resp.error === "string" ? resp.error : "";
  if (status !== 200 || errField !== "") {
    const detail = errField || text.trim();
    if (status === 404) throw new AttestError(`ratls: server has no RA-TLS v2 evidence endpoint (${ATTEST_PATH}): ${detail}`, status);
    throw new AttestError(`ratls: attest failed (${status}): ${detail}`, status);
  }
  if (resp.v !== PROTOCOL_VERSION) throw new AttestError(`ratls: attest response version ${String(resp.v)}, want ${PROTOCOL_VERSION}`, status);
  if (resp.mode !== requestedMode) throw new AttestError(`ratls: attest response mode "${String(resp.mode)}", requested "${requestedMode}"`, status);
  const tee = typeof resp.tee === "string" ? resp.tee : "";
  if (!teeTypeOf(tee)) throw new AttestError(`ratls: attest response: unknown tee "${tee}"`, status);
  const quote = typeof resp.quote === "string" ? b64Decode(resp.quote) : null;
  if (!quote || quote.length === 0) throw new AttestError("ratls: attest response: quote is not base64url", status);
  let gpuEvidence: Buffer | undefined;
  if (typeof resp.gpu_evidence === "string" && resp.gpu_evidence !== "") {
    const g = b64Decode(resp.gpu_evidence);
    if (!g) throw new AttestError("ratls: attest response: gpu_evidence is not base64url", status);
    gpuEvidence = g;
  } else if (resp.gpu_evidence !== undefined && resp.gpu_evidence !== null && resp.gpu_evidence !== "") {
    throw new AttestError("ratls: attest response: gpu_evidence is not base64url", status);
  }
  const quoteTimeRaw = typeof resp.quote_time === "string" ? resp.quote_time : "";
  if (parseQuoteTime(quoteTimeRaw) === null) throw new AttestError(`ratls: quote_time "${quoteTimeRaw}": not YYYY-MM-DDTHH:MMZ`, status);
  const out: ParsedAttestResponse = { tee: tee as EvidenceTee, quote, gpuEvidence, quoteTimeRaw, clientEvidenceRequired: false };
  const ce = resp.client_evidence ?? "";
  if (ce === "required") {
    if (typeof resp.client_context !== "string") throw new AttestError("ratls: server requires client evidence without a client_context", status);
    const cc = b64Decode(resp.client_context);
    if (!cc || cc.length !== CONTEXT_LEN) throw new AttestError(`ratls: client_context is not a ${CONTEXT_LEN}-byte base64url value`, status);
    out.clientEvidenceRequired = true;
    out.clientContext = cc;
  } else if (ce !== "" && ce !== "none") {
    throw new AttestError(`ratls: attest response: unknown client_evidence "${String(ce)}"`, status);
  }
  return out;
}

/** Build the "present" message of the mutual leg. */
export function buildPresentRequest(clientContext: Buffer, ce: ClientEvidence): string {
  return JSON.stringify({
    v: PROTOCOL_VERSION,
    mode: "present",
    context: b64Encode(clientContext),
    tee: ce.tee,
    quote: b64Encode(ce.quote),
    gpu_evidence: ce.gpuEvidence && ce.gpuEvidence.length > 0 ? b64Encode(ce.gpuEvidence) : null,
    quote_time: ce.quoteTime,
  });
}

// ---------------------------------------------------------------------------
//  report_data
// ---------------------------------------------------------------------------

function sha256(b: Buffer | string): Buffer {
  return crypto.createHash("sha256").update(b).digest();
}

/** SHA-512( SHA-256(spkiDer) || binding ). */
function computeReportDataHash(spkiDer: Buffer, binding: Buffer): Buffer {
  return crypto.createHash("sha512").update(Buffer.concat([sha256(spkiDer), binding])).digest();
}

/** The binding part of an Evidence; SHA-256(gpu_evidence) is folded after it. */
function reportDataBinding(ev: Pick<Evidence, "mode" | "quoteTimeRaw" | "context" | "hctx" | "gpuEvidence">): Buffer {
  let binding: Buffer;
  if (ev.mode === AttestationMode.Deterministic) {
    if (ev.quoteTimeRaw.length !== QUOTE_TIME_LEN) throw new Error("ratls: deterministic evidence needs a quote_time");
    binding = Buffer.from(ev.quoteTimeRaw, "ascii");
  } else if (ev.mode === AttestationMode.Challenge) {
    if (ev.context?.length !== CONTEXT_LEN || ev.hctx?.length !== HCTX_LEN) {
      throw new Error(`ratls: challenge evidence needs a ${CONTEXT_LEN}-byte context and a ${HCTX_LEN}-byte exporter value`);
    }
    binding = Buffer.concat([ev.context, ev.hctx]);
  } else {
    throw new Error(`ratls: no report_data for attestation mode ${ev.mode}`);
  }
  if (ev.gpuEvidence && ev.gpuEvidence.length > 0) binding = Buffer.concat([binding, sha256(ev.gpuEvidence)]);
  return binding;
}

/**
 * The report_data a quote must carry for the leaf whose SubjectPublicKeyInfo
 * is spkiDer and the evidence ev:
 *
 *   deterministic: SHA-512( SHA-256(SPKI_DER) || quote_time )
 *   challenge:     SHA-512( SHA-256(SPKI_DER) || context || hctx )
 *
 * with SHA-256(gpu_evidence) appended to the binding when GPU evidence is
 * present. The verifier predicts this value; it never accepts one from the peer.
 */
export function expectedReportData(
  spkiDer: Buffer,
  ev: Pick<Evidence, "mode" | "quoteTimeRaw" | "context" | "hctx" | "gpuEvidence">,
): Buffer {
  return computeReportDataHash(spkiDer, reportDataBinding(ev));
}

/** expectedReportData for the client evidence of a mutual leg (same GPU fold). */
export function clientReportData(spkiDer: Buffer, clientContext: Buffer, hctx: Buffer, gpuEvidence?: Buffer): Buffer {
  let binding = Buffer.concat([clientContext, hctx]);
  if (gpuEvidence && gpuEvidence.length > 0) binding = Buffer.concat([binding, sha256(gpuEvidence)]);
  return computeReportDataHash(spkiDer, binding);
}

/** The 64-byte report_data of a raw quote of the given evidence family. */
export function quoteReportData(tee: string, quote: Buffer): Buffer {
  switch (tee) {
    case "sgx": {
      const o = sgxOffsets(detectSgxFormat(quote));
      if (quote.length < o.rdEnd) throw new Error("SGX quote too small to contain report_data");
      return quote.subarray(o.rdOff, o.rdEnd);
    }
    case "tdx":
    case "tdx-gpu":
      if (quote.length < TDX_QUOTE_REPORT_DATA_END) throw new Error("TDX quote too small to contain report_data");
      return quote.subarray(TDX_QUOTE_REPORT_DATA_OFF, TDX_QUOTE_REPORT_DATA_END);
    case "sev-snp":
      if (quote.length < SEV_SNP_REPORT_DATA_END) throw new Error("SEV-SNP report too small to contain report_data");
      return quote.subarray(SEV_SNP_REPORT_DATA_OFF, SEV_SNP_REPORT_DATA_END);
  }
  throw new Error(`unknown evidence family "${tee}"`);
}

/** Parse "YYYY-MM-DDTHH:MMZ" strictly; null when malformed. */
function parseQuoteTime(raw: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})Z$/.exec(raw);
  if (!m) return null;
  const [y, mo, d, h, mi] = m.slice(1).map(Number);
  const t = new Date(Date.UTC(y, mo - 1, d, h, mi));
  // Reject dates that Date.UTC normalised (for example month 13).
  if (t.getUTCFullYear() !== y || t.getUTCMonth() !== mo - 1 || t.getUTCDate() !== d || t.getUTCHours() !== h || t.getUTCMinutes() !== mi) return null;
  return t;
}

/**
 * Reject a quote_time older than the runtime's cache lifetime (24 hours plus
 * 5 minutes of skew) or ahead of the clock beyond the skew. Returns the parsed time.
 */
export function checkQuoteTime(raw: string, now: Date = new Date()): Date {
  const t = parseQuoteTime(raw);
  if (!t) throw new Error(`ratls: quote_time "${raw}": not YYYY-MM-DDTHH:MMZ`);
  if (t.getTime() > now.getTime() + QUOTE_SKEW_MS) throw new Error(`ratls: quote_time ${raw} is in the future`);
  if (now.getTime() - t.getTime() > QUOTE_MAX_AGE_MS) throw new Error(`ratls: quote_time ${raw} is older than 24 hours`);
  return t;
}

/**
 * The 32-byte exporter value of a connection for label and context (RFC 8446
 * section 7.5), keyed by exporter_master_secret. TLS 1.3 only.
 */
export function exportHctx(socket: tls.TLSSocket, label: string, context: Buffer): Buffer {
  const proto = socket.getProtocol();
  if (proto !== "TLSv1.3") throw new Error(`ratls: exporter needs TLS 1.3, negotiated ${proto ?? "unknown"}`);
  return Buffer.from(socket.exportKeyingMaterial(HCTX_LEN, label, context));
}

/**
 * Takes the place of the exporter output when a container proves its identity
 * out of band (HTTP headers to the control plane) where no TLS connection to
 * the verifier exists: report_data = clientReportData(SPKI, challenge,
 * HEADER_IDENTITY_HCTX) with challenge the verifier's 32-byte value.
 */
export const HEADER_IDENTITY_HCTX: Buffer = sha256("privasys-ratls-attest-v2-header-identity");

// ---------------------------------------------------------------------------
//  Raw framing
// ---------------------------------------------------------------------------

/** One raw-binding frame: u32 big-endian length || payload. */
export function encodeFrame(payload: Buffer): Buffer {
  if (payload.length > MAX_FRAME) throw new Error(`frame too large: ${payload.length}`);
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

/** Decode one frame from the front of buf; null while incomplete. */
export function decodeFrame(buf: Buffer): { payload: Buffer; rest: Buffer } | null {
  if (buf.length < 4) return null;
  const length = buf.readUInt32BE(0);
  if (length > MAX_FRAME) throw new Error(`frame too large: ${length}`);
  if (buf.length < 4 + length) return null;
  return { payload: buf.subarray(4, 4 + length), rest: buf.subarray(4 + length) };
}

// ---------------------------------------------------------------------------
//  DER helpers (extension walk)
// ---------------------------------------------------------------------------

interface Tlv { tag: number; start: number; end: number; next: number }

function readTlv(buf: Buffer, off: number): Tlv {
  if (off + 2 > buf.length) throw new Error("DER: truncated");
  const tag = buf[off];
  let len = buf[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > buf.length) throw new Error("DER: bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > buf.length) throw new Error("DER: truncated value");
  return { tag, start: p, end: p + len, next: p + len };
}

function decodeOid(b: Buffer): string {
  if (b.length === 0) throw new Error("DER: empty OID");
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) {
      if (parts.length === 0) {
        const first = v < 80 ? Math.floor(v / 40) : 2;
        parts.push(first, v - first * 40);
      } else {
        parts.push(v);
      }
      v = 0;
    }
  }
  return parts.join(".");
}

/** A raw X.509 extension. */
export interface RawExtension { oid: string; critical: boolean; value: Buffer }

/** Every extension of a DER certificate, in order. */
export function parseCertificateExtensions(der: Buffer): RawExtension[] {
  const cert = readTlv(der, 0);
  const tbs = readTlv(der, cert.start);
  let p = tbs.start;
  const t0 = readTlv(der, p);
  if (t0.tag === 0xa0) p = t0.next; // [0] version
  for (let i = 0; i < 6; i++) p = readTlv(der, p).next; // serial, sigalg, issuer, validity, subject, spki
  const out: RawExtension[] = [];
  while (p < tbs.end) {
    const t = readTlv(der, p);
    if (t.tag === 0xa3) {
      const seq = readTlv(der, t.start);
      let q = seq.start;
      while (q < seq.end) {
        const ext = readTlv(der, q);
        const oidT = readTlv(der, ext.start);
        let r = oidT.next;
        let critical = false;
        let val = readTlv(der, r);
        if (val.tag === 0x01) {
          critical = der[val.start] !== 0;
          r = val.next;
          val = readTlv(der, r);
        }
        out.push({ oid: decodeOid(der.subarray(oidT.start, oidT.end)), critical, value: Buffer.from(der.subarray(val.start, val.end)) });
        q = ext.next;
      }
      break;
    }
    p = t.next;
  }
  return out;
}

/** DER SubjectPublicKeyInfo of a certificate (91 bytes for P-256). */
export function spkiDerOf(der: Buffer): Buffer {
  return Buffer.from(new crypto.X509Certificate(der).publicKey.export({ type: "spki", format: "der" }));
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

/** The evidence body attached to a CertInfo. */
export interface QuoteInfo {
  /** Quote format, named by the Intel-arc OIDs (as v1 did) or the SEV-SNP evidence type. */
  oid: string;
  label: string;
  critical: boolean;
  raw: Buffer;
  isMock: boolean;
  version?: number;
  reportData?: Buffer;
}

/** A Privasys-arc X.509 extension. */
export interface OidExtension {
  oid: string;
  label: string;
  value: Buffer;
}

/** Summary of a server's RA-TLS certificate and the evidence of its connection. */
export interface CertInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  /** Hex SHA-256 of the SPKI DER, the standard public-key fingerprint and the report_data input. */
  pubkeySha256: string;
  /** DER SubjectPublicKeyInfo of the leaf. */
  spkiDer: Buffer;
  /** Every extension OID of the certificate. */
  extensions: string[];
  /** A v1 certificate (evidence inside the certificate); a v2 verifier fails closed on it. */
  v1Leaf: boolean;
  /** Evidence body of the connection, from the attest response (on a v1 leaf, the unverified extension, for display). */
  quote?: QuoteInfo;
  /** NVIDIA GPU CC evidence of the attest response, when present. */
  gpuEvidence?: Buffer;
  /** Mode the evidence was obtained in; "none" when the connection carries no evidence. */
  attestation: AttestationMode;
  /** Full evidence record after verifyEvidence succeeded. */
  evidence?: Evidence;
  /** Privasys-arc extensions found in the certificate. */
  customOids: OidExtension[];
  /** Remote quote verification result (populated during verification). */
  quoteVerification?: QuoteVerificationResult;
  /** NVIDIA GPU verdict (populated during verification of a tdx-gpu connection). */
  gpuAttestation?: GpuAttestationResult;
}

const MOCK_PREFIX = "MOCK_QUOTE:";

function isMockQuote(raw: Buffer): boolean {
  return raw.length >= MOCK_PREFIX.length && raw.subarray(0, MOCK_PREFIX.length).toString("latin1") === MOCK_PREFIX;
}

/** QuoteInfo of a v1 quote extension, for display only. */
function parseV1Quote(oid: string, critical: boolean, raw: Buffer): QuoteInfo {
  const q: QuoteInfo = { oid, label: oidLabel(oid), critical, raw, isMock: isMockQuote(raw) };
  if (q.isMock) {
    q.reportData = raw.subarray(MOCK_PREFIX.length, Math.min(75, raw.length));
  } else if (raw.length >= 4) {
    q.version = raw.readUInt16LE(0);
    try { q.reportData = quoteReportData(oid === OID_SGX_QUOTE ? "sgx" : "tdx", raw); } catch { /* too short */ }
  }
  return q;
}

/** QuoteInfo of an attest-response quote. */
function quoteInfoOf(ev: Evidence): QuoteInfo {
  const oid = ev.tee === "sgx" ? OID_SGX_QUOTE : ev.tee === "sev-snp" ? OID_EVIDENCE_SEV_SNP_REPORT : OID_TDX_QUOTE;
  const q: QuoteInfo = { oid, label: oidLabel(oid), critical: false, raw: ev.quote, isMock: isMockQuote(ev.quote) };
  if (ev.quote.length >= 2) q.version = ev.quote.readUInt16LE(0);
  try { q.reportData = quoteReportData(ev.tee, ev.quote); } catch { /* too short */ }
  return q;
}

/** Inspect a DER certificate for the Privasys-arc extensions and the v1 shape. */
export function inspectDerCertificate(der: Buffer): CertInfo {
  const x = new crypto.X509Certificate(der);
  const spkiDer = Buffer.from(x.publicKey.export({ type: "spki", format: "der" }));
  const info: CertInfo = {
    subject: x.subject.split("\n").join(", "),
    issuer: x.issuer.split("\n").join(", "),
    serialNumber: x.serialNumber,
    validFrom: x.validFrom,
    validTo: x.validTo,
    pubkeySha256: sha256(spkiDer).toString("hex"),
    spkiDer,
    extensions: [],
    v1Leaf: false,
    attestation: AttestationMode.None,
    customOids: [],
  };
  for (const ext of parseCertificateExtensions(der)) {
    info.extensions.push(ext.oid);
    if (ext.oid === OID_SGX_QUOTE || ext.oid === OID_TDX_QUOTE) {
      // A v1 leaf: every v1 leaf carries an Intel-arc quote extension.
      info.v1Leaf = true;
      info.quote = parseV1Quote(ext.oid, ext.critical, ext.value);
    } else if (ext.oid.startsWith(OID_PRIVASYS_ARC_PREFIX)) {
      // Everything under the Privasys arc, including app-defined 5.4.* extensions.
      info.customOids.push({ oid: ext.oid, label: oidLabel(ext.oid), value: ext.value });
    }
  }
  return info;
}

/** The peer's management app id (OID 4.1) as lowercase hex, or "" when absent. */
export function appIdFromCert(info: CertInfo): string {
  const ext = info.customOids.find((e) => e.oid === OID_WORKLOAD_APP_ID);
  return ext ? ext.value.toString("hex") : "";
}

// ---------------------------------------------------------------------------
//  Fleet trust anchors
// ---------------------------------------------------------------------------

/**
 * Privasys production intermediate CA. Every enclave enrolled on the platform
 * serves a leaf issued by the intermediate of its environment, staged into the
 * enclave at approval time, so requiring the chain to reach one of these
 * anchors confines acceptance to enclaves Privasys provisioned. Hostname
 * verification is deliberately not part of the check: peers are dialled by
 * IP and the identity is the evidence plus the app identity in the certificate.
 */
export const PRIVASYS_INTERMEDIATE_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICXTCCAgSgAwIBAgIUGsQj8zdQMALqzHSJSJsxaKuTDuUwCgYIKoZIzj0EAwIw
dzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRv
bjEVMBMGA1UECgwMUHJpdmFzeXMgTHRkMRMwEQYDVQQLDApPcGVyYXRpb25zMRkw
FwYDVQQDDBBQcml2YXN5cyBSb290IENBMB4XDTI2MDMwMzA5NDcxN1oXDTMxMDMw
MjA5NDcxN1owfzELMAkGA1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNV
BAcMBkxvbmRvbjEVMBMGA1UECgwMUHJpdmFzeXMgTHRkMRMwEQYDVQQLDApPcGVy
YXRpb25zMSEwHwYDVQQDDBhQcml2YXN5cyBJbnRlcm1lZGlhdGUgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATs+4bGevjmiUiepVQbr22WKGqR42SK8Z4qk9gs
LxiJbUhJEO0tY1UlsoSBTrsBwb1Mq+ngoeSotFyLz1RTk4Gpo2YwZDASBgNVHRMB
Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUPFvb0C4gBRiY
Cg2vQpP8MqpG9CswHwYDVR0jBBgwFoAUs86NsnKlGHspTjvFY6gglLqc/4IwCgYI
KoZIzj0EAwIDRwAwRAIgHsQ73+XHYbDrXtY/tGPfwnWxGYa7OyFvKPzM52uFGh8C
IDO6Kd6Oajs9XXnRz7OKtlCNrJ7phZNIYFN6zPOqMxgB
-----END CERTIFICATE-----
`;

/** Privasys development intermediate CA (dev fleet). */
export const PRIVASYS_INTERMEDIATE_CA_DEV_PEM = `-----BEGIN CERTIFICATE-----
MIICdTCCAhqgAwIBAgIUJ/m03RGr3dAeXDmZ1C4izRK0SGAwCgYIKoZIzj0EAwIw
gYExCzAJBgNVBAYTAlVLMRcwFQYDVQQIDA5Vbml0ZWQgS2luZ2RvbTEPMA0GA1UE
BwwGTG9uZG9uMRUwEwYDVQQKDAxQcml2YXN5cyBMdGQxDDAKBgNVBAsMA0RldjEj
MCEGA1UEAwwaUHJpdmFzeXMgTHRkIFJvb3QgQ0EgKERFVikwHhcNMjYwMjE4MTUx
NzA3WhcNMzEwMjE3MTUxNzA3WjCBiTELMAkGA1UEBhMCVUsxFzAVBgNVBAgMDlVu
aXRlZCBLaW5nZG9tMQ8wDQYDVQQHDAZMb25kb24xFTATBgNVBAoMDFByaXZhc3lz
IEx0ZDEMMAoGA1UECwwDRGV2MSswKQYDVQQDDCJQcml2YXN5cyBMdGQgSW50ZXJt
ZWRpYXRlIENBIChERVYpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzCEGY7ay
05+Ve/GUgdXgoVTl1qgaaKkuTUDQMERuyG3gbvGHiYizSQf8zJE+MI27oEjcotsG
xgx/90RgIGKwuaNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AQYwHQYDVR0OBBYEFL/qhK4lcNDWws+Q9c/hpU2vMqu3MB8GA1UdIwQYMBaAFIPx
pxnvfgvw7iKj270kVlKeS2CBMAoGCCqGSM49BAMCA0kAMEYCIQDVhFpKwDBmgxrd
B2BlsOpVecxntcrFm4ltr8KQrtS5OwIhAMs7bI9w7HD2eYIaEpkxaxFyH4ENYbG4
D3EbYsQKbQUs
-----END CERTIFICATE-----
`;

/** Every certificate of a PEM bundle. */
export function parsePemCertificates(pem: string | Buffer): crypto.X509Certificate[] {
  const text = typeof pem === "string" ? pem : pem.toString("utf8");
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((b) => new crypto.X509Certificate(b));
}

/** The embedded Privasys production and development intermediate CAs. */
export function privasysTrustAnchors(): crypto.X509Certificate[] {
  return parsePemCertificates(PRIVASYS_INTERMEDIATE_CA_PEM + PRIVASYS_INTERMEDIATE_CA_DEV_PEM);
}

function certValidAt(c: crypto.X509Certificate, now: Date): boolean {
  return new Date(c.validFrom).getTime() <= now.getTime() && now.getTime() <= new Date(c.validTo).getTime();
}

/**
 * Require the presented chain (leaf first, DER) to reach one of the anchors
 * through valid CA certificates, without hostname verification. Anchors may
 * be intermediates: Node's own verifier insists on a self-signed root, so the
 * path is built here with signature, issuer and validity checks at each hop.
 */
export function verifyFleetChain(chain: Buffer[], anchors: crypto.X509Certificate[], now: Date = new Date()): void {
  verifyChainToAnchors(chain, anchors, now, "a trusted Privasys fleet anchor");
}

/** The path walk shared by the fleet and the public verifiers; `what` names the anchor set in the error. */
function verifyChainToAnchors(chain: Buffer[], anchors: crypto.X509Certificate[], now: Date, what: string): void {
  if (chain.length === 0) throw new Error("RA-TLS: server presented no certificate");
  if (anchors.length === 0) throw new Error("RA-TLS: no trust anchor configured");
  const certs = chain.map((d, i) => {
    try { return new crypto.X509Certificate(d); } catch (e) { throw new Error(`RA-TLS: parse peer certificate ${i}: ${(e as Error).message}`); }
  });
  const signedBy = (c: crypto.X509Certificate, issuer: crypto.X509Certificate): boolean => {
    try { return c.checkIssued(issuer) && c.verify(issuer.publicKey); } catch { return false; }
  };
  let cur = certs[0];
  const seen = new Set<crypto.X509Certificate>();
  for (let depth = 0; depth < 8; depth++) {
    if (!certValidAt(cur, now)) throw new Error(`RA-TLS: certificate "${cur.subject.split("\n").join(", ")}" is not valid at ${now.toISOString()}`);
    const anchor = anchors.find((a) => signedBy(cur, a));
    if (anchor) {
      if (!certValidAt(anchor, now)) throw new Error("RA-TLS: trust anchor is not valid at the current time");
      return;
    }
    seen.add(cur);
    const issuer = certs.find((c) => !seen.has(c) && c.ca && signedBy(cur, c));
    if (!issuer) break;
    cur = issuer;
  }
  throw new Error(`RA-TLS: certificate chain does not reach ${what}`);
}

// ---------------------------------------------------------------------------
//  Public PKI (trust mode Public, or Auto without evidence)
// ---------------------------------------------------------------------------

let bundledRoots: crypto.X509Certificate[] | undefined;

/** The platform's public PKI roots: the store bundled with Node (tls.rootCertificates), parsed once. */
export function publicTrustRoots(): crypto.X509Certificate[] {
  if (!bundledRoots) {
    const roots: crypto.X509Certificate[] = [];
    for (const pem of tls.rootCertificates) {
      try { roots.push(new crypto.X509Certificate(pem)); } catch { /* an entry Node itself would not use */ }
    }
    bundledRoots = roots;
  }
  return bundledRoots;
}

export interface PublicChainOptions {
  /** Validation time (default now). */
  now?: Date;
  /** Roots to anchor on (default publicTrustRoots()). */
  roots?: crypto.X509Certificate[];
}

/**
 * The ordinary HTTPS check: require the presented chain (leaf first, DER) to
 * reach a public PKI root and the leaf to be valid for `identity`, a DNS name
 * or an IP literal (SAN matching, as tls.checkServerIdentity does). Applied
 * only to a connection that requested no evidence; an attested connection
 * must chain to the fleet.
 */
export function verifyPublicChain(chain: Buffer[], identity: string, opts: PublicChainOptions = {}): void {
  verifyChainToAnchors(chain, opts.roots ?? publicTrustRoots(), opts.now ?? new Date(), "a public PKI root");
  const leaf = new crypto.X509Certificate(chain[0]);
  const matched = net.isIP(identity) ? leaf.checkIP(identity) : leaf.checkHost(identity);
  if (!matched) {
    throw new Error(`RA-TLS: certificate is not valid for "${identity}" (subject ${leaf.subject.split("\n").join(", ")}; altNames ${leaf.subjectAltName ?? "none"})`);
  }
}

// ---------------------------------------------------------------------------
//  Attested dependency set (OID 7.1)
// ---------------------------------------------------------------------------

/** A TDX measurement triple, lowercase hex. */
export interface DepTdxMeasurement { mrtd: string; rtmr1: string; rtmr2: string }

/** One allowed measurement of a dependency: exactly one of sgx (MRENCLAVE hex) or tdx. */
export interface DepMeasurement { sgx?: string; tdx?: DepTdxMeasurement }

/** One direct dependency a workload is pinned to. */
export interface DependencyEntry {
  /** Management app id of the dependency, lowercase hex (the OID 4.1 value). */
  appId: string;
  /** Any-of set of allowed measurements. */
  measurements: DepMeasurement[];
  /** OID values the peer must carry verbatim. */
  requiredOids: ExpectedOid[];
  /** Lowercase-hex commitment to the dependency's own subtree (foldIdentityHex); "" for a leaf. */
  foldedIdentity?: string;
}

/** A workload's set of direct attested dependencies. */
export interface DependencySet { entries: DependencyEntry[] }

function canonicalMeasurement(m: DepMeasurement): string {
  if (m.tdx) return `tdx:${m.tdx.mrtd.toLowerCase()}:${m.tdx.rtmr1.toLowerCase()}:${m.tdx.rtmr2.toLowerCase()}`;
  return `sgx:${(m.sgx ?? "").toLowerCase()}`;
}

function cmpOid(a: ExpectedOid, b: ExpectedOid): number {
  if (a.oid !== b.oid) return a.oid < b.oid ? -1 : 1;
  return Buffer.compare(a.expectedValue, b.expectedValue);
}

/** Length-prefixed byte stream shared by every SDK (u32 big-endian lengths). */
class CanonicalWriter {
  private parts: Buffer[] = [];
  u32(n: number): void { const b = Buffer.alloc(4); b.writeUInt32BE(n, 0); this.parts.push(b); }
  bytes(b: Buffer): void { this.u32(b.length); this.parts.push(b); }
  str(s: string): void { this.bytes(Buffer.from(s, "utf8")); }
  writeSet(s: DependencySet): void {
    const entries = [...s.entries].sort((a, b) => (a.appId < b.appId ? -1 : a.appId > b.appId ? 1 : 0));
    this.u32(entries.length);
    for (const e of entries) {
      this.str(e.appId);
      const ms = e.measurements.map(canonicalMeasurement).sort();
      this.u32(ms.length);
      for (const m of ms) this.str(m);
      const os = [...e.requiredOids].sort(cmpOid);
      this.u32(os.length);
      for (const o of os) { this.str(o.oid); this.bytes(o.expectedValue); }
      this.str((e.foldedIdentity ?? "").toLowerCase());
    }
  }
  out(): Buffer { return Buffer.concat(this.parts); }
}

/** Canonical encoding placed in the OID 7.1 extension; independent of declaration order. */
export function encodeDependencySet(s: DependencySet): Buffer {
  const w = new CanonicalWriter();
  w.writeSet(s);
  return w.out();
}

/**
 * A workload's folded identity, lowercase hex:
 * SHA-256( domain || measurements || requiredOids || encode(deps) ). It commits
 * to the whole dependency subtree while every hop verifies only direct edges.
 */
export function foldIdentityHex(ownMeasurements: string[], ownRequiredOids: ExpectedOid[], deps: DependencySet): string {
  const w = new CanonicalWriter();
  w.str("privasys-app-identity-v1");
  const ms = ownMeasurements.map((m) => m.toLowerCase()).sort();
  w.u32(ms.length);
  for (const m of ms) w.str(m);
  const os = [...ownRequiredOids].sort(cmpOid);
  w.u32(os.length);
  for (const o of os) { w.str(o.oid); w.bytes(o.expectedValue); }
  w.writeSet(deps);
  return sha256(w.out()).toString("hex");
}

// ---------------------------------------------------------------------------
//  Verification
// ---------------------------------------------------------------------------

function verifyImageProfile(exts: OidExtension[], policy: VerificationPolicy): void {
  const ext = exts.find((e) => e.oid === OID_IMAGE_PROFILE);
  if (!ext) return; // images predating the marker
  const profile = ext.value.toString("utf8").trim();
  if (profile !== "production" && !policy.allowDebugImages) {
    throw new Error(`server runs a "${profile}" image (OID ${OID_IMAGE_PROFILE}): debug/dev images are rejected unless VerificationPolicy.allowDebugImages is set`);
  }
}

function verifyExpectedOids(actual: OidExtension[], expected: ExpectedOid[]): void {
  for (const exp of expected) {
    const found = actual.find((e) => e.oid === exp.oid);
    if (!found) throw new Error(`expected OID ${exp.oid} (${oidLabel(exp.oid)}) not found in certificate`);
    if (!found.value.equals(exp.expectedValue)) {
      throw new Error(`${oidLabel(exp.oid)} (${exp.oid}) mismatch: got ${found.value.toString("hex")}, expected ${exp.expectedValue.toString("hex")}`);
    }
  }
}

function verifyCertificatePolicy(info: CertInfo, policy: VerificationPolicy): void {
  verifyImageProfile(info.customOids, policy);
  const expected = [...(policy.expectedOids ?? [])];
  if (policy.dependencySet) expected.push({ oid: OID_ATTESTED_DEPENDENCY_SET, expectedValue: encodeDependencySet(policy.dependencySet) });
  verifyExpectedOids(info.customOids, expected);
}

function expectRegister(name: string, actual: Buffer, expected?: Buffer): void {
  if (expected && !actual.equals(expected)) {
    throw new Error(`${name} mismatch: got ${actual.toString("hex")}, expected ${expected.toString("hex")}`);
  }
}

function verifyMeasurements(raw: Buffer, policy: VerificationPolicy): void {
  switch (policy.tee) {
    case TeeType.Sgx: {
      const o = sgxOffsets(detectSgxFormat(raw));
      if (raw.length < o.minSize) throw new Error(`SGX attestation blob too small: ${raw.length} < ${o.minSize}`);
      expectRegister("MRENCLAVE", raw.subarray(o.mreOff, o.mreEnd), policy.mrEnclave);
      expectRegister("MRSIGNER", raw.subarray(o.mrsOff, o.mrsEnd), policy.mrSigner);
      break;
    }
    case TeeType.Tdx:
      if (raw.length < TDX_QUOTE_MIN_SIZE) throw new Error(`TDX quote too small: ${raw.length} < ${TDX_QUOTE_MIN_SIZE}`);
      expectRegister("MRTD", raw.subarray(TDX_QUOTE_MRTD_OFF, TDX_QUOTE_MRTD_END), policy.mrTd);
      expectRegister("RTMR1", raw.subarray(TDX_QUOTE_RTMR1_OFF, TDX_QUOTE_RTMR1_END), policy.rtmr1);
      expectRegister("RTMR2", raw.subarray(TDX_QUOTE_RTMR2_OFF, TDX_QUOTE_RTMR2_END), policy.rtmr2);
      break;
    case TeeType.SevSnp:
      if (raw.length < SEV_SNP_REPORT_MIN_SIZE) throw new Error(`SEV-SNP report too small: ${raw.length} < ${SEV_SNP_REPORT_MIN_SIZE}`);
      expectRegister("MEASUREMENT", raw.subarray(SEV_SNP_MEASUREMENT_OFF, SEV_SNP_MEASUREMENT_END), policy.measurement);
      expectRegister("HOST_DATA", raw.subarray(SEV_SNP_HOST_DATA_OFF, SEV_SNP_HOST_DATA_END), policy.hostData);
      break;
    case TeeType.NvidiaGpu:
      break; // verified remotely
  }
}

/**
 * Verify a v2 leaf against the certificate part of a policy only: v2 shape
 * (no evidence in the certificate), image profile, expected OIDs and the
 * dependency set. It proves nothing about the TEE.
 */
export function verifyCertificateExtensions(der: Buffer, policy: VerificationPolicy): CertInfo {
  const info = inspectDerCertificate(der);
  if (info.v1Leaf) throw new Error("v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier");
  verifyCertificatePolicy(info, policy);
  return info;
}

/**
 * Verify the evidence obtained for the connection whose leaf is der, against
 * policy, in this order: v2 leaf shape, evidence family, measurement
 * registers, report_data (predicted from the leaf SPKI and the evidence, never
 * taken from the peer), certificate extensions, then the attestation server.
 */
export async function verifyEvidence(der: Buffer, evidence: Evidence | undefined, policy: VerificationPolicy): Promise<CertInfo> {
  const info = inspectDerCertificate(der);
  if (info.v1Leaf) throw new Error("v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier");
  if (!evidence) throw new Error("no attestation evidence for this connection (attestation mode none)");
  const ev = evidence;
  if (isMockQuote(ev.quote)) throw new Error("evidence is a MOCK quote");

  // 1. Evidence family against the policy.
  const tee = teeTypeOf(ev.tee);
  if (!tee) throw new Error(`unknown evidence family "${ev.tee}"`);
  if (policy.tee === TeeType.NvidiaGpu) throw new Error("TeeType.NvidiaGpu is not a primary evidence family in RA-TLS v2; verify a tdx-gpu connection with TeeType.Tdx");
  if (tee !== policy.tee) throw new Error(`expected ${policy.tee} evidence, got ${ev.tee}`);
  if (ev.tee === "tdx-gpu" && !(ev.gpuEvidence && ev.gpuEvidence.length > 0)) throw new Error("tdx-gpu evidence without gpu_evidence");

  // 2. Measurement registers.
  verifyMeasurements(ev.quote, policy);

  // 3. report_data, predicted from the leaf and the evidence.
  const expected = expectedReportData(info.spkiDer, ev);
  const actual = quoteReportData(ev.tee, ev.quote);
  if (!actual.equals(expected)) {
    throw new Error(`report_data mismatch (${ev.mode} mode):\n  got:      ${actual.toString("hex")}\n  expected: ${expected.toString("hex")}`);
  }

  // 4. Certificate extensions.
  verifyCertificatePolicy(info, policy);

  info.quote = quoteInfoOf(ev);
  info.gpuEvidence = ev.gpuEvidence;
  info.attestation = ev.mode;
  info.evidence = ev;

  // 5. Attestation server: quote signature, collateral, TCB; GPU verdict.
  if (policy.quoteVerification) {
    if (ev.gpuEvidence && ev.gpuEvidence.length > 0) {
      const r = await verifyTdxGpu(ev.quote, ev.gpuEvidence, policy.quoteVerification);
      info.quoteVerification = r.result;
      info.gpuAttestation = r.gpu;
    } else {
      info.quoteVerification = await verifyQuote(ev.quote, policy.quoteVerification);
    }
  }
  return info;
}

async function postVerification(body: Record<string, string>, config: QuoteVerificationConfig, what: string): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
  let res: Response;
  try {
    res = await fetch(config.endpoint, {
      method: "POST", headers, body: JSON.stringify(body),
      signal: AbortSignal.timeout((config.timeoutSecs ?? 10) * 1000),
    });
  } catch (e) {
    throw new Error(`${what} request failed: ${(e as Error).message}`);
  }
  const text = await res.text();
  if (res.status !== 200) throw new Error(`${what}: server returned HTTP ${res.status}: ${text}`);
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`failed to parse ${what} response: ${(e as Error).message} (body: ${text})`);
  }
}

function verdictOf(parsed: Record<string, unknown>, config: QuoteVerificationConfig, what: string): QuoteVerificationResult {
  const known = Object.values(QuoteVerificationStatus) as string[];
  const s = typeof parsed.status === "string" ? parsed.status : "";
  const result: QuoteVerificationResult = {
    status: (known.includes(s) ? s : QuoteVerificationStatus.Unrecognized) as QuoteVerificationStatus,
    tcbDate: typeof parsed.tcbDate === "string" ? parsed.tcbDate : undefined,
    advisoryIds: Array.isArray(parsed.advisoryIds) ? (parsed.advisoryIds as string[]) : [],
    tcbStatus: typeof parsed.tcbStatus === "string" ? parsed.tcbStatus : "",
  };
  if (result.status !== QuoteVerificationStatus.Ok && !(config.acceptedStatuses ?? []).includes(result.status)) {
    throw new Error(`${what} failed: status=${result.status}, advisories=${JSON.stringify(result.advisoryIds)}`);
  }
  if (config.enforceTcbStatus) {
    try {
      tcbStatusAcceptable(result.tcbStatus, config.acceptableTcbStatuses ?? []);
    } catch (e) {
      throw new Error(`${what} failed: ${(e as Error).message} (tcbDate=${result.tcbDate ?? ""}, advisories=${JSON.stringify(result.advisoryIds)})`);
    }
  }
  return result;
}

/** Verify a raw quote against the attestation server. */
async function verifyQuote(quote: Buffer, config: QuoteVerificationConfig): Promise<QuoteVerificationResult> {
  const parsed = await postVerification({ quote: quote.toString("base64") }, config, "quote verification");
  return verdictOf(parsed, config, "quote verification");
}

/** Verify a TDX quote plus NVIDIA GPU evidence (a "tdx-gpu" request). */
async function verifyTdxGpu(quote: Buffer, gpuEvidence: Buffer, config: QuoteVerificationConfig): Promise<{ result: QuoteVerificationResult; gpu: GpuAttestationResult }> {
  const parsed = await postVerification(
    { quote: quote.toString("base64"), type: "tdx-gpu", gpuQuote: gpuEvidence.toString("base64") },
    config, "tdx-gpu verification",
  );
  const result = verdictOf(parsed, config, "tdx-gpu verification");
  const gpu = parsed.gpuAttestation as GpuAttestationResult | undefined;
  if (!gpu) throw new Error("tdx-gpu verification: server returned no GPU attestation result");
  if (!gpu.verified) throw new Error(`GPU attestation failed: status=${gpu.status} error=${gpu.error}`);
  return { result, gpu };
}

// ---------------------------------------------------------------------------
//  HTTP/1.1 over the socket
// ---------------------------------------------------------------------------

/** A parsed HTTP/1.1 response. Header names are lowercase. */
export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

/** Decode a chunked body (RFC 9112 section 7.1); null while the terminal chunk is not buffered. */
function decodeChunked(rest: Buffer): { body: Buffer; consumed: number } | null {
  const parts: Buffer[] = [];
  let pos = 0;
  for (;;) {
    const lineEnd = rest.indexOf("\r\n", pos);
    if (lineEnd < 0) return null;
    const size = parseInt(rest.subarray(pos, lineEnd).toString("ascii").split(";")[0].trim(), 16);
    if (Number.isNaN(size)) throw new Error("invalid chunk size line");
    pos = lineEnd + 2;
    if (rest.length < pos + size + 2) return null;
    if (size === 0) return { body: Buffer.concat(parts), consumed: pos + 2 };
    parts.push(rest.subarray(pos, pos + size));
    pos += size + 2;
  }
}

/** Parse one response from the front of buf; null while incomplete. */
function parseHttpResponse(buf: Buffer): { value: HttpResponse; consumed: number } | null {
  const idx = buf.indexOf("\r\n\r\n");
  if (idx < 0) return null;
  const lines = buf.subarray(0, idx).toString("latin1").split("\r\n");
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0]);
  if (!m) throw new Error(`malformed HTTP status line: ${lines[0]}`);
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const c = line.indexOf(":");
    if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
  }
  const status = Number(m[1]);
  const bodyStart = idx + 4;
  // Transfer-Encoding matters as much as Content-Length: Go's http server
  // chunks anything over its 2 KiB buffer.
  if ((headers["transfer-encoding"] ?? "").toLowerCase().includes("chunked")) {
    const r = decodeChunked(buf.subarray(bodyStart));
    if (!r) return null;
    return { value: { status, headers, body: r.body }, consumed: bodyStart + r.consumed };
  }
  const len = headers["content-length"] !== undefined ? parseInt(headers["content-length"], 10) : 0;
  if (Number.isNaN(len) || len < 0) throw new Error("invalid Content-Length");
  if (buf.length - bodyStart < len) return null;
  return { value: { status, headers, body: Buffer.from(buf.subarray(bodyStart, bodyStart + len)) }, consumed: bodyStart + len };
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

export interface RaTlsClientOptions {
  /**
   * Fleet trust anchors for the server chain: a path to a PEM file, or PEM
   * contents as a Buffer. Default: the embedded Privasys intermediates
   * (production and development). Always used fleet-style (no hostname
   * check); never combined with trust Public.
   */
  caCert?: string | Buffer;
  /**
   * Which verifier the server chain must satisfy (default Auto): Fleet, Public
   * or Auto, see TrustMode. Public requires attestation None and no caCert.
   */
  trust?: TrustMode;
  /** Connect and read timeout in milliseconds (default 10000). */
  timeout?: number;
  /**
   * TLS SNI, so the enclave serves the per-workload certificate with the
   * workload OIDs. Also the Host header of the attest request.
   */
  serverName?: string;
  /** What to ask the server for after the handshake (default Challenge). */
  attestation?: AttestationMode;
  /**
   * Fixes the 32-byte challenge context (challenge mode). Verifiers that relay
   * a challenge chosen elsewhere (a browser talking to the management service)
   * set it so the evidence commits to that value; absent, a fresh random
   * context is drawn per attestation. Any other length is rejected.
   */
  context?: Buffer;
  /** Carrier of the attest messages (default Http). */
  framing?: Framing;
  /** Client certificate for mutual RA-TLS: PEM chain and PEM key (a v2 identity, no evidence). */
  clientCert?: { cert: string | Buffer; key: string | Buffer };
  /** Produces this client's evidence when the server requires it on a mutual leg. */
  clientEvidence?: ClientEvidenceSource;
}

/** A verified RA-TLS v2 connection. */
export class RaTlsClient {
  private readonly host: string;
  private readonly port: number;
  private readonly opts: RaTlsClientOptions;
  private readonly mode: AttestationMode;
  private readonly trust: TrustMode;
  private readonly framing: Framing;
  private readonly timeout: number;
  private sock?: tls.TLSSocket;
  private peerChain: Buffer[] = [];
  private presentedCertDer?: Buffer;
  private ev?: Evidence;
  private resolvedTrust?: ResolvedTrust;
  private lastPolicy?: VerificationPolicy;
  private pending: Buffer = Buffer.alloc(0);

  constructor(host: string, port = 443, opts: RaTlsClientOptions = {}) {
    this.host = host;
    this.port = port;
    this.opts = opts;
    this.mode = opts.attestation ?? AttestationMode.Challenge;
    this.framing = opts.framing ?? Framing.Http;
    this.timeout = opts.timeout ?? 10_000;
    if (opts.context !== undefined && opts.context.length !== CONTEXT_LEN) {
      throw new Error(`ratls: options.context must be ${CONTEXT_LEN} bytes`);
    }
    const trust = opts.trust ?? TrustMode.Auto;
    if (!(Object.values(TrustMode) as string[]).includes(trust)) throw new Error(`ratls: unknown trust mode "${String(trust)}"`);
    if (trust === TrustMode.Public) {
      // Never downgrade an attested connection to public PKI.
      if (this.mode !== AttestationMode.None) {
        throw new Error(`ratls: options.trust "public" cannot be combined with attestation mode "${this.mode}": an attested connection must chain to the fleet anchors`);
      }
      if (opts.caCert !== undefined) throw new Error('ratls: options.caCert is a fleet anchor and cannot be combined with options.trust "public"');
    }
    this.trust = trust;
  }

  /**
   * Handshake (TLS 1.3, chain check per the trust mode), then the evidence
   * exchange in the configured mode before any application data. A failure
   * closes the socket: a caller never gets a connected client whose evidence
   * is missing in a mode that asked for it.
   */
  async connect(): Promise<void> {
    // Public only: Node's own verifier (bundled roots, hostname) at the
    // handshake. Otherwise the chain is checked right after the handshake,
    // before anything is sent: the fleet walk accepts an intermediate anchor
    // and skips the hostname, which Node's verifier cannot do, and in Auto
    // without evidence the public walk is the second chance on the same
    // connection.
    const publicOnly = this.trust === TrustMode.Public;
    const fleetOnly = this.trust === TrustMode.Fleet || this.mode !== AttestationMode.None;
    let anchors: crypto.X509Certificate[] = [];
    if (!publicOnly) {
      anchors = this.opts.caCert === undefined
        ? privasysTrustAnchors()
        : parsePemCertificates(typeof this.opts.caCert === "string" ? fs.readFileSync(this.opts.caCert) : this.opts.caCert);
      if (anchors.length === 0) throw new Error("RA-TLS: no PEM certificate in the CA option");
    }

    const options: tls.ConnectionOptions = {
      host: this.host,
      port: this.port,
      minVersion: "TLSv1.3",
      ALPNProtocols: [RATLS_ALPN_PROTO, "http/1.1"],
      rejectUnauthorized: publicOnly,
      timeout: this.timeout,
    };
    if (!publicOnly) options.checkServerIdentity = () => undefined;
    if (this.opts.serverName) options.servername = this.opts.serverName;
    if (this.opts.clientCert) {
      options.cert = this.opts.clientCert.cert;
      options.key = this.opts.clientCert.key;
      const [leaf] = parsePemCertificates(this.opts.clientCert.cert);
      if (!leaf) throw new Error("RA-TLS: clientCert.cert holds no PEM certificate");
      this.presentedCertDer = Buffer.from(leaf.raw);
    }

    const sock = await new Promise<tls.TLSSocket>((resolve, reject) => {
      const onError = (e: Error) => reject(new Error(`TLS connect: ${e.message}`));
      const onTimeout = () => { s.destroy(); reject(new Error(`TLS connect: timeout after ${this.timeout} ms`)); };
      const s = tls.connect(options, () => { s.off("error", onError); s.off("timeout", onTimeout); resolve(s); });
      s.once("error", onError);
      s.once("timeout", onTimeout);
    });
    sock.setTimeout(this.timeout);
    sock.on("error", () => { /* surfaced by the pending read, if any */ });
    this.sock = sock;
    this.peerChain = peerChainOf(sock);

    try {
      this.resolvedTrust = publicOnly ? TrustMode.Public : this.verifyTrust(anchors, fleetOnly);
      await this.attest(this.mode);
    } catch (e) {
      this.close();
      throw e;
    }
  }

  /** The chain check after the handshake: fleet first, then public when Auto allows it. */
  private verifyTrust(anchors: crypto.X509Certificate[], fleetOnly: boolean): ResolvedTrust {
    try {
      verifyFleetChain(this.peerChain, anchors);
      return TrustMode.Fleet;
    } catch (fleetErr) {
      if (fleetOnly) throw fleetErr;
      const identity = this.opts.serverName ?? this.host;
      try {
        verifyPublicChain(this.peerChain, identity);
        return TrustMode.Public;
      } catch (publicErr) {
        throw new Error(`RA-TLS: certificate chain reaches neither a Privasys fleet anchor nor a public PKI root for "${identity}" (trust auto, no evidence requested): ${(fleetErr as Error).message}; ${(publicErr as Error).message}`);
      }
    }
  }

  /** Close the connection. */
  close(): void {
    this.sock?.destroy();
    this.sock = undefined;
  }

  /**
   * The underlying socket, for callers that take over the connection (an
   * HTTP agent, a WebSocket). Requests multiplexed over it inherit the
   * attestation verified at connect. Bytes already buffered by this client
   * are returned by `pendingBytes`.
   */
  get socket(): tls.TLSSocket {
    if (!this.sock) throw new Error("Not connected");
    return this.sock;
  }

  /** Bytes read from the socket but not yet consumed by a response. */
  get pendingBytes(): Buffer {
    return this.pending;
  }

  get tlsVersion(): string {
    return this.sock?.getProtocol() ?? "";
  }

  get cipher(): tls.CipherNameAndProtocol | undefined {
    return this.sock?.getCipher();
  }

  /** Negotiated ALPN protocol, or false when none. */
  get alpnProtocol(): string | false {
    return this.sock?.alpnProtocol ?? false;
  }

  /** DER certificates of the peer chain, leaf first. */
  peerCertificatesDer(): Buffer[] {
    return [...this.peerChain];
  }

  /** The evidence of this connection, undefined in mode None. Verified only after verifyCertificate succeeded. */
  get evidence(): Evidence | undefined {
    return this.ev;
  }

  /** The mode this connection was opened in. */
  get attestationMode(): AttestationMode {
    return this.mode;
  }

  /** The configured trust mode (Auto, Fleet or Public). */
  get trustMode(): TrustMode {
    return this.trust;
  }

  /**
   * The verifier the server chain satisfied: Fleet or Public. Undefined
   * before connect. Public only ever appears with attestation None.
   */
  get trustResolved(): ResolvedTrust | undefined {
    return this.resolvedTrust;
  }

  /**
   * The connection tag the server recorded and exposes to the workload as
   * X-Privasys-Attestation (ATTESTATION_HEADER): the mode once the exchange
   * completed, "none" until then.
   */
  get attestationTag(): AttestationMode {
    return this.ev ? this.ev.mode : AttestationMode.None;
  }

  /**
   * CertInfo of the leaf with the evidence of the connection attached
   * UNVERIFIED (quote, gpuEvidence, attestation, evidence) so measurements can
   * be displayed. verifyCertificate is what verifies it.
   */
  inspectCertificate(): CertInfo {
    if (this.peerChain.length === 0) throw new Error("Not connected");
    const info = inspectDerCertificate(this.peerChain[0]);
    if (this.ev) {
      info.quote = quoteInfoOf(this.ev);
      info.gpuEvidence = this.ev.gpuEvidence;
      info.attestation = this.ev.mode;
      info.evidence = this.ev;
    }
    return info;
  }

  /**
   * Verify the leaf and the evidence of this connection against a policy
   * (verifyEvidence). Call it before sending application data. In mode None
   * only the certificate extensions are verified.
   */
  async verifyCertificate(policy: VerificationPolicy): Promise<CertInfo> {
    if (this.peerChain.length === 0) throw new Error("no peer certificate");
    this.lastPolicy = policy;
    if (this.mode === AttestationMode.None) return verifyCertificateExtensions(this.peerChain[0], policy);
    return verifyEvidence(this.peerChain[0], this.ev, policy);
  }

  /**
   * Repeat the evidence exchange with a fresh context and, when a policy was
   * verified before, verify the new evidence against it. Long-lived
   * connections call it every few minutes and drop the connection on error.
   */
  async reattest(): Promise<void> {
    if (this.mode === AttestationMode.None) throw new Error("ratls: connection was opened with AttestationMode.None");
    if (this.framing === Framing.Raw) throw new Error("ratls: re-attestation is not possible on the raw binding; reconnect instead");
    await this.attest(this.mode);
    if (this.lastPolicy) await this.verifyCertificate(this.lastPolicy);
  }

  // -- evidence exchange ----------------------------------------------------

  private async attest(mode: AttestationMode): Promise<void> {
    if (mode === AttestationMode.None) { this.ev = undefined; return; }
    if (this.peerChain.length === 0) throw new Error("ratls: no peer certificate");
    const spki = spkiDerOf(this.peerChain[0]);
    let context: Buffer | undefined;
    let hctx: Buffer | undefined;
    if (mode === AttestationMode.Challenge) {
      context = this.opts.context ? Buffer.from(this.opts.context) : crypto.randomBytes(CONTEXT_LEN);
      hctx = exportHctx(this.socket, EXPORTER_LABEL_SERVER, context);
    }
    const { status, body } = await this.attestRoundTrip(buildAttestRequest(mode, spki, context));
    const p = parseAttestResponse(status, body, mode);
    const ev: Evidence = {
      mode, tee: p.tee, quote: p.quote, gpuEvidence: p.gpuEvidence,
      quoteTimeRaw: p.quoteTimeRaw, quoteTime: checkQuoteTime(p.quoteTimeRaw),
      context, hctx,
      clientEvidenceRequired: p.clientEvidenceRequired, clientContext: p.clientContext,
    };
    this.ev = ev;
    if (ev.clientEvidenceRequired) await this.present(ev);
  }

  /** Answer a server that requires client evidence (mutual leg). */
  private async present(ev: Evidence): Promise<void> {
    const source = this.opts.clientEvidence;
    if (!source) throw new Error("ratls: server requires client evidence and options.clientEvidence is not set");
    if (!this.presentedCertDer) throw new Error("ratls: server requires client evidence but no client certificate was presented");
    const clientContext = ev.clientContext as Buffer;
    const spki = spkiDerOf(this.presentedCertDer);
    const hctx = exportHctx(this.socket, EXPORTER_LABEL_CLIENT, clientContext);
    let ce: ClientEvidence;
    try {
      ce = await source({ spkiDer: spki, context: clientContext, hctx, reportData: clientReportData(spki, clientContext, hctx) });
    } catch (e) {
      throw new Error(`ratls: client evidence: ${(e as Error).message}`);
    }
    if (!ce || !ce.quote || ce.quote.length === 0) throw new Error("ratls: client evidence source returned no quote");
    const { status, body } = await this.attestRoundTrip(buildPresentRequest(clientContext, ce));
    const text = body.toString("utf8").trim();
    if (this.framing === Framing.Raw) {
      let ack: { v?: unknown; error?: unknown } = {};
      try { ack = JSON.parse(text) as typeof ack; } catch { /* rejected below */ }
      if (ack.v !== PROTOCOL_VERSION || (ack.error !== undefined && ack.error !== "")) throw new Error(`ratls: client evidence rejected: ${text}`);
      return;
    }
    if (status !== 204 && status !== 200) throw new Error(`ratls: client evidence rejected (${status}): ${text}`);
  }

  /**
   * Send one attest message and return the status (200 on the raw binding)
   * and body. The HTTP binding is HTTP/1.1: this client never offers h2.
   */
  private async attestRoundTrip(json: string): Promise<{ status: number; body: Buffer }> {
    const payload = Buffer.from(json, "utf8");
    if (this.framing === Framing.Raw) {
      this.socket.write(encodeFrame(payload));
      const body = await this.recvFrame();
      return { status: 200, body };
    }
    const resp = await this.httpDo("POST", ATTEST_PATH, { body: payload });
    return { status: resp.status, body: resp.body };
  }

  // -- socket reads ---------------------------------------------------------

  /** Read from the socket until parse yields a value; leftover bytes stay buffered. */
  private read<T>(parse: (buf: Buffer) => { value: T; consumed: number } | null): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const sock = this.sock;
      if (!sock) { reject(new Error("Not connected")); return; }
      const finish = (err?: Error, value?: T) => {
        sock.off("data", onData); sock.off("error", onError); sock.off("close", onClose); sock.off("timeout", onTimeout);
        sock.pause();
        if (err) reject(err); else resolve(value as T);
      };
      const attempt = (): boolean => {
        let r: { value: T; consumed: number } | null;
        try { r = parse(this.pending); } catch (e) { finish(e as Error); return true; }
        if (!r) return false;
        this.pending = Buffer.from(this.pending.subarray(r.consumed));
        finish(undefined, r.value);
        return true;
      };
      const onData = (chunk: Buffer) => { this.pending = Buffer.concat([this.pending, chunk]); attempt(); };
      const onError = (e: Error) => finish(e);
      const onClose = () => finish(new Error("connection closed before the response was complete"));
      const onTimeout = () => finish(new Error(`read timeout after ${this.timeout} ms`));
      if (attempt()) return;
      sock.on("data", onData); sock.on("error", onError); sock.on("close", onClose); sock.on("timeout", onTimeout);
      sock.resume();
    });
  }

  private recvFrame(): Promise<Buffer> {
    return this.read((buf) => {
      const r = decodeFrame(buf);
      return r ? { value: Buffer.from(r.payload), consumed: 4 + r.payload.length } : null;
    });
  }

  private recvHttpResponse(): Promise<HttpResponse> {
    return this.read(parseHttpResponse);
  }

  // -- HTTP/1.1 protocol ----------------------------------------------------

  /**
   * One HTTP/1.1 request over the connection. Content-Type defaults to
   * application/json when a body is present; `headers` may override it.
   */
  async httpDo(method: string, path: string, opts: { body?: Buffer; authToken?: string; headers?: Record<string, string>; connectionClose?: boolean } = {}): Promise<HttpResponse> {
    const sock = this.socket;
    const hdr: Record<string, string> = { Host: this.opts.serverName ?? this.host };
    if (opts.body && opts.body.length > 0) {
      hdr["Content-Length"] = String(opts.body.length);
      hdr["Content-Type"] = "application/json";
    }
    if (opts.authToken) hdr["Authorization"] = `Bearer ${opts.authToken}`;
    if (opts.connectionClose) hdr["Connection"] = "close";
    Object.assign(hdr, opts.headers ?? {});
    let head = `${method} ${path} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(hdr)) head += `${k}: ${v}\r\n`;
    head += "\r\n";
    sock.write(opts.body && opts.body.length > 0 ? Buffer.concat([Buffer.from(head, "latin1"), opts.body]) : head);
    return this.recvHttpResponse();
  }

  private async jsonCall(method: string, path: string, name: string, opts: { body?: Buffer; authToken?: string; connectionClose?: boolean } = {}): Promise<Record<string, unknown>> {
    const { status, body } = await this.httpDo(method, path, opts);
    if (status !== 200) throw new Error(`${name} failed (${status}): ${body.toString()}`);
    return body.length > 0 ? (JSON.parse(body.toString()) as Record<string, unknown>) : {};
  }

  /** GET /healthz, liveness probe (no auth). */
  healthz(): Promise<Record<string, unknown>> {
    return this.jsonCall("GET", "/healthz", "healthz");
  }

  /** GET /readyz, readiness probe (monitoring+ role). */
  readyz(authToken?: string): Promise<Record<string, unknown>> {
    return this.jsonCall("GET", "/readyz", "readyz", { authToken });
  }

  /** GET /status, enclave status (monitoring+ role). */
  status(authToken?: string): Promise<Record<string, unknown>> {
    return this.jsonCall("GET", "/status", "status", { authToken });
  }

  /** GET /metrics, Prometheus metrics (monitoring+ role). */
  async metrics(authToken?: string): Promise<string> {
    const { status, body } = await this.httpDo("GET", "/metrics", { authToken });
    if (status !== 200) throw new Error(`metrics failed (${status}): ${body.toString()}`);
    return body.toString();
  }

  /** POST /data, send a module command and return the response body. */
  async sendData(data: Buffer, authToken?: string): Promise<Buffer> {
    const { status, body } = await this.httpDo("POST", "/data", { body: data, authToken });
    if (status !== 200) throw new Error(`send_data failed (${status}): ${body.toString()}`);
    return body;
  }

  /** PUT /attestation-servers, set the attestation server list. */
  setAttestationServers(servers: string[], authToken?: string): Promise<Record<string, unknown>> {
    return this.jsonCall("PUT", "/attestation-servers", "set_attestation_servers", { body: Buffer.from(JSON.stringify({ servers })), authToken });
  }

  /** POST /shutdown, request a graceful shutdown. */
  async shutdown(authToken?: string): Promise<void> {
    await this.jsonCall("POST", "/shutdown", "shutdown", { authToken, connectionClose: true });
  }
}

/** DER chain the peer presented, leaf first. */
function peerChainOf(sock: tls.TLSSocket): Buffer[] {
  const out: Buffer[] = [];
  let cert: tls.DetailedPeerCertificate | undefined = sock.getPeerCertificate(true);
  const seen = new Set<string>();
  while (cert && cert.raw) {
    const fp = cert.fingerprint256 ?? cert.raw.toString("hex");
    if (seen.has(fp)) break;
    seen.add(fp);
    out.push(Buffer.from(cert.raw));
    cert = cert.issuerCertificate;
  }
  return out;
}

// ---------------------------------------------------------------------------
//  Pretty-print helper
// ---------------------------------------------------------------------------

/** Print a CertInfo to stdout. */
export function printCertInfo(info: CertInfo): void {
  console.log(`  Subject      : ${info.subject}`);
  console.log(`  Issuer       : ${info.issuer}`);
  console.log(`  Serial       : ${info.serialNumber}`);
  console.log(`  Valid From   : ${info.validFrom}`);
  console.log(`  Valid To     : ${info.validTo}`);
  console.log(`  Pubkey SHA256: ${info.pubkeySha256}`);
  console.log(`  Attestation  : ${info.attestation}${info.v1Leaf ? " (v1 leaf, rejected by a v2 verifier)" : ""}`);

  if (info.quote) {
    const q = info.quote;
    console.log();
    console.log(`  ** Evidence **`);
    console.log(`    Format    : ${q.oid}  (${q.label})`);
    console.log(`    Size      : ${q.raw.length} bytes`);
    if (q.isMock) console.log(`    ** MOCK QUOTE **`);
    if (q.version !== undefined) console.log(`    Version   : ${q.version}`);
    if (q.reportData) console.log(`    ReportData: ${q.reportData.toString("hex")}`);
    if (info.evidence?.quoteTimeRaw) console.log(`    QuoteTime : ${info.evidence.quoteTimeRaw}`);
    if (q.oid === OID_SGX_QUOTE) {
      const o = sgxOffsets(detectSgxFormat(q.raw));
      if (q.raw.length >= o.minSize) {
        console.log(`    MRENCLAVE : ${q.raw.subarray(o.mreOff, o.mreEnd).toString("hex")}`);
        console.log(`    MRSIGNER  : ${q.raw.subarray(o.mrsOff, o.mrsEnd).toString("hex")}`);
      }
    } else if (q.oid === OID_TDX_QUOTE && q.raw.length >= TDX_QUOTE_MIN_SIZE) {
      console.log(`    MRTD      : ${q.raw.subarray(TDX_QUOTE_MRTD_OFF, TDX_QUOTE_MRTD_END).toString("hex")}`);
      console.log(`    RTMR1     : ${q.raw.subarray(TDX_QUOTE_RTMR1_OFF, TDX_QUOTE_RTMR1_END).toString("hex")}`);
      console.log(`    RTMR2     : ${q.raw.subarray(TDX_QUOTE_RTMR2_OFF, TDX_QUOTE_RTMR2_END).toString("hex")}`);
    } else if (q.oid === OID_EVIDENCE_SEV_SNP_REPORT && q.raw.length >= SEV_SNP_REPORT_MIN_SIZE) {
      console.log(`    Measurement: ${q.raw.subarray(SEV_SNP_MEASUREMENT_OFF, SEV_SNP_MEASUREMENT_END).toString("hex")}`);
      console.log(`    HostData   : ${q.raw.subarray(SEV_SNP_HOST_DATA_OFF, SEV_SNP_HOST_DATA_END).toString("hex")}`);
    }
    if (info.gpuEvidence) console.log(`    GPU evidence: ${info.gpuEvidence.length} bytes`);
  } else {
    console.log();
    console.log(`  No evidence on this connection.`);
  }

  if (info.customOids.length > 0) {
    console.log();
    console.log(`  ** Privasys extensions **`);
    for (const ext of info.customOids) {
      console.log(`    ${ext.label} (${ext.oid}): ${ext.value.toString("hex")}`);
    }
  }

  if (info.quoteVerification) {
    const qv = info.quoteVerification;
    console.log();
    console.log(`  ** Quote Verification **`);
    console.log(`    Status    : ${qv.status}`);
    if (qv.tcbStatus) console.log(`    TCB Status: ${qv.tcbStatus}`);
    if (qv.tcbDate) console.log(`    TCB Date  : ${qv.tcbDate}`);
    if (qv.advisoryIds.length > 0) console.log(`    Advisories: ${qv.advisoryIds.join(", ")}`);
  }
  if (info.gpuAttestation) {
    const g = info.gpuAttestation;
    console.log();
    console.log(`  ** GPU Attestation **`);
    console.log(`    Verified  : ${g.verified} (${g.status})`);
    if (g.gpuUuid) console.log(`    GPU       : ${g.gpuUuid} driver ${g.driver} vbios ${g.vbios} cc ${g.ccEnvironment}`);
    console.log(`    RIM match : ${g.measurementsVerified}`);
  }
}
