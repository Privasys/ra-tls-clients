// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Package ratls provides an RA-TLS client connector for enclave-os-mini.
//
// Features:
//   - TLS connection with optional CA certificate verification
//   - RA-TLS certificate inspection (SGX / TDX quote extraction)
//   - HTTP/1.1 protocol for communicating with the enclave
//   - Typed request/response helpers matching the Rust protocol
//
// Usage:
//
//	client, _ := ratls.Connect("141.94.219.130", 443, &ratls.Options{CACertPath: "ca.pem"})
//	defer client.Close()
//	info := client.InspectCertificate()
//	resp, _ := client.SendData([]byte(`{"command":"hello"}`), "auth-token")
package ratls

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
//  Quote byte-offset constants
// ---------------------------------------------------------------------------

// SGX DCAP Quote v3: QuoteHeader(48) + ReportBody(384).
const (
	SGXQuoteMinSize       = 432
	SGXQuoteMRENCLAVEOff  = 112
	SGXQuoteMRENCLAVEEnd  = 144
	SGXQuoteMRSIGNEROff   = 176
	SGXQuoteMRSIGNEREnd   = 208
	SGXQuoteReportDataOff = 368
	SGXQuoteReportDataEnd = 432
)

// SGX raw Report (sgx_create_report): no QuoteHeader, just ReportBody(432).
const (
	SGXReportSize          = 432
	SGXReportMRENCLAVEOff  = 64
	SGXReportMRENCLAVEEnd  = 96
	SGXReportMRSIGNEROff   = 128
	SGXReportMRSIGNEREnd   = 160
	SGXReportReportDataOff = 320
	SGXReportReportDataEnd = 384
)

// SgxQuoteFormat identifies the format of an SGX attestation blob.
type SgxQuoteFormat int

const (
	// SgxFormatDcapV3 is a full DCAP Quote v3 (48-byte header + report body + sig).
	SgxFormatDcapV3 SgxQuoteFormat = iota
	// SgxFormatRawReport is a raw SGX Report from sgx_create_report (no header).
	SgxFormatRawReport
)

// DetectSgxFormat detects whether an SGX attestation blob is a DCAP Quote v3
// or a raw Report. DCAP Quote v3 starts with a 2-byte LE version field
// equal to 3; raw Reports start with CPUSVN[16] which never decodes to version 3.
func DetectSgxFormat(raw []byte) SgxQuoteFormat {
	if len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		if v == 3 {
			return SgxFormatDcapV3
		}
	}
	return SgxFormatRawReport
}

// sgxOffsets returns the MRENCLAVE, MRSIGNER, ReportData ranges and min size
// for the given SGX format.
func sgxOffsets(format SgxQuoteFormat) (mreOff, mreEnd, mrsOff, mrsEnd, rdOff, rdEnd, minSz int) {
	switch format {
	case SgxFormatDcapV3:
		return SGXQuoteMRENCLAVEOff, SGXQuoteMRENCLAVEEnd,
			SGXQuoteMRSIGNEROff, SGXQuoteMRSIGNEREnd,
			SGXQuoteReportDataOff, SGXQuoteReportDataEnd,
			SGXQuoteMinSize
	default: // RawReport
		return SGXReportMRENCLAVEOff, SGXReportMRENCLAVEEnd,
			SGXReportMRSIGNEROff, SGXReportMRSIGNEREnd,
			SGXReportReportDataOff, SGXReportReportDataEnd,
			SGXReportSize
	}
}

// TDX DCAP Quote v4: Quote4Header(48) + Report2Body(584).
//
// Report body register layout (offsets into the raw quote): MRTD(48)@184,
// then MRCONFIGID/MROWNER/MROWNERCONFIG(48 each), then RTMR0..3(48 each), then
// REPORTDATA(64)@568. RTMR1 and RTMR2 (the image-derived kernel/initrd+cmdline
// registers) sit at 424 and 472; MRTD alone (the TD firmware) does not identify
// the guest build, so a full identity is MRTD + RTMR1 + RTMR2.
const (
	TDXQuoteMinSize       = 632
	TDXQuoteMRTDOff       = 184
	TDXQuoteMRTDEnd       = 232
	TDXQuoteRTMR1Off      = 424
	TDXQuoteRTMR1End      = 472
	TDXQuoteRTMR2Off      = 472
	TDXQuoteRTMR2End      = 520
	TDXQuoteReportDataOff = 568
	TDXQuoteReportDataEnd = 632
)

// AMD SEV-SNP Attestation Report (raw report from /dev/sev-guest).
// Report layout: Version(4) GuestSVN(4) Policy(8) ... ReportData(64) Measurement(48) HostData(32) ...
// Total report size: 0x4A0 = 1184 bytes.
const (
	SEVSNPReportMinSize  = 0x4A0 // 1184 bytes
	SEVSNPReportDataOff  = 0x050 // 80
	SEVSNPReportDataEnd  = 0x090 // 144
	SEVSNPMeasurementOff = 0x090 // 144
	SEVSNPMeasurementEnd = 0x0C0 // 192
	SEVSNPHostDataOff    = 0x0C0 // 192
	SEVSNPHostDataEnd    = 0x0E0 // 224
)

// ---------------------------------------------------------------------------
//  RA-TLS verification types
// ---------------------------------------------------------------------------

// TeeType is the target TEE type for RA-TLS verification.
type TeeType int

const (
	// TeeTypeSGX targets Intel SGX enclaves.
	TeeTypeSGX TeeType = iota
	// TeeTypeTDX targets Intel TDX VMs.
	TeeTypeTDX
	// TeeTypeSEVSNP targets AMD SEV-SNP confidential VMs.
	TeeTypeSEVSNP
	// TeeTypeNVIDIAGPU targets NVIDIA GPU attestation.
	TeeTypeNVIDIAGPU
)

// ExpectedOid is an expected X.509 extension OID and its value.
type ExpectedOid struct {
	OID           string
	ExpectedValue []byte
}

// ---------------------------------------------------------------------------
//  Quote verification types
// ---------------------------------------------------------------------------

// QuoteVerificationStatus represents a TCB status from the verification service.
type QuoteVerificationStatus string

const (
	QvsOk                                QuoteVerificationStatus = "OK"
	QvsTcbOutOfDate                      QuoteVerificationStatus = "TCB_OUT_OF_DATE"
	QvsConfigurationNeeded               QuoteVerificationStatus = "CONFIGURATION_NEEDED"
	QvsSwHardeningNeeded                 QuoteVerificationStatus = "SW_HARDENING_NEEDED"
	QvsConfigurationAndSwHardeningNeeded QuoteVerificationStatus = "CONFIGURATION_AND_SW_HARDENING_NEEDED"
	QvsTcbRevoked                        QuoteVerificationStatus = "TCB_REVOKED"
	QvsTcbExpired                        QuoteVerificationStatus = "TCB_EXPIRED"
)

// TCBStatus is Intel's platform TCB status as reported by the attestation server's
// `tcbStatus` field. These are Intel's CamelCase values, distinct from the
// QuoteVerificationStatus verdict enum above.
type TCBStatus string

const (
	TCBUpToDate                          TCBStatus = "UpToDate"
	TCBSWHardeningNeeded                 TCBStatus = "SWHardeningNeeded"
	TCBConfigurationNeeded               TCBStatus = "ConfigurationNeeded"
	TCBConfigurationAndSWHardeningNeeded TCBStatus = "ConfigurationAndSWHardeningNeeded"
	TCBOutOfDate                         TCBStatus = "OutOfDate"
	TCBOutOfDateConfigurationNeeded      TCBStatus = "OutOfDateConfigurationNeeded"
	TCBRevoked                           TCBStatus = "Revoked"
)

// secureTCBFloor is the set of TCB statuses accepted without any policy relaxation:
// UpToDate and SWHardeningNeeded (the residual issues of the latter are mitigated by
// the enclave's software mitigations). Mirrors the attestation server's floor —
// defence in depth: the client enforces it even if the server does not.
var secureTCBFloor = map[TCBStatus]bool{
	TCBUpToDate:          true,
	TCBSWHardeningNeeded: true,
}

// tcbStatusAcceptable reports whether a reported TCB status passes acceptance given the
// caller's relaxation set (config.AcceptableTCBStatuses):
//
//   - Revoked is NEVER acceptable (non-overridable).
//   - Statuses in the secure floor are always accepted.
//   - Any other status is accepted only if listed in `acceptable`.
//   - An empty status (the server did not report one — e.g. SGX_TCB_MODE=off, or a TEE
//     without SGX collateral) is accepted, for backward compatibility with servers that
//     do not emit tcbStatus.
func tcbStatusAcceptable(status TCBStatus, acceptable []TCBStatus) error {
	if status == "" {
		return nil
	}
	if status == TCBRevoked {
		return fmt.Errorf("TCB status Revoked is never acceptable")
	}
	if secureTCBFloor[status] {
		return nil
	}
	for _, s := range acceptable {
		if s == status {
			return nil
		}
	}
	return fmt.Errorf("TCB status %q not accepted: not in the secure floor and not in the configured acceptable set", status)
}

// QuoteVerificationConfig configures remote quote verification via an HTTP service.
//
// Point Endpoint at a quote verification service (e.g. an attestation server).
type QuoteVerificationConfig struct {
	// Endpoint is the URL of the quote verification service (POST).
	Endpoint string
	// Token is an optional Bearer token for the verification service.
	Token string
	// AcceptedStatuses lists TCB statuses accepted in addition to "OK".
	AcceptedStatuses []QuoteVerificationStatus
	// EnforceTCBStatus turns on client-side enforcement of the server's reported Intel
	// `tcbStatus` against the secure floor + AcceptableTCBStatuses. It is OPT-IN
	// (default false) so that rebuilding a client against a server that newly reports
	// tcbStatus does not silently start rejecting platforms that were previously
	// accepted (e.g. a fleet running at ConfigurationAndSWHardeningNeeded). The reported
	// status is always parsed into the result regardless of this flag; only rejection is
	// gated. Callers enable this and supply AcceptableTCBStatuses from the measurement's
	// policy (e.g. the vault constellation's acceptable set).
	EnforceTCBStatus bool
	// AcceptableTCBStatuses relaxes the secure TCB floor (UpToDate, SWHardeningNeeded)
	// to also accept these Intel TCB statuses (e.g. ConfigurationAndSWHardeningNeeded on
	// a platform whose BIOS/config cannot be changed). Revoked is never accepted, even
	// if listed. Only consulted when EnforceTCBStatus is true.
	AcceptableTCBStatuses []TCBStatus
	// TimeoutSecs is the HTTP request timeout in seconds (default: 10).
	TimeoutSecs int
}

// QuoteVerificationResult is the result of remote quote verification.
type QuoteVerificationResult struct {
	// Status is the TCB status returned by the verification service.
	Status QuoteVerificationStatus
	// TcbDate is the TCB date from the collateral (if provided).
	TcbDate string
	// AdvisoryIDs lists Intel Security Advisory IDs (if any).
	AdvisoryIDs []string
	// TCBStatus is Intel's platform TCB status (the server's `tcbStatus` field), when
	// reported. Empty when the server did not derive it.
	TCBStatus TCBStatus
}

// GPUAttestationResult is the attestation server's NVIDIA GPU verdict, returned
// alongside the CPU quote verification for a tdx-gpu certificate. Mirrors the
// attestation-server GPUAttestationResult.
type GPUAttestationResult struct {
	Verified      bool   `json:"verified"`
	Status        string `json:"status"`
	Message       string `json:"message"`
	Error         string `json:"error"`
	GPUUUID       string `json:"gpuUuid"`
	Driver        string `json:"driver"`
	VBIOS         string `json:"vbios"`
	CCEnvironment string `json:"ccEnvironment"`
	// MeasurementsVerified is true only when firmware/VBIOS measurements were
	// matched against a signed NVIDIA RIM (see the attestation server).
	MeasurementsVerified bool `json:"measurementsVerified"`
}

// VerificationPolicy configures RA-TLS certificate verification.
type VerificationPolicy struct {
	// TEE is the expected TEE type.
	TEE TeeType
	// MRENCLAVE is the expected SGX MRENCLAVE (32 bytes). Nil to skip.
	MRENCLAVE []byte
	// MRSIGNER is the expected SGX MRSIGNER (32 bytes). Nil to skip.
	MRSIGNER []byte
	// MRTD is the expected TDX MRTD (48 bytes). Nil to skip.
	MRTD []byte
	// RTMR1 and RTMR2 are the expected TDX runtime measurement registers
	// (48 bytes each). Nil to skip. A full TDX identity pins MRTD AND both of
	// these image-derived registers, since MRTD (the TD firmware) alone does
	// not identify the guest build — the same rule the vault's TEE policy
	// applies.
	RTMR1 []byte
	RTMR2 []byte
	// Measurement is the expected SEV-SNP MEASUREMENT (48 bytes). Nil to skip.
	Measurement []byte
	// HostData is the expected SEV-SNP HOST_DATA (32 bytes). Nil to skip.
	HostData []byte
	// ExpectedOids are custom OID values to verify.
	ExpectedOids []ExpectedOid
	// QuoteVerification is an optional remote quote verification configuration.
	QuoteVerification *QuoteVerificationConfig
	// AllowDebugImages permits certificates whose Image Profile extension
	// (OID 1.3.6.1.4.1.65230.1.2) reports a non-production image (e.g.
	// "dev": built with SSH and debug tooling). Default false: any
	// non-"production" profile is rejected. Certificates without the
	// extension (images predating the marker) are accepted either way.
	AllowDebugImages bool
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

// QuoteInfo contains parsed attestation quote data from the certificate.
type QuoteInfo struct {
	OID        string
	Label      string
	Critical   bool
	Raw        []byte
	IsMock     bool
	Version    *uint16
	ReportData []byte
}

// OidExtension is a custom X.509 extension (e.g. Privasys configuration OID).
type OidExtension struct {
	OID   string
	Label string
	Value []byte
}

// CertInfo contains a summary of the server's RA-TLS certificate.
type CertInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	SigAlgo      string
	// PubKeySHA256 is SHA-256 of the full SPKI DER (SubjectPublicKeyInfo,
	// 91 bytes for P-256). This is the standard X.509 public key fingerprint
	// and is also the hash used in the ReportData computation:
	//   ReportData = SHA-512( SHA-256(SPKI_DER) || binding )
	PubKeySHA256 string
	Extensions   []string
	// V1Leaf reports a v1 certificate: attestation evidence carried as a
	// certificate extension. A v2 verifier fails closed on it.
	V1Leaf bool
	// Quote is the evidence body verified for the connection (RA-TLS v2:
	// from the attest response, never from the certificate). Nil until
	// VerifyCertificate ran with evidence, and on a V1Leaf where it is the
	// unverified extension for display only.
	Quote *QuoteInfo
	// GPUEvidence is the NVIDIA GPU CC evidence bundle of the attest
	// response, when present. Its SHA-256 is folded into report_data.
	GPUEvidence []byte
	// Attestation is the mode the evidence was obtained in; AttestationNone
	// when the connection carries no evidence.
	Attestation AttestationMode
	// Evidence is the full evidence record (mode, tee, quote, context, exporter
	// value, quote_time) after VerifyCertificate succeeded.
	Evidence *Evidence
	// CustomOids holds Privasys configuration OIDs found in the certificate.
	CustomOids []OidExtension
	// QuoteVerification holds the remote quote verification result (populated during Verify).
	QuoteVerification *QuoteVerificationResult
	// GPUAttestation holds the attestation server's NVIDIA GPU verdict, populated
	// during Verify when the certificate carries GPU evidence and remote
	// verification is configured.
	GPUAttestation *GPUAttestationResult
}

// InspectCertificate inspects an X.509 certificate for RA-TLS extensions.
func InspectCertificate(cert *x509.Certificate) CertInfo {
	pubDER, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	h := sha256.Sum256(pubDER)

	info := CertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SigAlgo:      cert.SignatureAlgorithm.String(),
		PubKeySHA256: hex.EncodeToString(h[:]),
	}

	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		info.Extensions = append(info.Extensions, oidStr)

		switch {
		case oidStr == OidSGXQuote || oidStr == OidTDXQuote:
			// A v1 leaf: evidence inside the certificate (every v1 leaf carries
			// an Intel-arc quote extension). Parsed for display, never verified.
			info.V1Leaf = true
			info.Quote = parseQuote(oidStr, ext.Critical, ext.Value)
		case strings.HasPrefix(oidStr, OidPrivasysArcPrefix):
			// Everything under the Privasys arc, including the open-ended
			// app-defined 5.4.* extensions.
			info.CustomOids = append(info.CustomOids, OidExtension{
				OID:   oidStr,
				Label: OidLabel(oidStr),
				Value: ext.Value,
			})
		}
	}
	info.Attestation = AttestationNone
	return info
}

// spkiDEROf returns the DER SubjectPublicKeyInfo of a certificate.
func spkiDEROf(cert *x509.Certificate) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return der, nil
}

func parseLeaf(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func parseQuote(oid string, critical bool, raw []byte) *QuoteInfo {
	q := &QuoteInfo{
		OID:      oid,
		Label:    OidLabel(oid),
		Critical: critical,
		Raw:      raw,
	}

	if len(raw) >= 11 && string(raw[:11]) == "MOCK_QUOTE:" {
		q.IsMock = true
		end := len(raw)
		if end > 75 {
			end = 75
		}
		q.ReportData = raw[11:end]
	} else if oid == OidSGXQuote && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
		format := DetectSgxFormat(raw)
		_, _, _, _, rdOff, rdEnd, minSz := sgxOffsets(format)
		if len(raw) >= minSz {
			q.ReportData = raw[rdOff:rdEnd]
		}
	} else if oid == OidTDXQuote && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
		if len(raw) >= TDXQuoteMinSize {
			q.ReportData = raw[TDXQuoteReportDataOff:TDXQuoteReportDataEnd]
		}
	}

	return q
}

// quoteInfoOf builds the QuoteInfo of an attest-response quote. OID names the
// quote format (the Intel arc OIDs, as in v1 certificates) so callers keep
// switching on it; the evidence never sits in the certificate.
func quoteInfoOf(ev *Evidence) *QuoteInfo {
	oid := OidSGXQuote
	switch ev.TEE {
	case "tdx", "tdx-gpu":
		oid = OidTDXQuote
	case "sev-snp":
		oid = OidEvidenceSEVSNPReport
	}
	q := &QuoteInfo{OID: oid, Label: OidLabel(oid), Raw: ev.Quote}
	if len(ev.Quote) >= 11 && string(ev.Quote[:11]) == "MOCK_QUOTE:" {
		q.IsMock = true
	}
	if len(ev.Quote) >= 2 {
		v := binary.LittleEndian.Uint16(ev.Quote[:2])
		q.Version = &v
	}
	if rd, err := QuoteReportData(ev.TEE, ev.Quote); err == nil {
		q.ReportData = rd
	}
	return q
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

// VerifyCertificateExtensions verifies a v2 leaf against the certificate part
// of a policy only: v2 shape (no evidence in the certificate), image profile
// and expected OIDs. It proves nothing about the TEE; callers that need
// evidence use VerifyEvidence or (*Client).VerifyCertificate.
func VerifyCertificateExtensions(cert *x509.Certificate, policy *VerificationPolicy) (CertInfo, error) {
	info := InspectCertificate(cert)
	if info.V1Leaf {
		return info, fmt.Errorf("v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier")
	}
	if err := verifyImageProfile(info.CustomOids, policy); err != nil {
		return info, err
	}
	if err := verifyExpectedOids(info.CustomOids, policy.ExpectedOids); err != nil {
		return info, err
	}
	return info, nil
}

// VerifyEvidence verifies the evidence ev obtained for the connection whose
// leaf is cert, against policy, in this order: v2 leaf shape, evidence family
// against policy.TEE, measurement registers, report_data (predicted from the
// leaf SPKI and ev, never taken from the peer), image profile, expected OIDs,
// then the attestation server (quote signature and TCB, GPU verdict). Returns
// the CertInfo with Quote, Evidence and Attestation filled on success.
func VerifyEvidence(cert *x509.Certificate, ev *Evidence, policy *VerificationPolicy) (CertInfo, error) {
	info := InspectCertificate(cert)
	if info.V1Leaf {
		return info, fmt.Errorf("v1 RA-TLS certificate (evidence inside the certificate) is not accepted by a v2 verifier")
	}
	if ev == nil {
		return info, fmt.Errorf("no attestation evidence for this connection (attestation mode none)")
	}
	if len(ev.Quote) >= 11 && string(ev.Quote[:11]) == "MOCK_QUOTE:" {
		return info, fmt.Errorf("evidence is a MOCK quote")
	}

	// 1. Evidence family against the policy.
	tee, ok := teeTypeOf(ev.TEE)
	if !ok {
		return info, fmt.Errorf("unknown evidence family %q", ev.TEE)
	}
	if policy.TEE == TeeTypeNVIDIAGPU {
		return info, fmt.Errorf("TeeTypeNVIDIAGPU is not a primary evidence family in RA-TLS v2; verify a tdx-gpu connection with TeeTypeTDX")
	}
	if tee != policy.TEE {
		return info, fmt.Errorf("expected %s evidence, got %s", policy.TEE, ev.TEE)
	}
	if ev.TEE == "tdx-gpu" && len(ev.GPUEvidence) == 0 {
		return info, fmt.Errorf("tdx-gpu evidence without gpu_evidence")
	}

	// 2. Measurement registers.
	if err := verifyMeasurements(ev.Quote, policy); err != nil {
		return info, err
	}

	// 3. report_data: predicted from the leaf and the evidence.
	spki, err := spkiDEROf(cert)
	if err != nil {
		return info, err
	}
	expected, err := ExpectedReportData(spki, ev)
	if err != nil {
		return info, err
	}
	actual, err := QuoteReportData(ev.TEE, ev.Quote)
	if err != nil {
		return info, err
	}
	if !bytesEqual(actual, expected) {
		return info, fmt.Errorf("report_data mismatch (%s mode):\n  got:      %s\n  expected: %s",
			ev.Mode, hex.EncodeToString(actual), hex.EncodeToString(expected))
	}

	// 4. Certificate extensions.
	if err := verifyImageProfile(info.CustomOids, policy); err != nil {
		return info, err
	}
	if err := verifyExpectedOids(info.CustomOids, policy.ExpectedOids); err != nil {
		return info, err
	}

	info.Quote = quoteInfoOf(ev)
	info.GPUEvidence = ev.GPUEvidence
	info.Attestation = ev.Mode
	info.Evidence = ev

	// 5. Attestation server: quote signature, collateral, TCB; GPU verdict.
	if policy.QuoteVerification != nil {
		if len(ev.GPUEvidence) > 0 {
			result, gpuResult, err := verifyTDXGPU(ev.Quote, ev.GPUEvidence, policy.QuoteVerification)
			if err != nil {
				return info, err
			}
			info.QuoteVerification = result
			info.GPUAttestation = gpuResult
		} else {
			result, err := verifyQuote(ev.Quote, policy.QuoteVerification)
			if err != nil {
				return info, err
			}
			info.QuoteVerification = result
		}
	}

	return info, nil
}

// verifyImageProfile rejects certificates from non-production VM images
// unless the policy explicitly allows them. The Image Profile extension
// (OID 1.3.6.1.4.1.65230.1.2) is baked into the measured rootfs:
// "production" images carry no SSH daemon or debug tooling, while "dev"
// images do and must never serve production workloads. Fail-closed: any
// value other than "production" counts as a debug image. Certificates
// without the extension (images predating the marker) are accepted.
func verifyImageProfile(oidExts []OidExtension, policy *VerificationPolicy) error {
	for _, ext := range oidExts {
		if ext.OID != OidImageProfile {
			continue
		}
		profile := strings.TrimSpace(string(ext.Value))
		if profile != "production" && !policy.AllowDebugImages {
			return fmt.Errorf("server runs a %q image (OID %s): debug/dev images are rejected unless VerificationPolicy.AllowDebugImages is set", profile, OidImageProfile)
		}
		return nil
	}
	return nil
}

func verifyMeasurements(raw []byte, policy *VerificationPolicy) error {
	switch policy.TEE {
	case TeeTypeSGX:
		format := DetectSgxFormat(raw)
		mreOff, mreEnd, mrsOff, mrsEnd, _, _, minSz := sgxOffsets(format)
		if len(raw) < minSz {
			return fmt.Errorf("SGX attestation blob too small: %d < %d", len(raw), minSz)
		}
		if policy.MRENCLAVE != nil {
			actual := raw[mreOff:mreEnd]
			if !bytesEqual(actual, policy.MRENCLAVE) {
				return fmt.Errorf("MRENCLAVE mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.MRENCLAVE))
			}
		}
		if policy.MRSIGNER != nil {
			actual := raw[mrsOff:mrsEnd]
			if !bytesEqual(actual, policy.MRSIGNER) {
				return fmt.Errorf("MRSIGNER mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.MRSIGNER))
			}
		}
	case TeeTypeTDX:
		if len(raw) < TDXQuoteMinSize {
			return fmt.Errorf("TDX quote too small: %d < %d", len(raw), TDXQuoteMinSize)
		}
		if policy.MRTD != nil {
			actual := raw[TDXQuoteMRTDOff:TDXQuoteMRTDEnd]
			if !bytesEqual(actual, policy.MRTD) {
				return fmt.Errorf("MRTD mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.MRTD))
			}
		}
		// RTMR1/RTMR2 pin the guest build (kernel/initrd + cmdline). Verified
		// alongside MRTD so the same firmware running a different enclave-os-virtual
		// image is rejected — matching the vault's TEE-policy rule.
		if policy.RTMR1 != nil {
			actual := raw[TDXQuoteRTMR1Off:TDXQuoteRTMR1End]
			if !bytesEqual(actual, policy.RTMR1) {
				return fmt.Errorf("RTMR1 mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.RTMR1))
			}
		}
		if policy.RTMR2 != nil {
			actual := raw[TDXQuoteRTMR2Off:TDXQuoteRTMR2End]
			if !bytesEqual(actual, policy.RTMR2) {
				return fmt.Errorf("RTMR2 mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.RTMR2))
			}
		}
	case TeeTypeSEVSNP:
		if len(raw) < SEVSNPReportMinSize {
			return fmt.Errorf("SEV-SNP report too small: %d < %d", len(raw), SEVSNPReportMinSize)
		}
		if policy.Measurement != nil {
			actual := raw[SEVSNPMeasurementOff:SEVSNPMeasurementEnd]
			if !bytesEqual(actual, policy.Measurement) {
				return fmt.Errorf("MEASUREMENT mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.Measurement))
			}
		}
		if policy.HostData != nil {
			actual := raw[SEVSNPHostDataOff:SEVSNPHostDataEnd]
			if !bytesEqual(actual, policy.HostData) {
				return fmt.Errorf("HOST_DATA mismatch: got %s, expected %s",
					hex.EncodeToString(actual), hex.EncodeToString(policy.HostData))
			}
		}
	case TeeTypeNVIDIAGPU:
		// NVIDIA GPU evidence is verified remotely; no local measurement check.
	}
	return nil
}

func verifyExpectedOids(actual []OidExtension, expected []ExpectedOid) error {
	for _, exp := range expected {
		var found *OidExtension
		for i := range actual {
			if actual[i].OID == exp.OID {
				found = &actual[i]
				break
			}
		}
		if found == nil {
			return fmt.Errorf("expected OID %s (%s) not found in certificate",
				exp.OID, OidLabel(exp.OID))
		}
		if !bytesEqual(found.Value, exp.ExpectedValue) {
			return fmt.Errorf("%s (%s) mismatch: got %s, expected %s",
				OidLabel(exp.OID), exp.OID,
				hex.EncodeToString(found.Value), hex.EncodeToString(exp.ExpectedValue))
		}
	}
	return nil
}

// computeReportDataHash computes SHA-512( SHA-256(pubkey) || binding ).
func computeReportDataHash(pubkeyInput, binding []byte) []byte {
	pkHash := sha256.Sum256(pubkeyInput)
	buf := make([]byte, 0, 32+len(binding))
	buf = append(buf, pkHash[:]...)
	buf = append(buf, binding...)
	h := sha512.Sum512(buf)
	return h[:]
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// verifyQuote verifies the raw quote against a remote quote verification service.
func verifyQuote(quoteRaw []byte, config *QuoteVerificationConfig) (*QuoteVerificationResult, error) {
	body, err := json.Marshal(map[string]string{
		"quote": base64.StdEncoding.EncodeToString(quoteRaw),
	})
	if err != nil {
		return nil, fmt.Errorf("quote verification: %w", err)
	}

	timeout := time.Duration(config.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}

	req, err := http.NewRequest("POST", config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("quote verification: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quote verification request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("quote verification: failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("quote verification: server returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Status      string   `json:"status"`
		TcbDate     string   `json:"tcbDate"`
		AdvisoryIDs []string `json:"advisoryIds"`
		TCBStatus   string   `json:"tcbStatus"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse quote verification response: %w (body: %s)", err, string(respBody))
	}

	result := &QuoteVerificationResult{
		Status:      QuoteVerificationStatus(parsed.Status),
		TcbDate:     parsed.TcbDate,
		AdvisoryIDs: parsed.AdvisoryIDs,
		TCBStatus:   TCBStatus(parsed.TCBStatus),
	}

	if result.Status != QvsOk {
		accepted := false
		for _, s := range config.AcceptedStatuses {
			if s == result.Status {
				accepted = true
				break
			}
		}
		if !accepted {
			return nil, fmt.Errorf("quote verification failed: status=%s, advisories=%v",
				result.Status, result.AdvisoryIDs)
		}
	}

	// Opt-in: enforce the Intel TCB status against the secure floor + caller relaxations
	// (Revoked never accepted). Client-side defence in depth: the relying party makes
	// this decision even though the server may only report the status.
	if config.EnforceTCBStatus {
		if err := tcbStatusAcceptable(result.TCBStatus, config.AcceptableTCBStatuses); err != nil {
			return nil, fmt.Errorf("quote verification failed: %w (tcbDate=%s, advisories=%v)",
				err, result.TcbDate, result.AdvisoryIDs)
		}
	}

	return result, nil
}

// verifyTDXGPU verifies a combined CPU quote + NVIDIA GPU evidence against the
// remote attestation server (a "tdx-gpu" request). It returns the CPU quote
// verdict and the GPU verdict separately. The GPU evidence has already been
// bound to the certificate's public key via ReportData (verified locally in
// verifyReportData); this call establishes that the GPU is a genuine NVIDIA
// device in Confidential Computing mode with an authentic, nonce-bound report.
func verifyTDXGPU(quoteRaw, gpuEvidence []byte, config *QuoteVerificationConfig) (*QuoteVerificationResult, *GPUAttestationResult, error) {
	body, err := json.Marshal(map[string]string{
		"quote":    base64.StdEncoding.EncodeToString(quoteRaw),
		"type":     "tdx-gpu",
		"gpuQuote": base64.StdEncoding.EncodeToString(gpuEvidence),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("tdx-gpu verification: %w", err)
	}

	timeout := time.Duration(config.TimeoutSecs) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	httpClient := &http.Client{Timeout: timeout}

	req, err := http.NewRequest("POST", config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("tdx-gpu verification: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("tdx-gpu verification request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("tdx-gpu verification: failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("tdx-gpu verification: server returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		Status         string                `json:"status"`
		TcbDate        string                `json:"tcbDate"`
		AdvisoryIDs    []string              `json:"advisoryIds"`
		TCBStatus      string                `json:"tcbStatus"`
		GPUAttestation *GPUAttestationResult `json:"gpuAttestation"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, nil, fmt.Errorf("failed to parse tdx-gpu verification response: %w (body: %s)", err, string(respBody))
	}

	result := &QuoteVerificationResult{
		Status:      QuoteVerificationStatus(parsed.Status),
		TcbDate:     parsed.TcbDate,
		AdvisoryIDs: parsed.AdvisoryIDs,
		TCBStatus:   TCBStatus(parsed.TCBStatus),
	}
	if result.Status != QvsOk {
		accepted := false
		for _, s := range config.AcceptedStatuses {
			if s == result.Status {
				accepted = true
				break
			}
		}
		if !accepted {
			return nil, nil, fmt.Errorf("tdx-gpu verification failed: status=%s, advisories=%v",
				result.Status, result.AdvisoryIDs)
		}
	}
	if config.EnforceTCBStatus {
		if err := tcbStatusAcceptable(result.TCBStatus, config.AcceptableTCBStatuses); err != nil {
			return nil, nil, fmt.Errorf("tdx-gpu verification failed: %w (tcbDate=%s, advisories=%v)",
				err, result.TcbDate, result.AdvisoryIDs)
		}
	}

	if parsed.GPUAttestation == nil {
		return nil, nil, fmt.Errorf("tdx-gpu verification: server returned no GPU attestation result")
	}
	if !parsed.GPUAttestation.Verified {
		return nil, nil, fmt.Errorf("GPU attestation failed: status=%s error=%s",
			parsed.GPUAttestation.Status, parsed.GPUAttestation.Error)
	}

	return result, parsed.GPUAttestation, nil
}

// VerifyCertificate verifies the server's leaf certificate and the evidence
// obtained for this connection against a policy (see VerifyEvidence). Call it
// before sending any application data. In AttestationNone mode only the
// certificate extensions are verified and the result carries no evidence.
func (c *Client) VerifyCertificate(policy *VerificationPolicy) (CertInfo, error) {
	if len(c.peerCerts) == 0 {
		return CertInfo{}, fmt.Errorf("no peer certificate")
	}
	c.lastPolicy = policy
	if c.mode == AttestationNone {
		return VerifyCertificateExtensions(c.peerCerts[0], policy)
	}
	return VerifyEvidence(c.peerCerts[0], c.evidence, policy)
}

// ---------------------------------------------------------------------------
//  Framing
// ---------------------------------------------------------------------------

func encodeFrame(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func decodeFrame(buf []byte) (payload []byte, consumed int, ok bool) {
	if len(buf) < 4 {
		return nil, 0, false
	}
	length := int(binary.BigEndian.Uint32(buf[:4]))
	if len(buf) < 4+length {
		return nil, 0, false
	}
	return buf[4 : 4+length], 4 + length, true
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

// Options configures the RA-TLS client connection.
type Options struct {
	// CACertPath is the path to a PEM file whose certificates become the
	// trust anchors for the server chain. If empty, the embedded Privasys
	// intermediate CAs (production and development) are used; see
	// PrivasysTrustAnchors. The chain check is mandatory in both cases and
	// does not include hostname verification (RA-TLS peers are commonly
	// dialled by IP; the identity is the quote and the app identity in the
	// certificate).
	CACertPath string
	// Timeout is the connection/read timeout (default: 10s).
	Timeout time.Duration
	// ClientCert is an optional TLS client certificate for mutual RA-TLS
	// (a v2 identity: leaf key, chain, OIDs, no evidence). When set, the
	// client presents it during the handshake.
	ClientCert *tls.Certificate
	// GetClientCertificate is a callback for dynamic client certificate
	// selection during the TLS handshake (EgressIdentity.GetClientCertificate
	// for containers). Takes precedence over ClientCert when both are set.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// ClientEvidence produces this client's evidence when the server requires
	// it on a mutual leg (EgressIdentity.ClientEvidence for containers).
	// Without it a server that requires client evidence fails the connection.
	ClientEvidence ClientEvidenceSource
	// Attestation selects what to ask the server for after the handshake.
	// The zero value is AttestationChallenge.
	Attestation AttestationMode
	// Context optionally fixes the 32-byte challenge context (challenge mode).
	// Verifiers that relay a browser-chosen challenge set it so the evidence
	// commits to that value; nil draws a fresh random context per attestation.
	// Any other length is rejected by Connect.
	Context []byte
	// Framing selects the carrier of the attest messages: HTTP (default) or
	// raw length-prefixed frames for non-HTTP protocols.
	Framing Framing
	// ServerName sets the TLS SNI extension. For per-workload certificates,
	// set this to the app/workload hostname so the enclave returns the
	// workload-specific certificate with the workload OIDs. It is also the
	// Host header of the attest request.
	ServerName string
}

// Client is a verified RA-TLS v2 connection.
type Client struct {
	conn      *tls.Conn
	peerCerts []*x509.Certificate

	mode           AttestationMode
	framing        Framing
	hostHeader     string
	evidence       *Evidence
	clientEvidence ClientEvidenceSource
	presentedCert  *tls.Certificate
	context        []byte
	lastPolicy     *VerificationPolicy
}

// RATLSALPNProto is the ALPN protocol identifier advertised by every
// RA-TLS-capable client. The Privasys gateway inspects the ClientHello:
// connections that advertise this token are spliced (pure L4 forwarding,
// the enclave terminates RA-TLS); all others are terminated by the
// gateway with its public Let's Encrypt cert and forwarded over an
// internal RA-TLS leg. Mirrors the constant in
// `platform/ra-tls-clients/rust/src/ratls_client.rs` (RATLS_ALPN_PROTO)
// and `platform/gateway/internal/sni`.
const RATLSALPNProto = "privasys-ratls/1"

func containsProto(list []string, p string) bool {
	for _, item := range list {
		if item == p {
			return true
		}
	}
	return false
}

// Connect establishes a TLS connection to the server.
func Connect(host string, port int, opts *Options) (*Client, error) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	if len(opts.Context) != 0 && len(opts.Context) != ContextLen {
		return nil, fmt.Errorf("ratls: Options.Context must be %d bytes", ContextLen)
	}

	tlsConfig := &tls.Config{}

	// SNI: set ServerName so the enclave can serve per-workload certificates
	if opts.ServerName != "" {
		tlsConfig.ServerName = opts.ServerName
	}

	// Advertise the Privasys RA-TLS marker first so the platform
	// gateway routes the connection to the splice path (pure L4
	// forwarding to the enclave) instead of terminating with its
	// public LE cert. Then advertise `http/1.1` so the actual TLS
	// server on the spliced upstream — typically Caddy in
	// enclave-os-virtual, whose default NextProtos is
	// ["h2", "http/1.1"] — can negotiate a real HTTP version. Without
	// `http/1.1`, TLS 1.3 strict ALPN aborts with
	// no_application_protocol because the marker is not in the
	// server's list. Browsers and other plain TLS clients don't
	// advertise the marker and end up on the terminate path.
	//
	// We deliberately do NOT advertise `h2`: this client speaks
	// HTTP/1.1 manually over the raw *tls.Conn (see sendHTTPRequest /
	// recvHTTPResponse below). If we offered `h2` first Caddy would
	// pick it (its own preference is `h2` ahead of `http/1.1`), then
	// our HTTP/1.1 request would be sent over an h2-negotiated
	// connection and Caddy would close mid-request (observed as
	// "connection closed before HTTP headers" on
	// /__privasys/session-bootstrap with wallet 1.2.16).
	for i, proto := range []string{RATLSALPNProto, "http/1.1"} {
		if containsProto(tlsConfig.NextProtos, proto) {
			continue
		}
		insertAt := i
		if insertAt > len(tlsConfig.NextProtos) {
			insertAt = len(tlsConfig.NextProtos)
		}
		tlsConfig.NextProtos = append(
			tlsConfig.NextProtos[:insertAt],
			append([]string{proto}, tlsConfig.NextProtos[insertAt:]...)...,
		)
	}

	// TLS 1.3 only: the exporter of the challenge mode needs it, and the
	// Privasys runtimes offer nothing lower.
	tlsConfig.MinVersion = tls.VersionTLS13

	// Mutual RA-TLS: dynamic cert callback takes precedence over static cert.
	// The presented certificate is recorded so client evidence can name it.
	client := &Client{
		mode:           opts.Attestation,
		framing:        opts.Framing,
		hostHeader:     opts.ServerName,
		clientEvidence: opts.ClientEvidence,
		context:        opts.Context,
	}
	if opts.GetClientCertificate != nil {
		get := opts.GetClientCertificate
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := get(info)
			if err == nil && cert != nil {
				client.presentedCert = cert
			}
			return cert, err
		}
	} else if opts.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*opts.ClientCert}
		client.presentedCert = opts.ClientCert
	}

	// Server chain: mandatory, against the Privasys fleet anchors or the
	// certificates in CACertPath. The standard library's own verification
	// is disabled only so that verifyFleetChain can run the chain check
	// without hostname verification; it is never skipped.
	anchors, err := PrivasysTrustAnchors()
	if opts.CACertPath != "" {
		anchors, err = trustAnchorsFromFile(opts.CACertPath)
	}
	if err != nil {
		return nil, err
	}
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyPeerCertificate = verifyFleetChain(anchors)

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connect: %w", err)
	}
	client.conn = conn
	client.peerCerts = conn.ConnectionState().PeerCertificates

	// Evidence exchange, before any application data. A failure here closes
	// the connection: a caller never gets a Client whose evidence is missing
	// in a mode that asked for it.
	if err := conn.SetDeadline(time.Now().Add(opts.Timeout)); err == nil {
		defer conn.SetDeadline(time.Time{})
	}
	if err := client.attest(opts.Attestation); err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Conn exposes the verified connection for callers that pool it (an
// http.Transport DialTLSContext). The caller takes over the connection's
// lifetime: requests multiplexed over it inherit the handshake-bound
// attestation verified once at dial.
func (c *Client) Conn() *tls.Conn {
	return c.conn
}

// PeerCertificates returns the peer's x509 certificates from the TLS handshake.
func (c *Client) PeerCertificates() []*x509.Certificate {
	return c.peerCerts
}

// TLSVersion returns the negotiated TLS version string.
func (c *Client) TLSVersion() string {
	state := c.conn.ConnectionState()
	switch state.Version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return fmt.Sprintf("0x%04x", state.Version)
	}
}

// CipherSuite returns the negotiated cipher suite name.
func (c *Client) CipherSuite() string {
	return tls.CipherSuiteName(c.conn.ConnectionState().CipherSuite)
}

// InspectCert returns RA-TLS certificate info for the server's leaf cert,
// with the evidence obtained for the connection attached UNVERIFIED (Quote,
// GPUEvidence, Attestation, Evidence) so measurements can be displayed.
// VerifyCertificate is what verifies it.
func (c *Client) InspectCert() CertInfo {
	if len(c.peerCerts) == 0 {
		return CertInfo{}
	}
	info := InspectCertificate(c.peerCerts[0])
	if c.evidence != nil {
		info.Quote = quoteInfoOf(c.evidence)
		info.GPUEvidence = c.evidence.GPUEvidence
		info.Attestation = c.evidence.Mode
		info.Evidence = c.evidence
	}
	return info
}

// PeerCertificatesDER returns the DER-encoded peer certificates.
func (c *Client) PeerCertificatesDER() [][]byte {
	out := make([][]byte, len(c.peerCerts))
	for i, cert := range c.peerCerts {
		out[i] = cert.Raw
	}
	return out
}

// -- HTTP/1.1 protocol ----------------------------------------------------

// sendHTTPRequest sends an HTTP/1.1 request over the TLS connection.
func (c *Client) sendHTTPRequest(method, path string, body []byte, authToken string, connClose bool) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\nHost: %s\r\n",
		method, path, c.conn.RemoteAddr().String())
	if len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Length: %d\r\nContent-Type: application/json\r\n", len(body))
	}
	if authToken != "" {
		fmt.Fprintf(&buf, "Authorization: Bearer %s\r\n", authToken)
	}
	if connClose {
		buf.WriteString("Connection: close\r\n")
	}
	buf.WriteString("\r\n")
	if len(body) > 0 {
		buf.Write(body)
	}
	_, err := c.conn.Write(buf.Bytes())
	return err
}

// recvHTTPResponse reads an HTTP/1.1 response from the TLS connection.
// Returns (statusCode, body, error).
func (c *Client) recvHTTPResponse() (int, []byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)

	// Read until we find \r\n\r\n
	for {
		if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
			break
		}
		n, err := c.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				break
			}
			return 0, nil, fmt.Errorf("reading HTTP headers: %w", err)
		}
	}

	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return 0, nil, fmt.Errorf("no HTTP header terminator found")
	}

	headerSection := string(buf[:headerEnd])
	bodyStart := headerEnd + 4

	// Parse status line
	lines := strings.SplitN(headerSection, "\r\n", 2)
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("malformed HTTP status line: %s", lines[0])
	}
	statusCode := 0
	fmt.Sscanf(parts[1], "%d", &statusCode)

	// Parse content-length
	contentLength := 0
	for _, line := range strings.Split(headerSection, "\r\n")[1:] {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			fmt.Sscanf(val, "%d", &contentLength)
		}
	}

	// Collect body
	body := buf[bodyStart:]
	for len(body) < contentLength {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			body = append(body, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(body) > contentLength {
		body = body[:contentLength]
	}

	return statusCode, body, nil
}

// Healthz sends GET /healthz (liveness probe, no auth).
func (c *Client) Healthz() (map[string]interface{}, error) {
	if err := c.sendHTTPRequest("GET", "/healthz", nil, "", false); err != nil {
		return nil, err
	}
	status, body, err := c.recvHTTPResponse()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("healthz failed (%d): %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Readyz sends GET /readyz (monitoring+ role).
func (c *Client) Readyz(authToken string) (map[string]interface{}, error) {
	if err := c.sendHTTPRequest("GET", "/readyz", nil, authToken, false); err != nil {
		return nil, err
	}
	status, body, err := c.recvHTTPResponse()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("readyz failed (%d): %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Status sends GET /status (monitoring+ role).
func (c *Client) Status(authToken string) ([]map[string]interface{}, error) {
	if err := c.sendHTTPRequest("GET", "/status", nil, authToken, false); err != nil {
		return nil, err
	}
	status, body, err := c.recvHTTPResponse()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("status failed (%d): %s", status, string(body))
	}
	var result []map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Metrics sends GET /metrics (monitoring+ role).
func (c *Client) Metrics(authToken string) (map[string]interface{}, error) {
	if err := c.sendHTTPRequest("GET", "/metrics", nil, authToken, false); err != nil {
		return nil, err
	}
	status, body, err := c.recvHTTPResponse()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("metrics failed (%d): %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SendData sends POST /data with module command payload.
// Auth is passed via the Authorization header.
func (c *Client) SendData(data []byte, authToken string) ([]byte, error) {
	if err := c.sendHTTPRequest("POST", "/data", data, authToken, false); err != nil {
		return nil, err
	}
	status, body, err := c.recvHTTPResponse()
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("server error (%d): %s", status, string(body))
	}
	return body, nil
}

// HTTPDo sends an HTTP/1.1 request over the verified RA-TLS connection with an
// explicit Host header (required for per-container / per-workload routing
// through the enclave's Caddy) and returns the response. Parsing uses
// net/http, so chunked and streaming (e.g. SSE) responses work; the caller
// must close resp.Body. Used by clients that call a container app directly
// over RA-TLS instead of proxying through a control plane.
func (c *Client) HTTPDo(method, path, hostHeader string, body []byte, authToken string) (*http.Response, error) {
	var hdr http.Header
	if authToken != "" {
		hdr = http.Header{"Authorization": []string{"Bearer " + authToken}}
	}
	return c.HTTPDoHeader(method, path, hostHeader, body, hdr)
}

// HTTPDoHeader is HTTPDo carrying the caller's FULL header set. HTTPDo
// rebuilt the request with only Content-Type and Authorization, silently
// dropping everything else — which broke any protocol riding on custom
// headers over the attested leg (first seen live 2026-08-09: the
// confidential-AI enclave set X-Privasys-On-Behalf-Of on Drive tool calls
// and Drive 401'd every one with "missing on-behalf-of subject").
// Content-Type still defaults to application/json when a body is present
// and the caller did not say otherwise.
func (c *Client) HTTPDoHeader(method, path, hostHeader string, body []byte, hdr http.Header) (*http.Response, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://"+hostHeader+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Host = hostHeader
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if len(body) > 0 {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.ContentLength = int64(len(body))
	}
	if err := req.Write(c.conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(c.conn), req)
}

// SetAttestationServers sends PUT /attestation-servers.
func (c *Client) SetAttestationServers(servers interface{}, authToken string) (map[string]interface{}, error) {
	payload, err := json.Marshal(map[string]interface{}{"servers": servers})
	if err != nil {
		return nil, err
	}
	if err := c.sendHTTPRequest("PUT", "/attestation-servers", payload, authToken, false); err != nil {
		return nil, err
	}
	status, body, errR := c.recvHTTPResponse()
	if errR != nil {
		return nil, errR
	}
	if status != 200 {
		return nil, fmt.Errorf("set_attestation_servers failed (%d): %s", status, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Shutdown sends POST /shutdown (manager role).
func (c *Client) Shutdown(authToken string) error {
	if err := c.sendHTTPRequest("POST", "/shutdown", nil, authToken, true); err != nil {
		return err
	}
	status, body, err := c.recvHTTPResponse()
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("shutdown failed (%d): %s", status, string(body))
	}
	return nil
}

// -- Legacy frame protocol (deprecated) -----------------------------------

func (c *Client) sendFrame(payload []byte) error {
	_, err := c.conn.Write(encodeFrame(payload))
	return err
}

// SendRaw sends a pre-built JSON payload as a framed request and returns
// the raw response bytes.
//
// Deprecated: Use HTTP methods (SendData, Healthz, etc.) instead.
func (c *Client) SendRaw(payload []byte) ([]byte, error) {
	if err := c.sendFrame(payload); err != nil {
		return nil, err
	}
	return c.recvFrame()
}

func (c *Client) recvFrame() ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if payload, _, ok := decodeFrame(buf); ok {
				return payload, nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("connection closed before frame received")
			}
			return nil, err
		}
	}
}

// Ping sends a Ping request and expects Pong.
//
// Deprecated: Use Healthz() instead.
func (c *Client) Ping() (bool, error) {
	result, err := c.Healthz()
	if err != nil {
		return false, err
	}
	return result["status"] == "ok", nil
}

// ---------------------------------------------------------------------------
//  Pretty-print
// ---------------------------------------------------------------------------

// PrintCertInfo prints certificate and quote info to stdout.
func PrintCertInfo(info CertInfo) {
	fmt.Printf("  Subject      : %s\n", info.Subject)
	fmt.Printf("  Issuer       : %s\n", info.Issuer)
	fmt.Printf("  Serial       : %s\n", info.SerialNumber)
	fmt.Printf("  Not Before   : %s\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After    : %s\n", info.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Sig Algo     : %s\n", info.SigAlgo)
	fmt.Printf("  PubKey SHA256: %s\n", info.PubKeySHA256)

	if info.Quote != nil {
		q := info.Quote
		fmt.Println()
		fmt.Println("  ** RA-TLS Extension found! **")
		fmt.Printf("    OID       : %s  (%s)\n", q.OID, q.Label)
		fmt.Printf("    Critical  : %v\n", q.Critical)
		fmt.Printf("    Size      : %d bytes\n", len(q.Raw))
		if q.IsMock {
			fmt.Println("    ** MOCK QUOTE **")
		}
		if q.Version != nil {
			fmt.Printf("    Version   : %d\n", *q.Version)
		}
		if q.ReportData != nil {
			fmt.Printf("    ReportData: %s\n", hex.EncodeToString(q.ReportData))
		}

		// Display measurement registers
		if q.OID == OidSGXQuote {
			format := DetectSgxFormat(q.Raw)
			mreOff, mreEnd, mrsOff, mrsEnd, _, _, minSz := sgxOffsets(format)
			if len(q.Raw) >= minSz {
				formatName := "DcapV3"
				if format == SgxFormatRawReport {
					formatName = "RawReport"
				}
				fmt.Printf("    Format    : %s\n", formatName)
				fmt.Printf("    MRENCLAVE : %s\n", hex.EncodeToString(q.Raw[mreOff:mreEnd]))
				fmt.Printf("    MRSIGNER  : %s\n", hex.EncodeToString(q.Raw[mrsOff:mrsEnd]))
			}
		} else if q.OID == OidTDXQuote && len(q.Raw) >= TDXQuoteMinSize {
			fmt.Printf("    MRTD      : %s\n", hex.EncodeToString(q.Raw[TDXQuoteMRTDOff:TDXQuoteMRTDEnd]))
		}

		previewLen := 32
		if len(q.Raw) < previewLen {
			previewLen = len(q.Raw)
		}
		fmt.Printf("    Preview   : %s...\n", hex.EncodeToString(q.Raw[:previewLen]))
	} else {
		fmt.Println()
		fmt.Println("  No RA-TLS extension found.")
	}

	if len(info.CustomOids) > 0 {
		fmt.Println()
		fmt.Println("  ** Privasys Configuration OIDs **")
		for _, ext := range info.CustomOids {
			fmt.Printf("    %s (%s): %s\n", ext.Label, ext.OID, hex.EncodeToString(ext.Value))
		}
	}

	if info.QuoteVerification != nil {
		qv := info.QuoteVerification
		fmt.Println()
		fmt.Println("  ** Quote Verification **")
		fmt.Printf("    Status    : %s\n", qv.Status)
		if qv.TcbDate != "" {
			fmt.Printf("    TCB Date  : %s\n", qv.TcbDate)
		}
		if len(qv.AdvisoryIDs) > 0 {
			fmt.Printf("    Advisories: %s\n", fmt.Sprintf("%v", qv.AdvisoryIDs))
		}
	}
}
