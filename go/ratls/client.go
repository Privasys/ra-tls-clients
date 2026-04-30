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
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
//  RA-TLS OIDs
// ---------------------------------------------------------------------------

const (
	// OidSGXQuote is the OID for Intel SGX quotes (enclave-os-mini).
	OidSGXQuote = "1.2.840.113741.1.13.1.0"
	// OidTDXQuote is the OID for Intel TDX quotes (enclave-os-virtual).
	OidTDXQuote = "1.2.840.113741.1.5.5.1.6"
	// OidSEVSNPReport is the OID for AMD SEV-SNP attestation reports.
	OidSEVSNPReport = "1.3.6.1.4.1.65230.4.1"
	// OidNVIDIAGPUEvidence is the OID for NVIDIA GPU attestation evidence.
	OidNVIDIAGPUEvidence = "1.3.6.1.4.1.65230.5.1"

	// Privasys configuration OIDs

	// OidConfigMerkleRoot proves all config inputs.
	OidConfigMerkleRoot = "1.3.6.1.4.1.65230.1.1"
	// OidEgressCAHash proves the outbound trust anchors.
	OidEgressCAHash = "1.3.6.1.4.1.65230.2.1"
	// OidRuntimeVersionHash is the SHA-256 of the runtime version (Wasmtime / containerd).
	OidRuntimeVersionHash = "1.3.6.1.4.1.65230.2.4"
	// OidCombinedWorkloadsHash proves the application code (WASM apps / container images).
	OidCombinedWorkloadsHash = "1.3.6.1.4.1.65230.2.5"
	// OidDEKOrigin is the Data Encryption Key origin ("byok:<fingerprint>" or "generated").
	OidDEKOrigin = "1.3.6.1.4.1.65230.2.6"
	// OidAttestationServersHash is the SHA-256 of the sorted attestation server URL list.
	OidAttestationServersHash = "1.3.6.1.4.1.65230.2.7"
	// OidWorkloadConfigMerkleRoot is the per-workload config Merkle root.
	OidWorkloadConfigMerkleRoot = "1.3.6.1.4.1.65230.3.1"
	// OidWorkloadCodeHash is the per-workload code/image hash.
	OidWorkloadCodeHash = "1.3.6.1.4.1.65230.3.2"
	// OidWorkloadImageRef is the per-workload image ref (Virtual only).
	OidWorkloadImageRef = "1.3.6.1.4.1.65230.3.3"
	// OidWorkloadKeySource is the per-workload key source / volume encryption.
	OidWorkloadKeySource = "1.3.6.1.4.1.65230.3.4"
	// OidWorkloadConfigurationHash is the per-workload configuration hash.
	OidWorkloadConfigurationHash = "1.3.6.1.4.1.65230.3.5"

	// Backward-compatible aliases

	// OidWasmAppsHash is an alias for OidCombinedWorkloadsHash (legacy name).
	OidWasmAppsHash = OidCombinedWorkloadsHash
)

// privasysOIDs is the set of Privasys configuration OIDs.
var privasysOIDs = map[string]bool{
	OidConfigMerkleRoot:          true,
	OidEgressCAHash:              true,
	OidRuntimeVersionHash:        true,
	OidCombinedWorkloadsHash:     true,
	OidDEKOrigin:                 true,
	OidAttestationServersHash:    true,
	OidWorkloadConfigMerkleRoot:  true,
	OidWorkloadCodeHash:          true,
	OidWorkloadImageRef:          true,
	OidWorkloadKeySource:         true,
	OidWorkloadConfigurationHash: true,
}

// OidLabel returns a human-readable label for a known RA-TLS OID.
func OidLabel(oid string) string {
	switch oid {
	case OidSGXQuote:
		return "SGX Quote"
	case OidTDXQuote:
		return "TDX Quote"
	case OidSEVSNPReport:
		return "SEV-SNP Report"
	case OidNVIDIAGPUEvidence:
		return "NVIDIA GPU Evidence"
	case OidConfigMerkleRoot:
		return "Config Merkle Root"
	case OidEgressCAHash:
		return "Egress CA Hash"
	case OidRuntimeVersionHash:
		return "Runtime Version Hash"
	case OidCombinedWorkloadsHash:
		return "Combined Workloads Hash"
	case OidDEKOrigin:
		return "DEK Origin"
	case OidAttestationServersHash:
		return "Attestation Servers Hash"
	case OidWorkloadConfigMerkleRoot:
		return "Workload Config Merkle Root"
	case OidWorkloadCodeHash:
		return "Workload Code Hash"
	case OidWorkloadImageRef:
		return "Workload Image Ref"
	case OidWorkloadKeySource:
		return "Workload Key Source"
	case OidWorkloadConfigurationHash:
		return "Workload Configuration Hash"
	default:
		return "Unknown"
	}
}

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
const (
	TDXQuoteMinSize       = 632
	TDXQuoteMRTDOff       = 184
	TDXQuoteMRTDEnd       = 232
	TDXQuoteReportDataOff = 568
	TDXQuoteReportDataEnd = 632
)

// AMD SEV-SNP Attestation Report (raw report from /dev/sev-guest).
// Report layout: Version(4) GuestSVN(4) Policy(8) ... ReportData(64) Measurement(48) HostData(32) ...
// Total report size: 0x4A0 = 1184 bytes.
const (
	SEVSNPReportMinSize      = 0x4A0 // 1184 bytes
	SEVSNPReportDataOff      = 0x050 // 80
	SEVSNPReportDataEnd      = 0x090 // 144
	SEVSNPMeasurementOff     = 0x090 // 144
	SEVSNPMeasurementEnd     = 0x0C0 // 192
	SEVSNPHostDataOff        = 0x0C0 // 192
	SEVSNPHostDataEnd        = 0x0E0 // 224
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

// ReportDataMode controls how the verifier reproduces the quote's ReportData.
type ReportDataMode int

const (
	// ReportDataSkip does not verify ReportData.
	ReportDataSkip ReportDataMode = iota
	// ReportDataDeterministic reproduces ReportData from the certificate alone.
	ReportDataDeterministic
	// ReportDataChallengeResponse uses a client-supplied nonce.
	ReportDataChallengeResponse
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
	// Measurement is the expected SEV-SNP MEASUREMENT (48 bytes). Nil to skip.
	Measurement []byte
	// HostData is the expected SEV-SNP HOST_DATA (32 bytes). Nil to skip.
	HostData []byte
	// ReportData controls how ReportData is verified.
	ReportData ReportDataMode
	// Nonce is the client-supplied nonce for ChallengeResponse mode.
	Nonce []byte
	// ExpectedOids are custom OID values to verify.
	ExpectedOids []ExpectedOid
	// QuoteVerification is an optional remote quote verification configuration.
	QuoteVerification *QuoteVerificationConfig
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
	Quote        *QuoteInfo
	// CustomOids holds Privasys configuration OIDs found in the certificate.
	CustomOids []OidExtension
	// QuoteVerification holds the remote quote verification result (populated during Verify).
	QuoteVerification *QuoteVerificationResult
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

		if oidStr == OidSGXQuote || oidStr == OidTDXQuote || oidStr == OidSEVSNPReport || oidStr == OidNVIDIAGPUEvidence {
			info.Quote = parseQuote(oidStr, ext.Critical, ext.Value)
		} else if privasysOIDs[oidStr] {
			info.CustomOids = append(info.CustomOids, OidExtension{
				OID:   oidStr,
				Label: OidLabel(oidStr),
				Value: ext.Value,
			})
		}
	}

	return info
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
	} else if oid == OidSEVSNPReport && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
		if len(raw) >= SEVSNPReportMinSize {
			q.ReportData = raw[SEVSNPReportDataOff:SEVSNPReportDataEnd]
		}
	} else if oid == OidNVIDIAGPUEvidence {
		// NVIDIA GPU evidence is opaque; no standard binary layout to parse.
		// Mark as present. Version/ReportData left nil.
	}

	return q
}

// ---------------------------------------------------------------------------
//  RA-TLS verification
// ---------------------------------------------------------------------------

// VerifyRaTlsCert verifies an X.509 certificate against a VerificationPolicy.
// Returns the CertInfo on success or an error describing the first failure.
func VerifyRaTlsCert(cert *x509.Certificate, policy *VerificationPolicy) (CertInfo, error) {
	info := InspectCertificate(cert)

	// 1. Quote must be present
	if info.Quote == nil {
		return info, fmt.Errorf("no RA-TLS attestation quote in certificate")
	}
	if info.Quote.IsMock {
		return info, fmt.Errorf("certificate contains a MOCK quote")
	}

	// 2. Correct TEE type
	switch policy.TEE {
	case TeeTypeSGX:
		if info.Quote.OID != OidSGXQuote {
			return info, fmt.Errorf("expected SGX quote (%s), found %s", OidSGXQuote, info.Quote.OID)
		}
	case TeeTypeTDX:
		if info.Quote.OID != OidTDXQuote {
			return info, fmt.Errorf("expected TDX quote (%s), found %s", OidTDXQuote, info.Quote.OID)
		}
	case TeeTypeSEVSNP:
		if info.Quote.OID != OidSEVSNPReport {
			return info, fmt.Errorf("expected SEV-SNP report (%s), found %s", OidSEVSNPReport, info.Quote.OID)
		}
	case TeeTypeNVIDIAGPU:
		if info.Quote.OID != OidNVIDIAGPUEvidence {
			return info, fmt.Errorf("expected NVIDIA GPU evidence (%s), found %s", OidNVIDIAGPUEvidence, info.Quote.OID)
		}
	}

	// 3. Measurement registers
	if err := verifyMeasurements(info.Quote.Raw, policy); err != nil {
		return info, err
	}

	// 4. ReportData
	if err := verifyReportData(cert, info.Quote.Raw, policy); err != nil {
		return info, err
	}

	// 5. Custom OID values
	if err := verifyExpectedOids(info.CustomOids, policy.ExpectedOids); err != nil {
		return info, err
	}

	// 6. Remote quote verification
	if policy.QuoteVerification != nil {
		result, err := verifyQuote(info.Quote.Raw, policy.QuoteVerification)
		if err != nil {
			return info, err
		}
		info.QuoteVerification = result
	}

	return info, nil
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

func verifyReportData(cert *x509.Certificate, raw []byte, policy *VerificationPolicy) error {
	var binding []byte

	switch policy.ReportData {
	case ReportDataSkip:
		return nil
	case ReportDataDeterministic:
		if policy.TEE == TeeTypeSGX || policy.TEE == TeeTypeNVIDIAGPU {
			// Deterministic mode is not applicable for SGX or NVIDIA GPU.
			return nil
		}
		// TDX: binding is NotBefore formatted as "YYYY-MM-DDTHH:MMZ"
		nb := cert.NotBefore.UTC()
		binding = []byte(fmt.Sprintf("%04d-%02d-%02dT%02d:%02dZ",
			nb.Year(), nb.Month(), nb.Day(), nb.Hour(), nb.Minute()))
	case ReportDataChallengeResponse:
		binding = policy.Nonce
	}

	// Build the pubkey input — both SGX and TDX use full SPKI DER.
	// SHA-256 of the SPKI DER matches the standard "Public Key SHA-256"
	// fingerprint shown by X.509 certificate viewers.
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubkeyInput := pubDER

	expected := computeReportDataHash(pubkeyInput, binding)

	// Get actual ReportData
	var actual []byte
	switch policy.TEE {
	case TeeTypeSGX:
		format := DetectSgxFormat(raw)
		_, _, _, _, rdOff, rdEnd, _ := sgxOffsets(format)
		if len(raw) < rdEnd {
			return fmt.Errorf("quote too small to contain ReportData")
		}
		actual = raw[rdOff:rdEnd]
	case TeeTypeTDX:
		if len(raw) < TDXQuoteReportDataEnd {
			return fmt.Errorf("quote too small to contain ReportData")
		}
		actual = raw[TDXQuoteReportDataOff:TDXQuoteReportDataEnd]
	case TeeTypeSEVSNP:
		if len(raw) < SEVSNPReportDataEnd {
			return fmt.Errorf("report too small to contain ReportData")
		}
		actual = raw[SEVSNPReportDataOff:SEVSNPReportDataEnd]
	case TeeTypeNVIDIAGPU:
		return nil
	}

	if !bytesEqual(actual, expected) {
		return fmt.Errorf("ReportData mismatch:\n  got:      %s\n  expected: %s",
			hex.EncodeToString(actual), hex.EncodeToString(expected))
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
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse quote verification response: %w (body: %s)", err, string(respBody))
	}

	result := &QuoteVerificationResult{
		Status:      QuoteVerificationStatus(parsed.Status),
		TcbDate:     parsed.TcbDate,
		AdvisoryIDs: parsed.AdvisoryIDs,
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

	return result, nil
}

// VerifyCertificate verifies the server's leaf certificate against a policy.
func (c *Client) VerifyCertificate(policy *VerificationPolicy) (CertInfo, error) {
	if len(c.peerCerts) == 0 {
		return CertInfo{}, fmt.Errorf("no peer certificate")
	}
	return VerifyRaTlsCert(c.peerCerts[0], policy)
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
	// CACertPath is the path to a PEM CA certificate for chain verification.
	// If empty, certificate verification is disabled (dev mode).
	CACertPath string
	// Timeout is the connection/read timeout (default: 10s).
	Timeout time.Duration
	// ClientCert is an optional TLS client certificate for mutual RA-TLS.
	// When set, the client presents this certificate during the handshake.
	// The querying enclave's RA-TLS cert (with SGX/TDX quote in extensions)
	// should be provided here for vault GetSecret operations.
	ClientCert *tls.Certificate
	// GetClientCertificate is a callback for dynamic client certificate
	// generation during the TLS handshake.  The CertificateRequestInfo
	// parameter includes RATLSChallenge (Privasys Go fork) — the raw
	// challenge nonce sent by the server as TLS extension 0xffbb.
	// The callback can bind this nonce into a fresh RA-TLS certificate.
	//
	// Takes precedence over ClientCert when both are set.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// Challenge is a nonce to send in the TLS ClientHello as RA-TLS
	// extension 0xFFBB (client → server challenge). The server will bind
	// this nonce into the ReportData of a fresh attestation certificate.
	//
	// Requires the Privasys/go fork (https://github.com/Privasys/go/tree/ratls).
	// Build with: GOROOT=~/go-ratls go build -tags ratls
	Challenge []byte
	// ServerName sets the TLS SNI extension. For per-workload certificates,
	// set this to the app/workload hostname so the enclave returns the
	// workload-specific certificate with 3.x OIDs.
	ServerName string
}

// Client is an RA-TLS client for enclave-os-mini.
type Client struct {
	conn      *tls.Conn
	peerCerts []*x509.Certificate
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

	tlsConfig := &tls.Config{}

	// SNI: set ServerName so the enclave can serve per-workload certificates
	if opts.ServerName != "" {
		tlsConfig.ServerName = opts.ServerName
	}

	// Advertise the Privasys RA-TLS ALPN so the platform gateway routes
	// the connection to the splice path (pure L4 forwarding to the
	// enclave) instead of terminating with its public LE cert. Browsers
	// and other plain TLS clients don't advertise it and end up on the
	// terminate path. The server side does not need to negotiate this
	// protocol back.
	if !containsProto(tlsConfig.NextProtos, RATLSALPNProto) {
		tlsConfig.NextProtos = append([]string{RATLSALPNProto}, tlsConfig.NextProtos...)
	}

	// RA-TLS challenge (client → server): send nonce in ClientHello 0xFFBB
	if len(opts.Challenge) > 0 {
		if err := setRATLSChallenge(tlsConfig, opts.Challenge); err != nil {
			return nil, fmt.Errorf("set RA-TLS challenge: %w", err)
		}
	}

	// Mutual RA-TLS: dynamic cert callback takes precedence over static cert
	if opts.GetClientCertificate != nil {
		tlsConfig.GetClientCertificate = opts.GetClientCertificate
	} else if opts.ClientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	if opts.CACertPath != "" {
		caPEM, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		block, _ := pem.Decode(caPEM)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in CA cert file")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA cert: %w", err)
		}
		pool.AddCert(caCert)
		tlsConfig.RootCAs = pool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connect: %w", err)
	}

	return &Client{
		conn:      conn,
		peerCerts: conn.ConnectionState().PeerCertificates,
	}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
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

// InspectCert returns RA-TLS certificate info for the server's leaf cert.
func (c *Client) InspectCert() CertInfo {
	if len(c.peerCerts) == 0 {
		return CertInfo{}
	}
	return InspectCertificate(c.peerCerts[0])
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
