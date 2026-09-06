// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// Platform allow-list.
//
// A quote that verifies proves that a genuine TEE with the reported
// measurements signed it, not which machine it came from: evidence from any
// platform whose attestation key has not been revoked passes. A relying party
// that knows which machines it operates pins them with
// VerificationPolicy.AllowedPlatformIDs. The identifier is read by the
// attestation server from the verified evidence and reported in its response
// (the "platform" object): for Intel SGX and TDX the PCK certificate's
// Platform Instance ID (SGX extension 1.2.840.113741.1.13.1.6, present on
// certificates issued by the PCK Platform CA), else its PPID (.1); for AMD
// SEV-SNP the report's CHIP_ID. The list is also sent to the server, which
// enforces it too (status PLATFORM_NOT_ALLOWED); the client check below is
// the relying party's own decision and does not depend on the server
// honouring the request. Hardware endorsements (Intel POE) will replace this
// once a distribution channel exists.

// PlatformID is the identifier an allow-list entry is matched against: the
// Platform Instance ID when the server reported one, else the PPID, else the
// SEV-SNP CHIP_ID; empty when the server reported no platform identity.
func (r *QuoteVerificationResult) PlatformID() string {
	if r == nil {
		return ""
	}
	switch {
	case r.PlatformInstanceID != "":
		return r.PlatformInstanceID
	case r.PPID != "":
		return r.PPID
	default:
		return r.ChipID
	}
}

// normalizePlatformID lowercases a hex identifier and drops separators.
func normalizePlatformID(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", ":", "", " ", "").Replace(strings.TrimSpace(s)))
}

// platformAllowed checks the platform identity of the verified evidence (read
// from the quote, else reported by the attestation server) against the
// policy's allow-list. An empty list allows every platform; a non-empty list
// with no identity at all fails closed.
func platformAllowed(r *QuoteVerificationResult, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	id := normalizePlatformID(r.PlatformID())
	if id == "" {
		return fmt.Errorf("platform allow-list: the evidence carries no platform identity and the attestation server reported none")
	}
	for _, a := range allowed {
		if normalizePlatformID(a) == id {
			return nil
		}
	}
	return fmt.Errorf("platform %s is not in AllowedPlatformIDs (%d entries)", id, len(allowed))
}

// platformFromResponse fills the identity fields of a result from the
// server's "platform" object (absent on servers predating the field).
func platformFromResponse(r *QuoteVerificationResult, p *platformResponse) {
	if p == nil {
		return
	}
	r.PPID = p.PPID
	r.PlatformInstanceID = p.PlatformInstanceID
	r.FMSPC = p.FMSPC
	r.ChipID = p.ChipID
}

// PlatformIdentity is the identity of the physical platform read from the
// evidence itself: the PCK certificate embedded in an SGX or TDX quote's
// certification data, or the CHIP_ID of an SEV-SNP report. Lowercase hex.
type PlatformIdentity struct {
	PPID               string
	PlatformInstanceID string
	FMSPC              string
	ChipID             string
}

// ID is the identifier of record: Platform Instance ID, else PPID, else CHIP_ID.
func (p *PlatformIdentity) ID() string {
	if p == nil {
		return ""
	}
	switch {
	case p.PlatformInstanceID != "":
		return p.PlatformInstanceID
	case p.PPID != "":
		return p.PPID
	default:
		return p.ChipID
	}
}

var (
	oidSgxExtension      = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidSgxPPID           = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 1}
	oidSgxFMSPC          = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
	oidSgxPlatformInstID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 6}
)

const (
	pemCertBegin       = "-----BEGIN CERTIFICATE-----"
	pemCertEnd         = "-----END CERTIFICATE-----"
	sevSnpChipIDOffset = 0x1A0
	sevSnpChipIDLen    = 64
	sgxPckIDLen        = 16
	sgxPckFMSPCLen     = 6
)

// PlatformIdentityFromQuote reads the platform identity out of raw evidence
// of family tee ("sgx", "tdx", "tdx-gpu", "sev-snp"). For DCAP quotes it is
// the SGX extension of the first certificate of the PEM chain in the quote's
// certification data, the PCK leaf whose key certified the quote; the value
// is therefore only as trustworthy as the quote's verification, which is why
// the SDK reads it after the attestation server accepted the quote. Returns
// nil, nil when the evidence carries no identity (a quote whose certification
// data is not a PEM chain).
func PlatformIdentityFromQuote(tee string, quote []byte) (*PlatformIdentity, error) {
	if tee == "sev-snp" {
		if len(quote) < sevSnpChipIDOffset+sevSnpChipIDLen {
			return nil, fmt.Errorf("SEV-SNP report too small for CHIP_ID: %d bytes", len(quote))
		}
		return &PlatformIdentity{ChipID: hex.EncodeToString(quote[sevSnpChipIDOffset : sevSnpChipIDOffset+sevSnpChipIDLen])}, nil
	}
	leaf := firstPEMCertificate(quote)
	if leaf == nil {
		return nil, nil
	}
	cert, err := x509.ParseCertificate(leaf)
	if err != nil {
		return nil, fmt.Errorf("PCK certificate in quote: %w", err)
	}
	return platformIdentityFromPCK(cert)
}

// firstPEMCertificate returns the DER of the first PEM certificate block found
// in data (the PCK leaf of a DCAP quote), or nil.
func firstPEMCertificate(data []byte) []byte {
	i := bytes.Index(data, []byte(pemCertBegin))
	if i < 0 {
		return nil
	}
	block, _ := pem.Decode(data[i:])
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return block.Bytes
}

// platformIdentityFromPCK parses the SGX extension of a PCK certificate.
func platformIdentityFromPCK(cert *x509.Certificate) (*PlatformIdentity, error) {
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSgxExtension) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("certificate carries no SGX extension (%s): not a PCK certificate", oidSgxExtension)
	}
	var entries []asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("SGX extension: %w", err)
	}
	p := &PlatformIdentity{}
	for _, e := range entries {
		var entry struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(e.FullBytes, &entry); err != nil {
			return nil, fmt.Errorf("SGX extension entry: %w", err)
		}
		octets := func(name string, size int) (string, error) {
			var b []byte
			if _, err := asn1.Unmarshal(entry.Value.FullBytes, &b); err != nil {
				return "", fmt.Errorf("SGX extension %s: %w", name, err)
			}
			if len(b) != size {
				return "", fmt.Errorf("SGX extension %s: %d bytes, want %d", name, len(b), size)
			}
			return hex.EncodeToString(b), nil
		}
		var err error
		switch {
		case entry.Type.Equal(oidSgxPPID):
			p.PPID, err = octets("PPID", sgxPckIDLen)
		case entry.Type.Equal(oidSgxFMSPC):
			p.FMSPC, err = octets("FMSPC", sgxPckFMSPCLen)
		case entry.Type.Equal(oidSgxPlatformInstID):
			p.PlatformInstanceID, err = octets("Platform Instance ID", sgxPckIDLen)
		}
		if err != nil {
			return nil, err
		}
	}
	if p.PPID == "" {
		return nil, fmt.Errorf("PCK certificate SGX extension carries no PPID")
	}
	return p, nil
}

// applyLocalPlatform reconciles the identity read from the quote with the one
// the attestation server reported. The quote's value is authoritative once the
// server has verified the quote (the PCK leaf it embeds is the key that
// certified it); a server value that disagrees is an error, and a server
// value fills in when the quote carries none.
func applyLocalPlatform(r *QuoteVerificationResult, tee string, quote []byte) error {
	local, err := PlatformIdentityFromQuote(tee, quote)
	if err != nil {
		return fmt.Errorf("platform identity in quote: %w", err)
	}
	if local == nil {
		return nil
	}
	reported := &PlatformIdentity{PPID: r.PPID, PlatformInstanceID: r.PlatformInstanceID, FMSPC: r.FMSPC, ChipID: r.ChipID}
	for _, pair := range [][2]string{{local.PPID, reported.PPID}, {local.PlatformInstanceID, reported.PlatformInstanceID}, {local.FMSPC, reported.FMSPC}, {local.ChipID, reported.ChipID}} {
		if pair[0] != "" && pair[1] != "" && normalizePlatformID(pair[0]) != normalizePlatformID(pair[1]) {
			return fmt.Errorf("platform identity mismatch: the quote carries %s, the attestation server reported %s", local.ID(), reported.ID())
		}
	}
	r.PPID, r.PlatformInstanceID, r.FMSPC, r.ChipID = local.PPID, local.PlatformInstanceID, local.FMSPC, local.ChipID
	r.PlatformFromQuote = true
	return nil
}

// platformResponse mirrors the attestation server's PlatformIdentity.
type platformResponse struct {
	PPID               string `json:"ppid"`
	PlatformInstanceID string `json:"platformInstanceId"`
	FMSPC              string `json:"fmspc"`
	ChipID             string `json:"chipId"`
}
