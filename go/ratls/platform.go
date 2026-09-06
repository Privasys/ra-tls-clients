// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
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

// platformAllowed checks the platform identity the attestation server
// reported against the policy's allow-list. An empty list allows every
// platform; a non-empty list with no reported identity fails closed.
func platformAllowed(r *QuoteVerificationResult, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	id := normalizePlatformID(r.PlatformID())
	if id == "" {
		return fmt.Errorf("platform allow-list: the attestation server reported no platform identity (upgrade the server or drop AllowedPlatformIDs)")
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

// platformResponse mirrors the attestation server's PlatformIdentity.
type platformResponse struct {
	PPID               string `json:"ppid"`
	PlatformInstanceID string `json:"platformInstanceId"`
	FMSPC              string `json:"fmspc"`
	ChipID             string `json:"chipId"`
}
