// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"testing"
)

// makeTDXQuote builds a minimal raw TDX quote with the three identity registers
// set, so verifyMeasurements can be exercised without real hardware.
func makeTDXQuote(mrtd, rtmr1, rtmr2 byte) []byte {
	raw := make([]byte, TDXQuoteMinSize)
	copy(raw[TDXQuoteMRTDOff:TDXQuoteMRTDEnd], bytes.Repeat([]byte{mrtd}, 48))
	copy(raw[TDXQuoteRTMR1Off:TDXQuoteRTMR1End], bytes.Repeat([]byte{rtmr1}, 48))
	copy(raw[TDXQuoteRTMR2Off:TDXQuoteRTMR2End], bytes.Repeat([]byte{rtmr2}, 48))
	return raw
}

// TestTDXRequiresMRTDAndBothRTMRs mirrors the vault TEE-policy rule: a TDX
// identity is MRTD AND RTMR1 AND RTMR2 — the same firmware (MRTD) running a
// different guest build (different RTMR1/2) must be rejected.
func TestTDXRequiresMRTDAndBothRTMRs(t *testing.T) {
	quote := makeTDXQuote(0xAA, 0xBB, 0xCC)
	full := &VerificationPolicy{
		TEE:   TeeTypeTDX,
		MRTD:  bytes.Repeat([]byte{0xAA}, 48),
		RTMR1: bytes.Repeat([]byte{0xBB}, 48),
		RTMR2: bytes.Repeat([]byte{0xCC}, 48),
	}
	if err := verifyMeasurements(quote, full); err != nil {
		t.Fatalf("matching MRTD+RTMR1+RTMR2 should pass, got %v", err)
	}

	// Same MRTD firmware, different guest build (RTMR1/2) must be rejected.
	if err := verifyMeasurements(makeTDXQuote(0xAA, 0xEE, 0xFF), full); err == nil {
		t.Fatal("same MRTD but different RTMR1/2 must be rejected")
	}
	// Wrong RTMR1 only.
	if err := verifyMeasurements(makeTDXQuote(0xAA, 0xEE, 0xCC), full); err == nil {
		t.Fatal("wrong RTMR1 must be rejected")
	}
	// Wrong RTMR2 only.
	if err := verifyMeasurements(makeTDXQuote(0xAA, 0xBB, 0xFF), full); err == nil {
		t.Fatal("wrong RTMR2 must be rejected")
	}
}

// TestMeasurementPolicyTDXPopulatesAllThree proves measurementPolicy pins the
// full triple from a DependencyEntry measurement, so MatchDependency enforces
// RTMR1/2 too.
func TestMeasurementPolicyTDXPopulatesAllThree(t *testing.T) {
	m := DepMeasurement{TDX: &DepTdxMeasurement{
		MRTD:  hexRepeat(0xAA),
		RTMR1: hexRepeat(0xBB),
		RTMR2: hexRepeat(0xCC),
	}}
	pol, err := measurementPolicy(TeeTypeTDX, m)
	if err != nil {
		t.Fatalf("measurementPolicy failed: %v", err)
	}
	if len(pol.MRTD) != 48 || len(pol.RTMR1) != 48 || len(pol.RTMR2) != 48 {
		t.Fatalf("expected all three 48-byte registers, got MRTD=%d RTMR1=%d RTMR2=%d",
			len(pol.MRTD), len(pol.RTMR1), len(pol.RTMR2))
	}
	if err := verifyMeasurements(makeTDXQuote(0xAA, 0xBB, 0xCC), pol); err != nil {
		t.Fatalf("policy from measurementPolicy should verify a matching quote: %v", err)
	}

	// An incomplete measurement (missing RTMRs) must be rejected, not silently
	// downgraded to MRTD-only.
	if _, err := measurementPolicy(TeeTypeTDX, DepMeasurement{TDX: &DepTdxMeasurement{MRTD: hexRepeat(0xAA)}}); err == nil {
		t.Fatal("measurement missing RTMR1/2 must be rejected")
	}
}

// hexRepeat returns the hex string of 48 repeated bytes.
func hexRepeat(b byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 96)
	for i := 0; i < 48; i++ {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
