// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// sgxPeer builds a CertInfo whose quote is a raw SGX report carrying mrenclave,
// plus the given custom OID extensions. Mirrors what a real dependency peer
// presents (measurement register + app-id / code-hash OIDs).
func sgxPeer(mrenclave []byte, oids []OidExtension) CertInfo {
	raw := make([]byte, SGXReportSize)
	copy(raw[SGXReportMRENCLAVEOff:SGXReportMRENCLAVEEnd], mrenclave)
	return CertInfo{
		Quote:      &QuoteInfo{OID: OidSGXQuote, Raw: raw},
		CustomOids: oids,
	}
}

func mre(b byte) []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = b
	}
	return m
}

func TestEncodeDependencySetDeterministic(t *testing.T) {
	// Two sets with the same logical content but different declaration order
	// (entries, measurements, and required OIDs all shuffled) must encode equal.
	a := DependencySet{Entries: []DependencyEntry{
		{
			AppID:        "bbb",
			Measurements: []DepMeasurement{{SGX: "22"}, {SGX: "11"}},
			RequiredOids: []ExpectedOid{{OID: OidWorkloadAppID, ExpectedValue: []byte("bbb")}, {OID: OidWorkloadCodeHash, ExpectedValue: []byte("hashB")}},
		},
		{
			AppID:        "aaa",
			Measurements: []DepMeasurement{{SGX: "33"}},
			RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("hashA")}},
		},
	}}
	b := DependencySet{Entries: []DependencyEntry{
		{
			AppID:        "aaa",
			Measurements: []DepMeasurement{{SGX: "33"}},
			RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("hashA")}},
		},
		{
			AppID:        "bbb",
			Measurements: []DepMeasurement{{SGX: "11"}, {SGX: "22"}},
			RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("hashB")}, {OID: OidWorkloadAppID, ExpectedValue: []byte("bbb")}},
		},
	}}
	if !bytes.Equal(EncodeDependencySet(a), EncodeDependencySet(b)) {
		t.Fatal("encoding is not order-independent")
	}
}

func TestDependencySetRoundTrip(t *testing.T) {
	set := DependencySet{Entries: []DependencyEntry{
		{
			AppID: "confidential-ai",
			Measurements: []DepMeasurement{
				{SGX: "abcd"},
				{TDX: &DepTdxMeasurement{MRTD: "aa", RTMR1: "bb", RTMR2: "cc"}},
			},
			RequiredOids:   []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte{0xde, 0xad}}},
			FoldedIdentity: "00ff",
		},
	}}
	dec, err := DecodeDependencySet(EncodeDependencySet(set))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(EncodeDependencySet(dec), EncodeDependencySet(set)) {
		t.Fatal("round-trip changed the canonical encoding")
	}
}

func TestDecodeRejectsTruncated(t *testing.T) {
	enc := EncodeDependencySet(DependencySet{Entries: []DependencyEntry{{AppID: "x", Measurements: []DepMeasurement{{SGX: "11"}}}}})
	if _, err := DecodeDependencySet(enc[:len(enc)-1]); err == nil {
		t.Fatal("expected error on truncated encoding")
	}
}

func TestFoldIdentityRipplesOnNestedChange(t *testing.T) {
	// A depends on B. B's own subtree changes (its FoldedIdentity moves).
	// A's folded identity MUST change, even though A's own code/measurement did
	// not — this is the depth-soundness property.
	own := []string{"sgx:" + hex.EncodeToString(mre(0xA1))}
	ownOids := []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("A-code")}}

	depB := func(folded string) DependencySet {
		return DependencySet{Entries: []DependencyEntry{{
			AppID:          "B",
			Measurements:   []DepMeasurement{{SGX: hex.EncodeToString(mre(0xB2))}},
			RequiredOids:   []ExpectedOid{{OID: OidWorkloadAppID, ExpectedValue: []byte("B")}},
			FoldedIdentity: folded,
		}}}
	}

	id1 := FoldIdentityHex(own, ownOids, depB("1111"))
	id2 := FoldIdentityHex(own, ownOids, depB("2222")) // B's subtree changed
	if id1 == id2 {
		t.Fatal("folded identity did not ripple when a nested dependency changed")
	}

	// Same inputs → same identity (stable).
	if FoldIdentityHex(own, ownOids, depB("1111")) != id1 {
		t.Fatal("folded identity is not stable for identical inputs")
	}
}

func TestMatchDependencyAcceptsPinnedPeer(t *testing.T) {
	mreB := mre(0xB2)
	peer := sgxPeer(mreB, []OidExtension{
		{OID: OidWorkloadAppID, Value: []byte("B")},
		{OID: OidWorkloadCodeHash, Value: []byte("B-code")},
	})
	entry := DependencyEntry{
		AppID:        "B",
		Measurements: []DepMeasurement{{SGX: hex.EncodeToString(mreB)}},
		RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("B-code")}},
	}
	if err := MatchDependency(peer, TeeTypeSGX, entry); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
}

func TestMatchDependencyFailsClosedOnMeasurementMismatch(t *testing.T) {
	peer := sgxPeer(mre(0xEE), []OidExtension{{OID: OidWorkloadCodeHash, Value: []byte("B-code")}}) // rogue measurement
	entry := DependencyEntry{
		AppID:        "B",
		Measurements: []DepMeasurement{{SGX: hex.EncodeToString(mre(0xB2))}},
		RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("B-code")}},
	}
	if err := MatchDependency(peer, TeeTypeSGX, entry); err == nil {
		t.Fatal("expected fail-closed on measurement mismatch")
	}
}

func TestMatchDependencyFailsClosedOnMissingOid(t *testing.T) {
	mreB := mre(0xB2)
	peer := sgxPeer(mreB, []OidExtension{{OID: OidWorkloadAppID, Value: []byte("B")}}) // code hash absent
	entry := DependencyEntry{
		AppID:        "B",
		Measurements: []DepMeasurement{{SGX: hex.EncodeToString(mreB)}},
		RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("B-code")}},
	}
	if err := MatchDependency(peer, TeeTypeSGX, entry); err == nil {
		t.Fatal("expected fail-closed on missing required OID")
	}
}

func TestMatchDependencyFailsClosedWithoutQuote(t *testing.T) {
	peer := CertInfo{CustomOids: []OidExtension{{OID: OidWorkloadCodeHash, Value: []byte("B-code")}}}
	entry := DependencyEntry{AppID: "B", Measurements: []DepMeasurement{{SGX: hex.EncodeToString(mre(0xB2))}}}
	if err := MatchDependency(peer, TeeTypeSGX, entry); err == nil {
		t.Fatal("expected fail-closed when peer carries no quote")
	}
}

func TestVerifyPeerIsDependency(t *testing.T) {
	mreB := mre(0xB2)
	// OID 3.6 carries the raw app-id bytes on the wire; a dependency set
	// declares the app-id in the canonical lowercase-hex form (what the
	// control plane and the JSON authoring tools use). AppIDFromCert
	// bridges the two by hex-encoding, so the pinned entry is hex.
	appIDBytes := []byte("B")
	set := DependencySet{Entries: []DependencyEntry{{
		AppID:        hex.EncodeToString(appIDBytes),
		Measurements: []DepMeasurement{{SGX: hex.EncodeToString(mreB)}},
		RequiredOids: []ExpectedOid{{OID: OidWorkloadCodeHash, ExpectedValue: []byte("B-code")}},
	}}}

	good := sgxPeer(mreB, []OidExtension{
		{OID: OidWorkloadAppID, Value: appIDBytes},
		{OID: OidWorkloadCodeHash, Value: []byte("B-code")},
	})
	if err := VerifyPeerIsDependency(good, TeeTypeSGX, set); err != nil {
		t.Fatalf("expected declared dependency to verify, got %v", err)
	}

	// A genuine enclave with a valid quote but an app-id we never pinned.
	rogue := sgxPeer(mre(0xCC), []OidExtension{{OID: OidWorkloadAppID, Value: []byte("C")}})
	if err := VerifyPeerIsDependency(rogue, TeeTypeSGX, set); err == nil {
		t.Fatal("expected fail-closed for an undeclared dependency app-id")
	}

	// No app-id at all.
	anon := sgxPeer(mreB, nil)
	if err := VerifyPeerIsDependency(anon, TeeTypeSGX, set); err == nil {
		t.Fatal("expected fail-closed when peer has no app-id")
	}
}
