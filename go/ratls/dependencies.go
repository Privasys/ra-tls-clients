// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

// Attested cross-enclave dependencies.
//
// A workload that depends on other enclaves (for example a service that calls a
// confidential-inference enclave) is pinned to a fixed set of dependency
// identities. The runtime carries that set in the certificate extension
// OidAttestedDependencySet (65230.6.1) and refuses, fail-closed, to complete an
// RA-TLS handshake with a peer that does not match the pinned identity for the
// dependency being dialled. The extension is written by the trusted runtime, so
// the advertised set and the enforced set are one object: an app cannot claim a
// dependency it is not constrained to use, nor use one it did not advertise.
//
// A dependency identity is the SAME tuple used to verify any app — measurement
// registers plus required OID values (code hash 65230.3.2, app-id 65230.3.6).
// Verification therefore reuses the ordinary certificate matcher, not a parallel
// one.
//
// Depth soundness comes from the identity fold: a dependency entry commits to
// the dependency's OWN dependency set via FoldedIdentity, so a change deep in the
// tree changes the identity a dependent is pinned to. Enforcement stays a single
// direct-edge check at every hop; the recursion lives in the pinned identity, not
// in the verifier. See FoldIdentity.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// domainFoldIdentity separates the fold preimage from any other SHA-256 use.
const domainFoldIdentity = "privasys-app-identity-v1"

// DepTdxMeasurement is a TDX measurement triple (all lowercase hex).
type DepTdxMeasurement struct {
	MRTD  string `json:"mrtd"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// DepMeasurement is one allowed measurement for a dependency, mirroring the
// vault's Measurement enum. Exactly one of SGX / TDX is set.
type DepMeasurement struct {
	// SGX is a lowercase-hex MRENCLAVE (SGX enclaves). Empty when TDX is set.
	SGX string `json:"sgx,omitempty"`
	// TDX is an MRTD+RTMR triple (TDX VMs). Nil when SGX is set.
	TDX *DepTdxMeasurement `json:"tdx,omitempty"`
}

// canonical returns a stable string form used for sorting and for the fold
// preimage. It is identical across SDKs.
func (m DepMeasurement) canonical() string {
	if m.TDX != nil {
		return "tdx:" + strings.ToLower(m.TDX.MRTD) + ":" + strings.ToLower(m.TDX.RTMR1) + ":" + strings.ToLower(m.TDX.RTMR2)
	}
	return "sgx:" + strings.ToLower(m.SGX)
}

// DependencyEntry pins one DIRECT dependency: the identity a dependent enclave is
// allowed to talk to for that dependency app.
type DependencyEntry struct {
	// AppID is the management app-id of the dependency (matches the peer's
	// OID 65230.3.6 value). It is how a dependent selects which entry applies to
	// the peer it is dialling, and the key the wallet caches an approval under.
	AppID string `json:"app_id"`
	// Measurements is the any-of set of allowed measurement registers. A peer
	// matches when it satisfies at least one.
	Measurements []DepMeasurement `json:"measurements"`
	// RequiredOids are OID values the peer's certificate must carry verbatim
	// (typically code hash 65230.3.2 and app-id 65230.3.6).
	RequiredOids []ExpectedOid `json:"required_oids"`
	// FoldedIdentity is the lowercase-hex commitment to THIS dependency's own
	// transitive dependency subtree (its FoldIdentity output). Empty for a leaf
	// dependency that declares no dependencies of its own. Because a parent's
	// FoldIdentity folds in this value, a change anywhere in the subtree changes
	// the parent's pinned identity — which is what makes direct-edge enforcement
	// sound at depth.
	FoldedIdentity string `json:"folded_identity,omitempty"`
}

// DependencySet is a workload's ordered set of direct attested dependencies.
type DependencySet struct {
	Entries []DependencyEntry `json:"entries"`
}

// normalise sorts the set into canonical order: entries by app-id, each entry's
// measurements by canonical form, and required OIDs by (oid, value). Encoding and
// folding both operate on the normalised form so the output is independent of the
// order in which dependencies were declared.
func (s DependencySet) normalise() DependencySet {
	out := DependencySet{Entries: make([]DependencyEntry, len(s.Entries))}
	copy(out.Entries, s.Entries)
	for i := range out.Entries {
		e := &out.Entries[i]
		ms := make([]DepMeasurement, len(e.Measurements))
		copy(ms, e.Measurements)
		sort.Slice(ms, func(a, b int) bool { return ms[a].canonical() < ms[b].canonical() })
		e.Measurements = ms
		os := make([]ExpectedOid, len(e.RequiredOids))
		copy(os, e.RequiredOids)
		sort.Slice(os, func(a, b int) bool {
			if os[a].OID != os[b].OID {
				return os[a].OID < os[b].OID
			}
			return string(os[a].ExpectedValue) < string(os[b].ExpectedValue)
		})
		e.RequiredOids = os
	}
	sort.Slice(out.Entries, func(a, b int) bool { return out.Entries[a].AppID < out.Entries[b].AppID })
	return out
}

// canonicalWriter builds an unambiguous, length-prefixed byte stream. The same
// grammar is reproduced byte-for-byte in every SDK, so the OID value and the fold
// preimage are portable and deterministic without depending on a JSON or CBOR
// library.
type canonicalWriter struct{ buf []byte }

func (w *canonicalWriter) u32(n int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	w.buf = append(w.buf, b[:]...)
}

func (w *canonicalWriter) bytes(b []byte) {
	w.u32(len(b))
	w.buf = append(w.buf, b...)
}

func (w *canonicalWriter) str(s string) { w.bytes([]byte(s)) }

func (s DependencySet) writeCanonical(w *canonicalWriter) {
	n := s.normalise()
	w.u32(len(n.Entries))
	for _, e := range n.Entries {
		w.str(e.AppID)
		w.u32(len(e.Measurements))
		for _, m := range e.Measurements {
			w.str(m.canonical())
		}
		w.u32(len(e.RequiredOids))
		for _, o := range e.RequiredOids {
			w.str(o.OID)
			w.bytes(o.ExpectedValue)
		}
		w.str(strings.ToLower(e.FoldedIdentity))
	}
}

// EncodeDependencySet returns the canonical byte encoding placed in the
// OidAttestedDependencySet certificate extension. It is deterministic: the same
// logical set always encodes to the same bytes regardless of declaration order.
func EncodeDependencySet(s DependencySet) []byte {
	w := &canonicalWriter{}
	s.writeCanonical(w)
	return w.buf
}

// DecodeDependencySet parses the canonical encoding. Measurement and OID-value
// details are collapsed to their canonical string forms; DecodeDependencySet is
// intended for inspection and round-trip checks, not for reconstructing typed
// measurements (verification uses the encoded bytes and the live certificate).
func DecodeDependencySet(b []byte) (DependencySet, error) {
	r := &canonicalReader{buf: b}
	n, err := r.u32()
	if err != nil {
		return DependencySet{}, err
	}
	set := DependencySet{Entries: make([]DependencyEntry, 0, n)}
	for i := uint32(0); i < n; i++ {
		var e DependencyEntry
		if e.AppID, err = r.str(); err != nil {
			return DependencySet{}, err
		}
		mc, err := r.u32()
		if err != nil {
			return DependencySet{}, err
		}
		for j := uint32(0); j < mc; j++ {
			s, err := r.str()
			if err != nil {
				return DependencySet{}, err
			}
			e.Measurements = append(e.Measurements, decodeCanonicalMeasurement(s))
		}
		oc, err := r.u32()
		if err != nil {
			return DependencySet{}, err
		}
		for j := uint32(0); j < oc; j++ {
			oid, err := r.str()
			if err != nil {
				return DependencySet{}, err
			}
			val, err := r.bytes()
			if err != nil {
				return DependencySet{}, err
			}
			e.RequiredOids = append(e.RequiredOids, ExpectedOid{OID: oid, ExpectedValue: val})
		}
		if e.FoldedIdentity, err = r.str(); err != nil {
			return DependencySet{}, err
		}
		set.Entries = append(set.Entries, e)
	}
	if r.off != len(r.buf) {
		return DependencySet{}, fmt.Errorf("trailing bytes in dependency-set encoding")
	}
	return set, nil
}

func decodeCanonicalMeasurement(s string) DepMeasurement {
	if strings.HasPrefix(s, "tdx:") {
		parts := strings.Split(strings.TrimPrefix(s, "tdx:"), ":")
		m := &DepTdxMeasurement{}
		if len(parts) > 0 {
			m.MRTD = parts[0]
		}
		if len(parts) > 1 {
			m.RTMR1 = parts[1]
		}
		if len(parts) > 2 {
			m.RTMR2 = parts[2]
		}
		return DepMeasurement{TDX: m}
	}
	return DepMeasurement{SGX: strings.TrimPrefix(s, "sgx:")}
}

type canonicalReader struct {
	buf []byte
	off int
}

func (r *canonicalReader) u32() (uint32, error) {
	if r.off+4 > len(r.buf) {
		return 0, fmt.Errorf("dependency-set encoding truncated")
	}
	n := binary.BigEndian.Uint32(r.buf[r.off : r.off+4])
	r.off += 4
	return n, nil
}

func (r *canonicalReader) bytes() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if r.off+int(n) > len(r.buf) {
		return nil, fmt.Errorf("dependency-set encoding truncated")
	}
	b := append([]byte(nil), r.buf[r.off:r.off+int(n)]...)
	r.off += int(n)
	return b, nil
}

func (r *canonicalReader) str() (string, error) {
	b, err := r.bytes()
	return string(b), err
}

// FoldIdentity computes a workload's folded identity:
//
//	identity(X) = SHA-256( domain || measurements(X) || requiredOids(X) || encode(deps(X)) )
//
// Because deps(X) carries each direct dependency's own FoldedIdentity, the result
// transitively commits to the entire dependency subtree while every hop verifies
// only its direct edges. A dependent pins X by this value (typically as the
// FoldedIdentity of its own dependency entry for X), so any change beneath X — a
// swapped sub-dependency, a new measurement — changes what the dependent accepts
// and forces re-approval.
//
// ownMeasurements are the workload's own measurement registers (canonical form,
// e.g. DepMeasurement.canonical()); ownRequiredOids are its own pinned OID values.
func FoldIdentity(ownMeasurements []string, ownRequiredOids []ExpectedOid, deps DependencySet) [32]byte {
	w := &canonicalWriter{}
	w.str(domainFoldIdentity)

	ms := append([]string(nil), ownMeasurements...)
	for i := range ms {
		ms[i] = strings.ToLower(ms[i])
	}
	sort.Strings(ms)
	w.u32(len(ms))
	for _, m := range ms {
		w.str(m)
	}

	os := append([]ExpectedOid(nil), ownRequiredOids...)
	sort.Slice(os, func(a, b int) bool {
		if os[a].OID != os[b].OID {
			return os[a].OID < os[b].OID
		}
		return string(os[a].ExpectedValue) < string(os[b].ExpectedValue)
	})
	w.u32(len(os))
	for _, o := range os {
		w.str(o.OID)
		w.bytes(o.ExpectedValue)
	}

	deps.writeCanonical(w)
	return sha256.Sum256(w.buf)
}

// FoldIdentityHex is FoldIdentity as lowercase hex, the form stored in
// DependencyEntry.FoldedIdentity.
func FoldIdentityHex(ownMeasurements []string, ownRequiredOids []ExpectedOid, deps DependencySet) string {
	h := FoldIdentity(ownMeasurements, ownRequiredOids, deps)
	return hex.EncodeToString(h[:])
}

// MatchDependency reports whether a peer certificate satisfies a single
// dependency entry: its measurement registers match at least one allowed
// measurement AND every required OID is present verbatim. It returns nil on a
// match and a descriptive error otherwise. This is the fail-closed check the
// dialling runtime runs before sending any application data to a dependency.
//
// It reuses the ordinary certificate matcher (verifyMeasurements / the OID check)
// rather than a parallel verifier, so a dependency is verified exactly as any app.
func MatchDependency(peer CertInfo, tee TeeType, entry DependencyEntry) error {
	if peer.Quote == nil || len(peer.Quote.Raw) == 0 {
		return fmt.Errorf("dependency %s: peer certificate carries no quote (fail closed)", entry.AppID)
	}
	if len(entry.Measurements) == 0 {
		return fmt.Errorf("dependency %s: entry pins no measurement (fail closed)", entry.AppID)
	}

	var lastErr error
	matched := false
	for _, m := range entry.Measurements {
		pol, err := measurementPolicy(tee, m)
		if err != nil {
			lastErr = err
			continue
		}
		if err := verifyMeasurements(peer.Quote.Raw, pol); err == nil {
			matched = true
			break
		} else {
			lastErr = err
		}
	}
	if !matched {
		return fmt.Errorf("dependency %s: peer matches no pinned measurement (fail closed): %v", entry.AppID, lastErr)
	}

	if err := verifyExpectedOids(peer.CustomOids, entry.RequiredOids); err != nil {
		return fmt.Errorf("dependency %s: %w", entry.AppID, err)
	}
	return nil
}

// measurementPolicy builds a single-measurement VerificationPolicy so
// MatchDependency can reuse verifyMeasurements for each allowed measurement.
func measurementPolicy(tee TeeType, m DepMeasurement) (*VerificationPolicy, error) {
	pol := &VerificationPolicy{TEE: tee}
	switch tee {
	case TeeTypeSGX:
		b, err := hex.DecodeString(m.SGX)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("invalid SGX MRENCLAVE %q", m.SGX)
		}
		pol.MRENCLAVE = b
	case TeeTypeTDX:
		if m.TDX == nil {
			return nil, fmt.Errorf("TDX measurement missing MRTD triple")
		}
		// A TDX dependency pins the full triple: MRTD + RTMR1 + RTMR2. MRTD
		// alone (the TD firmware) does not identify the guest build, so all
		// three are required — the same rule the vault's TEE policy enforces.
		mrtd, err := hex.DecodeString(m.TDX.MRTD)
		if err != nil || len(mrtd) != 48 {
			return nil, fmt.Errorf("invalid TDX MRTD %q", m.TDX.MRTD)
		}
		rtmr1, err := hex.DecodeString(m.TDX.RTMR1)
		if err != nil || len(rtmr1) != 48 {
			return nil, fmt.Errorf("invalid TDX RTMR1 %q", m.TDX.RTMR1)
		}
		rtmr2, err := hex.DecodeString(m.TDX.RTMR2)
		if err != nil || len(rtmr2) != 48 {
			return nil, fmt.Errorf("invalid TDX RTMR2 %q", m.TDX.RTMR2)
		}
		pol.MRTD = mrtd
		pol.RTMR1 = rtmr1
		pol.RTMR2 = rtmr2
	default:
		return nil, fmt.Errorf("unsupported TEE type for dependency measurement")
	}
	return pol, nil
}

// AppIDFromCert returns the peer's management app-id (OID 65230.3.6) or "" when
// absent. A dependent uses it to select which dependency entry applies to a peer.
func AppIDFromCert(peer CertInfo) string {
	for _, o := range peer.CustomOids {
		if o.OID == OidWorkloadAppID {
			// OID 3.6 carries the app id as the raw 16 bytes (the runtime
			// stamps parseAppID's output). The canonical app-id form used
			// everywhere a dependency is DECLARED — the control plane's
			// attestation profiles, the per-app IdP roles, and the
			// hand/tooling-authored dependency-set JSON — is lowercase hex
			// (AppIDHex). A JSON dependency set cannot even carry the raw
			// bytes (they are not valid UTF-8), so returning the raw string
			// here made the top-level app-id gate unsatisfiable for every
			// real app. Hex-encode so the value matches the declared form.
			return hex.EncodeToString(o.Value)
		}
	}
	return ""
}

// VerifyPeerIsDependency enforces the whole set: it selects the entry whose AppID
// matches the peer's app-id (OID 65230.3.6) and requires the peer to match it. A
// peer whose app-id is not a declared dependency is rejected — a dependent talks
// only to enclaves it has pinned. This is the top-level fail-closed gate.
func VerifyPeerIsDependency(peer CertInfo, tee TeeType, set DependencySet) error {
	appID := AppIDFromCert(peer)
	if appID == "" {
		return fmt.Errorf("peer certificate carries no app-id (OID %s); cannot match a declared dependency (fail closed)", OidWorkloadAppID)
	}
	for _, e := range set.Entries {
		if e.AppID == appID {
			return MatchDependency(peer, tee, e)
		}
	}
	return fmt.Errorf("peer app-id %s is not a declared dependency (fail closed)", appID)
}
