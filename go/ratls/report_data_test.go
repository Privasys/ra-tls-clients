// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
)

// Same fixed P-256 EC point as the Rust test (secp256r1 generator).
var testECPointX, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
var testECPointY, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

// Same 32-byte challenge nonce as the Rust test.
var testNonce, _ = hex.DecodeString("deadbeefcafebabe01020304050607081020304050607080aabbccddeeff0011")

func TestSPKIDERMatchesRust(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     testECPointX,
		Y:     testECPointY,
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	spkiHex := hex.EncodeToString(spkiDER)
	t.Logf("SPKI DER (%d bytes): %s", len(spkiDER), spkiHex)

	// Must match Rust's build_p256_spki_der output exactly.
	const expectedSPKI = "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	if spkiHex != expectedSPKI {
		t.Errorf("SPKI DER mismatch:\n  go:   %s\n  rust: %s", spkiHex, expectedSPKI)
	}

	if len(spkiDER) != 91 {
		t.Errorf("expected 91 bytes, got %d", len(spkiDER))
	}
}

func TestPubKeySHA256MatchesRust(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     testECPointX,
		Y:     testECPointY,
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	h := sha256.Sum256(spkiDER)
	pkHashHex := hex.EncodeToString(h[:])
	t.Logf("pubkey_sha256: %s", pkHashHex)

	// Must match Rust's SHA-256(SPKI DER).
	const expectedHash = "5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3"
	if pkHashHex != expectedHash {
		t.Errorf("pubkey_sha256 mismatch:\n  go:   %s\n  rust: %s", pkHashHex, expectedHash)
	}
}

func TestReportDataMatchesRust(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     testECPointX,
		Y:     testECPointY,
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	// Step 1: SHA-256(SPKI DER)
	pkHash := sha256.Sum256(spkiDER)
	t.Logf("pubkey_sha256: %s", hex.EncodeToString(pkHash[:]))

	// Step 2: SHA-512(pkHash || nonce)
	preimage := make([]byte, 0, 32+len(testNonce))
	preimage = append(preimage, pkHash[:]...)
	preimage = append(preimage, testNonce...)
	rd := sha512.Sum512(preimage)

	rdHex := hex.EncodeToString(rd[:])
	t.Logf("report_data:   %s", rdHex)
	t.Logf("nonce:         %s", hex.EncodeToString(testNonce))

	// Must match Rust's compute_report_data_hash output.
	const expectedRD = "4e7417a5a805d06851005163eca7e7b05f511af48ac1b9f53f87aacc3844eb103451fc804ae19f0635cf67e78cbdeecf47220d594a90d6e4eaba201df46a43d8"
	if rdHex != expectedRD {
		t.Errorf("report_data mismatch:\n  go:   %s\n  rust: %s", rdHex, expectedRD)
	}
}

// TestFrontendVerification simulates exactly what the browser does:
// given pubkey_sha256 (hex) and challenge (hex), compute SHA-512 and compare.
func TestFrontendVerification(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     testECPointX,
		Y:     testECPointY,
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	// This is what InspectCertificate produces
	pkHash := sha256.Sum256(spkiDER)
	pubkeySha256Hex := hex.EncodeToString(pkHash[:])
	nonceHex := hex.EncodeToString(testNonce)

	// Now simulate the frontend: decode hex, concat, SHA-512
	pubkeyBytes, _ := hex.DecodeString(pubkeySha256Hex)
	nonceBytes, _ := hex.DecodeString(nonceHex)
	preimage := append(pubkeyBytes, nonceBytes...)
	rd := sha512.Sum512(preimage)
	computed := hex.EncodeToString(rd[:])

	t.Logf("Frontend verification:")
	t.Logf("  pubkey_sha256: %s", pubkeySha256Hex)
	t.Logf("  challenge:     %s", nonceHex)
	t.Logf("  computed:      %s", computed)

	// This must equal the enclave's report_data
	const expectedRD = "4e7417a5a805d06851005163eca7e7b05f511af48ac1b9f53f87aacc3844eb103451fc804ae19f0635cf67e78cbdeecf47220d594a90d6e4eaba201df46a43d8"
	if computed != expectedRD {
		t.Errorf("frontend verification mismatch:\n  computed: %s\n  expected: %s", computed, expectedRD)
	}
}
