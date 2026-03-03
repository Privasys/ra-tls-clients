// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

package vault

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestShamirSplitAndReconstruct(t *testing.T) {
	secret := []byte("super secret vault data")
	shares, err := ShamirSplit(secret, 3, 5)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}

	// Any 3 of 5 shares should reconstruct.
	for _, combo := range [][]*Share{
		{shares[0], shares[1], shares[2]},
		{shares[0], shares[2], shares[4]},
		{shares[1], shares[3], shares[4]},
		{shares[2], shares[3], shares[4]},
	} {
		result, err := ShamirReconstruct(combo)
		if err != nil {
			t.Fatalf("reconstruct: %v", err)
		}
		if !bytes.Equal(result, secret) {
			t.Fatalf("expected %q, got %q", secret, result)
		}
	}
}

func TestShamirThreshold2(t *testing.T) {
	secret := []byte{0xff, 0x00, 0xab}
	shares, err := ShamirSplit(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	for i := 0; i < 3; i++ {
		for j := i + 1; j < 3; j++ {
			result, err := ShamirReconstruct([]*Share{shares[i], shares[j]})
			if err != nil {
				t.Fatalf("reconstruct(%d,%d): %v", i, j, err)
			}
			if !bytes.Equal(result, secret) {
				t.Fatalf("pair (%d,%d): expected %x, got %x", i, j, secret, result)
			}
		}
	}
}

func TestShamirInsufficientShares(t *testing.T) {
	secret := []byte("test")
	shares, err := ShamirSplit(secret, 3, 5)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// Only 2 shares should not reconstruct correctly.
	result, err := ShamirReconstruct([]*Share{shares[0], shares[1]})
	if err != nil {
		// Error is acceptable.
		return
	}
	// No error, but result should be wrong.
	if bytes.Equal(result, secret) {
		t.Fatal("expected wrong result with insufficient shares")
	}
}

func TestShamirShareSerialization(t *testing.T) {
	secret := []byte("roundtrip")
	shares, err := ShamirSplit(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	for _, s := range shares {
		b := ShareToBytes(s)
		s2, err := ShareFromBytes(b)
		if err != nil {
			t.Fatalf("from_bytes: %v", err)
		}
		if s.X != s2.X || !bytes.Equal(s.Data, s2.Data) {
			t.Fatalf("serialization roundtrip failed for x=%d", s.X)
		}
	}
}

func TestShamirFromBytesErrors(t *testing.T) {
	_, err := ShareFromBytes([]byte{})
	if err == nil {
		t.Fatal("expected error for empty bytes")
	}

	_, err = ShareFromBytes([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for x=0")
	}
}

func TestShamirSplitErrors(t *testing.T) {
	// threshold < 2
	_, err := ShamirSplit([]byte("a"), 1, 3)
	if err == nil {
		t.Fatal("expected error for threshold < 2")
	}

	// threshold > num_shares
	_, err = ShamirSplit([]byte("a"), 4, 3)
	if err == nil {
		t.Fatal("expected error for threshold > num_shares")
	}

	// empty secret
	_, err = ShamirSplit([]byte{}, 2, 3)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}

	// num_shares > 255
	_, err = ShamirSplit([]byte("a"), 2, 256)
	if err == nil {
		t.Fatal("expected error for num_shares > 255")
	}
}

func TestShamirLargeSecret(t *testing.T) {
	secret := make([]byte, 4096)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand: %v", err)
	}

	shares, err := ShamirSplit(secret, 5, 10)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// Use shares 0, 2, 4, 6, 8.
	subset := []*Share{shares[0], shares[2], shares[4], shares[6], shares[8]}
	result, err := ShamirReconstruct(subset)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !bytes.Equal(result, secret) {
		t.Fatal("large secret reconstruction failed")
	}
}

func TestGF256Basics(t *testing.T) {
	// Additive identity
	if gfAdd(0x53, 0x00) != 0x53 {
		t.Fatal("add identity failed")
	}
	// Self-inverse
	if gfAdd(0x53, 0x53) != 0 {
		t.Fatal("self-inverse failed")
	}
	// Multiplicative identity
	if gfMul(0x53, 1) != 0x53 {
		t.Fatal("mul identity failed")
	}
	// Multiply by zero
	if gfMul(0x53, 0) != 0 {
		t.Fatal("mul by zero failed")
	}
	// Inverse: a * inv(a) == 1
	a := byte(0x53)
	inv := gfInv(a)
	if gfMul(a, inv) != 1 {
		t.Fatalf("inv failed: %x * %x = %x", a, inv, gfMul(a, inv))
	}
	// inv(1) == 1
	if gfInv(1) != 1 {
		t.Fatalf("inv(1) = %x, expected 1", gfInv(1))
	}
}
