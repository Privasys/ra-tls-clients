// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Package vault provides a high-level vault client with Shamir Secret
// Sharing for distributing secrets across multiple SGX/TDX vault instances
// via RA-TLS connections.
//
// # Architecture
//
// The vault client splits secrets using Shamir's threshold scheme and
// stores one share per vault endpoint.  Reconstruction requires any
// N-of-M shares, providing both redundancy and security: compromising
// fewer than N vaults reveals nothing about the secret.
//
// This package imports the ratls package for RA-TLS transport
// (Connect, SendData, VerifyCertificate).
package vault

// Shamir Secret Sharing over GF(2^8).
//
// Splits a secret into n shares such that any t (threshold) shares can
// reconstruct the original, but fewer reveal nothing.
//
// Field: GF(2^8) with irreducible polynomial p(x) = x^8 + x^4 + x^3 + x + 1
// (0x11b, same as AES) and generator g = 3.

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// ---------------------------------------------------------------------------
//  GF(2^8) tables — computed at init time
// ---------------------------------------------------------------------------

var gfExp [256]byte // gfExp[i] = g^i for i in 0..254, gfExp[255] = gfExp[0]
var gfLog [256]byte // gfLog[x] = i such that g^i = x (log[0] undefined)

func init() {
	var val uint16 = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(val)
		gfLog[val] = byte(i)

		// val *= 3 in GF(2^8): val*3 = val*2 XOR val
		doubled := val << 1
		if doubled&0x100 != 0 {
			doubled ^= 0x11b
		}
		val = doubled ^ val
	}
	gfExp[255] = gfExp[0] // g^255 = g^0 = 1 (group order 255)
}

func gfAdd(a, b byte) byte { return a ^ b }

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	logSum := uint16(gfLog[a]) + uint16(gfLog[b])
	return gfExp[logSum%255]
}

func gfInv(a byte) byte {
	if a == 0 {
		panic("gfInv(0): no inverse for zero in GF(256)")
	}
	return gfExp[255-uint16(gfLog[a])]
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

// Share is a single Shamir share: evaluation point X (1–255) and per-byte
// evaluated data (same length as the original secret).
type Share struct {
	X    byte
	Data []byte
}

// ShareToBytes serialises a share: [X, Data...]
func ShareToBytes(s *Share) []byte {
	buf := make([]byte, 1+len(s.Data))
	buf[0] = s.X
	copy(buf[1:], s.Data)
	return buf
}

// ShareFromBytes deserialises [X, Data...].
func ShareFromBytes(b []byte) (*Share, error) {
	if len(b) < 2 {
		return nil, errors.New("share too short (need at least x + 1 data byte)")
	}
	if b[0] == 0 {
		return nil, errors.New("share X must be non-zero")
	}
	data := make([]byte, len(b)-1)
	copy(data, b[1:])
	return &Share{X: b[0], Data: data}, nil
}

// ShamirSplit splits a secret into numShares shares with the given threshold.
// Any threshold shares reconstruct the secret; fewer reveal nothing.
//
// Constraints: threshold >= 2, numShares >= threshold, numShares <= 255,
// secret must not be empty.
func ShamirSplit(secret []byte, threshold, numShares int) ([]*Share, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be >= 2")
	}
	if numShares < threshold {
		return nil, errors.New("numShares must be >= threshold")
	}
	if numShares > 255 {
		return nil, errors.New("max 255 shares (GF(256) constraint)")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret must not be empty")
	}

	shares := make([]*Share, numShares)
	for i := 0; i < numShares; i++ {
		shares[i] = &Share{
			X:    byte(i + 1),
			Data: make([]byte, 0, len(secret)),
		}
	}

	coeffs := make([]byte, threshold-1)
	for _, b := range secret {
		// Random polynomial of degree (threshold-1): coeffs[0]=secret_byte, rest random
		if _, err := rand.Read(coeffs); err != nil {
			return nil, fmt.Errorf("RNG failed: %w", err)
		}
		for _, share := range shares {
			val := evalPoly(b, coeffs, share.X)
			share.Data = append(share.Data, val)
		}
	}

	return shares, nil
}

// ShamirReconstruct reconstructs the original secret from threshold (or more) shares
// using Lagrange interpolation at x = 0.
func ShamirReconstruct(shares []*Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}
	dataLen := len(shares[0].Data)
	for _, s := range shares[1:] {
		if len(s.Data) != dataLen {
			return nil, errors.New("all shares must have the same data length")
		}
	}

	// Check for duplicate X
	seen := [256]bool{}
	for _, s := range shares {
		if seen[s.X] {
			return nil, fmt.Errorf("duplicate share X=%d", s.X)
		}
		seen[s.X] = true
	}

	xs := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s.X
	}

	secret := make([]byte, dataLen)
	ys := make([]byte, len(shares))
	for j := 0; j < dataLen; j++ {
		for i, s := range shares {
			ys[i] = s.Data[j]
		}
		secret[j] = lagrangeAtZero(xs, ys)
	}

	return secret, nil
}

// ---------------------------------------------------------------------------
//  Internal
// ---------------------------------------------------------------------------

// evalPoly evaluates constant + coeffs[0]*x + coeffs[1]*x^2 + ... using Horner.
func evalPoly(constant byte, coeffs []byte, x byte) byte {
	var val byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		val = gfAdd(gfMul(val, x), coeffs[i])
	}
	return gfAdd(gfMul(val, x), constant)
}

// lagrangeAtZero computes Lagrange interpolation at x=0 in GF(2^8).
func lagrangeAtZero(xs, ys []byte) byte {
	n := len(xs)
	var result byte
	for i := 0; i < n; i++ {
		var num byte = 1
		var den byte = 1
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			num = gfMul(num, xs[j])               // 0 - xs[j] = xs[j] in GF(2^8)
			den = gfMul(den, gfAdd(xs[i], xs[j])) // xs[i] - xs[j] = xs[i] ^ xs[j]
		}
		basis := gfMul(num, gfInv(den))
		result = gfAdd(result, gfMul(ys[i], basis))
	}
	return result
}
