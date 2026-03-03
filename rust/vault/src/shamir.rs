// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Shamir Secret Sharing over GF(2^8).
//!
//! Splits a secret into `n` shares such that any `t` (threshold) shares can
//! reconstruct the original secret, but fewer than `t` shares reveal nothing.
//!
//! The field is GF(2^8) with irreducible polynomial
//! p(x) = x^8 + x^4 + x^3 + x + 1 (0x11b, same as AES) and generator g = 3.
//!
//! # Example
//!
//! ```
//! use vault_client::shamir;
//!
//! let secret = b"my-encryption-key-256bit-value!!";
//! let shares = shamir::split(secret, 3, 10).unwrap();
//!
//! // Any 3 shares can reconstruct:
//! let reconstructed = shamir::reconstruct(&shares[0..3]).unwrap();
//! assert_eq!(&reconstructed, secret);
//!
//! // Different 3 shares also work:
//! let reconstructed2 = shamir::reconstruct(&shares[5..8]).unwrap();
//! assert_eq!(&reconstructed2, secret);
//! ```

use ring::rand::{SecureRandom, SystemRandom};

// ---------------------------------------------------------------------------
//  GF(2^8) arithmetic with irreducible polynomial 0x11b, generator 3
// ---------------------------------------------------------------------------

/// Precomputed tables: (exp_table, log_table).
///
/// - `EXP[i] = g^i` for i in 0..254 (g = 3)
/// - `LOG[x] = i` such that `g^i = x` for x in 1..255
///
/// `LOG[0]` is undefined (kept as 0).  `EXP[255]` is unused (kept as 0).
const TABLES: ([u8; 256], [u8; 256]) = build_tables();
const GF_EXP: [u8; 256] = TABLES.0;
const GF_LOG: [u8; 256] = TABLES.1;

const fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];

    let mut val: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = val as u8;
        log[val as usize] = i as u8;

        // val *= 3 in GF(2^8):  val*3 = val*2 XOR val
        let mut doubled = val << 1;
        if doubled & 0x100 != 0 {
            doubled ^= 0x11b;
        }
        val = doubled ^ val;
        i += 1;
    }
    // exp[255] = exp[0] = 1  (group order is 255, so g^255 = g^0 = 1)
    exp[255] = exp[0];
    (exp, log)
}

/// Addition in GF(2^8) = XOR.
#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(2^8) using log/exp tables.
#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_sum = GF_LOG[a as usize] as u16 + GF_LOG[b as usize] as u16;
    GF_EXP[(log_sum % 255) as usize]
}

/// Multiplicative inverse in GF(2^8).
///
/// # Panics
///
/// Panics if `a == 0` (zero has no inverse).
#[inline]
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "no inverse for 0 in GF(256)");
    GF_EXP[(255 - GF_LOG[a as usize] as u16) as usize]
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// A single Shamir share: evaluation point `x` (1–255) and the
/// per-byte evaluations.
///
/// Serialisation format (for storage/transport):
/// `[x, data[0], data[1], ..., data[n-1]]`
#[derive(Debug, Clone)]
pub struct Share {
    /// Evaluation point (1–255).  Must be unique across shares.
    pub x: u8,
    /// Evaluated bytes — same length as the original secret.
    pub data: Vec<u8>,
}

impl Share {
    /// Serialise to bytes: `[x, data...]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.data.len());
        buf.push(self.x);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialise from bytes: `[x, data...]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 2 {
            return Err("share too short (need at least x + 1 data byte)".into());
        }
        let x = bytes[0];
        if x == 0 {
            return Err("share x must be non-zero".into());
        }
        Ok(Self {
            x,
            data: bytes[1..].to_vec(),
        })
    }
}

/// Split `secret` into `num_shares` shares with the given `threshold`.
///
/// Any `threshold` shares can reconstruct the secret; fewer reveal nothing
/// about any individual byte.
///
/// # Constraints
///
/// - `threshold >= 2`
/// - `num_shares >= threshold`
/// - `num_shares <= 255`
/// - `secret` must not be empty
///
/// # Errors
///
/// Returns an error if constraints are violated or the system RNG fails.
pub fn split(secret: &[u8], threshold: usize, num_shares: usize) -> Result<Vec<Share>, String> {
    if threshold < 2 {
        return Err("threshold must be >= 2".into());
    }
    if num_shares < threshold {
        return Err("num_shares must be >= threshold".into());
    }
    if num_shares > 255 {
        return Err("max 255 shares (GF(256) constraint)".into());
    }
    if secret.is_empty() {
        return Err("secret must not be empty".into());
    }

    let rng = SystemRandom::new();

    // Pre-allocate shares with x = 1..=num_shares
    let mut shares: Vec<Share> = (1..=num_shares)
        .map(|i| Share {
            x: i as u8,
            data: Vec::with_capacity(secret.len()),
        })
        .collect();

    // For each byte of the secret, create a random polynomial of degree
    // (threshold - 1) with constant term = secret byte, then evaluate it
    // at each share's x.
    let mut random_coeffs = vec![0u8; threshold - 1];

    for &byte in secret {
        rng.fill(&mut random_coeffs)
            .map_err(|_| "system RNG failed")?;

        // coeffs[0] = secret byte, coeffs[1..] = random
        // We evaluate using Horner's method inline to avoid allocation.
        for share in &mut shares {
            let mut val = 0u8;
            // Horner: ((coeffs[t-2]*x + coeffs[t-3])*x + ...)*x + coeffs[0]
            for &c in random_coeffs.iter().rev() {
                val = gf_add(gf_mul(val, share.x), c);
            }
            val = gf_add(gf_mul(val, share.x), byte);
            share.data.push(val);
        }
    }

    Ok(shares)
}

/// Reconstruct the original secret from `threshold` (or more) shares
/// using Lagrange interpolation at x = 0.
///
/// # Errors
///
/// Returns an error if:
/// - No shares provided
/// - Shares have different lengths
/// - Duplicate x values
pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>, String> {
    if shares.is_empty() {
        return Err("no shares provided".into());
    }
    let len = shares[0].data.len();
    if shares.iter().any(|s| s.data.len() != len) {
        return Err("all shares must have the same data length".into());
    }

    // Check for duplicate x values
    let mut seen = [false; 256];
    for s in shares {
        if seen[s.x as usize] {
            return Err(format!("duplicate share x={}", s.x));
        }
        seen[s.x as usize] = true;
    }

    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    let mut secret = Vec::with_capacity(len);

    for j in 0..len {
        let ys: Vec<u8> = shares.iter().map(|s| s.data[j]).collect();
        secret.push(lagrange_at_zero(&xs, &ys));
    }

    Ok(secret)
}

/// Lagrange interpolation at x = 0 in GF(2^8).
///
/// Given points (xs[i], ys[i]), computes f(0) where f is the unique
/// polynomial of degree < n passing through all points.
fn lagrange_at_zero(xs: &[u8], ys: &[u8]) -> u8 {
    let n = xs.len();
    let mut result = 0u8;

    for i in 0..n {
        // Compute Lagrange basis polynomial L_i(0):
        //   L_i(0) = product_{j != i} (0 - xs[j]) / (xs[i] - xs[j])
        //          = product_{j != i} xs[j] / (xs[i] ^ xs[j])
        //
        // In GF(2^8): subtraction = addition = XOR, and 0 - x = x.
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..n {
            if i == j {
                continue;
            }
            num = gf_mul(num, xs[j]);
            den = gf_mul(den, gf_add(xs[i], xs[j]));
        }
        let basis = gf_mul(num, gf_inv(den));
        result = gf_add(result, gf_mul(ys[i], basis));
    }

    result
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf256_basics() {
        // g^0 = 1
        assert_eq!(GF_EXP[0], 1);
        // g^1 = 3
        assert_eq!(GF_EXP[1], 3);
        // g^2 = 5 (3*3 in GF(256))
        assert_eq!(GF_EXP[2], 5);

        // mul identity
        assert_eq!(gf_mul(1, 42), 42);
        assert_eq!(gf_mul(42, 1), 42);

        // mul by zero
        assert_eq!(gf_mul(0, 42), 0);
        assert_eq!(gf_mul(42, 0), 0);

        // inverse
        for x in 1..=255u8 {
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "inv failed for {x}");
        }
    }

    #[test]
    fn split_and_reconstruct_basic() {
        let secret = b"hello world";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        for s in &shares {
            assert_eq!(s.data.len(), secret.len());
        }

        // Any 3 shares reconstruct
        let r = reconstruct(&shares[0..3]).unwrap();
        assert_eq!(r, secret);

        let r = reconstruct(&shares[2..5]).unwrap();
        assert_eq!(r, secret);

        let r = reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]).unwrap();
        assert_eq!(r, secret);
    }

    #[test]
    fn split_and_reconstruct_all_shares() {
        let secret = b"any t-of-n subset works";
        let shares = split(secret, 3, 10).unwrap();

        // Using all 10 shares also works
        let r = reconstruct(&shares).unwrap();
        assert_eq!(r, secret);
    }

    #[test]
    fn split_and_reconstruct_threshold_2() {
        let secret = b"min threshold";
        let shares = split(secret, 2, 5).unwrap();

        for i in 0..5 {
            for j in (i + 1)..5 {
                let r = reconstruct(&[shares[i].clone(), shares[j].clone()]).unwrap();
                assert_eq!(r, secret, "failed for shares ({i}, {j})");
            }
        }
    }

    #[test]
    fn share_serialisation_roundtrip() {
        let secret = b"roundtrip test";
        let shares = split(secret, 3, 5).unwrap();

        for s in &shares {
            let bytes = s.to_bytes();
            let s2 = Share::from_bytes(&bytes).unwrap();
            assert_eq!(s.x, s2.x);
            assert_eq!(s.data, s2.data);
        }
    }

    #[test]
    fn split_errors() {
        assert!(split(b"x", 1, 5).is_err()); // threshold < 2
        assert!(split(b"x", 5, 3).is_err()); // num_shares < threshold
        assert!(split(b"x", 2, 256).is_err()); // > 255 shares
        assert!(split(b"", 2, 3).is_err()); // empty secret
    }

    #[test]
    fn reconstruct_errors() {
        assert!(reconstruct(&[]).is_err()); // no shares

        let shares = split(b"test", 2, 3).unwrap();
        let mut bad = shares.clone();
        bad[1].data.push(0); // different length
        assert!(reconstruct(&bad).is_err());

        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&dup).is_err()); // duplicate x
    }

    #[test]
    fn large_secret() {
        // 1 KB secret
        let secret: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let shares = split(&secret, 5, 20).unwrap();
        let r = reconstruct(&shares[3..8]).unwrap();
        assert_eq!(r, secret);
    }
}
