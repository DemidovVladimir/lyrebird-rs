// Copyright (c) 2021 Yawning Angel <yawning at schwanenlied dot me>
// Copyright (c) 2026 lyrebird-rs contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Port of lyrebird internal/x25519ell2 (GPL-3.0-or-later) and the
// Elligator2 map from gitlab.com/yawning/edwards25519-extra (BSD-3-Clause).

//! Obfuscated X25519 via Elligator2, with the "dirty" public key fix
//! (a random low-order component) so representatives are uniform.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::field::{fe_const, Fe};

const NEG_TWO: Fe = fe_const([
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
]);
const NEG_A: Fe = fe_const([
    0xe7, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
]);
const U_FACTOR: Fe = fe_const([
    0x8d, 0xbe, 0xe2, 0x6b, 0xb1, 0xc9, 0x23, 0x76, 0x0e, 0x37, 0xa0, 0xa5, 0xf2, 0xcf, 0x79, 0xa1,
    0xb1, 0x50, 0x08, 0x84, 0xcd, 0xfe, 0x65, 0xa9, 0xe9, 0x41, 0x7c, 0x60, 0xff, 0xb6, 0xf9, 0x28,
]);
/// x of the order-8 Edwards point L = (LOP_X, LOP_Y) used for the dirty key.
const LOP_X: [u8; 32] = [
    0x4a, 0xd1, 0x45, 0xc5, 0x46, 0x46, 0xa1, 0xde, 0x38, 0xe2, 0xe5, 0x13, 0x70, 0x3c, 0x19, 0x5c,
    0xbb, 0x4a, 0xde, 0x38, 0x32, 0x99, 0x33, 0xe9, 0x28, 0x4a, 0x39, 0x06, 0xa0, 0xb9, 0xd5, 0x1f,
];
const LOP_Y: [u8; 32] = [
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
];

fn fe_a() -> Fe {
    Fe::from_u64(486662)
}

/// [c]L for c in 0..8 — the eight torsion points in the order Go's
/// `selectLowOrderPoint` indexes them.
fn low_order_points() -> [EdwardsPoint; 8] {
    let mut compressed = LOP_Y;
    compressed[31] |= (LOP_X[0] & 1) << 7;
    let l = CompressedEdwardsY(compressed)
        .decompress()
        .expect("low order point decompresses");
    let mut out = [EdwardsPoint::default(); 8];
    for i in 1..8 {
        out[i] = out[i - 1] + l;
    }
    out
}

/// [clamp(sk)]B + [sk[0] & 7]L, as a Montgomery u-coordinate.
fn scalar_base_mult_dirty(private_key: &[u8; 32]) -> Fe {
    let pk = EdwardsPoint::mul_base_clamped(*private_key);
    let points = low_order_points();
    let c = private_key[0] & 7;
    let mut lop = EdwardsPoint::default();
    for (i, p) in points.iter().enumerate() {
        lop.conditional_assign(p, (i as u8).ct_eq(&c));
    }
    Fe::from_bytes(&(pk + lop).to_montgomery().to_bytes())
}

fn u_to_representative(u: &Fe, tweak: u8) -> Option<[u8; 32]> {
    let t1 = *u;
    let t2 = t1.add(&fe_a());
    let t3 = t1.mul(&t2).mul(&NEG_TWO);
    let (t3, is_square) = Fe::sqrt_ratio(&Fe::ONE, &t3);
    if !bool::from(is_square) {
        return None;
    }
    let t1 = Fe::select(&t2, &t1, Choice::from(tweak & 1));
    let t3 = t1.mul(&t3);
    let doubled = t3.add(&t3);
    let t3 = Fe::select(&t3.neg(), &t3, Choice::from(doubled.to_bytes()[0] & 1));
    let mut representative = t3.to_bytes();
    representative[31] |= tweak & 0xc0;
    Some(representative)
}

/// Obfuscated X25519 key generation. `None` when the key has no
/// representative (about half of all keys); callers retry with a new key.
/// Returns `(public_key, representative)`.
pub fn scalar_base_mult(private_key: &[u8; 32], tweak: u8) -> Option<([u8; 32], [u8; 32])> {
    let u = scalar_base_mult_dirty(private_key);
    let representative = u_to_representative(&u, tweak)?;
    Some((u.to_bytes(), representative))
}

/// Elligator2 "Montgomery flavor" map, u-coordinate only.
fn montgomery_flavor_u(r: &Fe) -> Fe {
    let a = fe_a();
    let a_squared = Fe::from_u64(486662 * 486662);
    let two = Fe::ONE.add(&Fe::ONE);

    let t1 = r.square().mul(&two);
    let u = t1.add(&Fe::ONE);
    let t2 = u.square();
    let t3 = a_squared.mul(&t1).sub(&t2).mul(&a);
    let t1 = t2.mul(&u).mul(&t3);
    let (t1, is_square) = Fe::sqrt_ratio(&Fe::ONE, &t1);
    let u = r.square().mul(&U_FACTOR);
    let u = Fe::select(&Fe::ONE, &u, is_square);
    let t1 = t1.square();
    u.mul(&NEG_A).mul(&t3).mul(&t2).mul(&t1)
}

/// Public key for a representative (top two bits ignored).
pub fn representative_to_public_key(representative: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *representative;
    clamped[31] &= 63;
    montgomery_flavor_u(&Fe::from_bytes(&clamped)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct KeyVec {
        private: String,
        tweak: u8,
        dirty_u: String,
        ok: bool,
        public: String,
        representative: String,
    }
    #[derive(Deserialize)]
    struct ReprVec {
        representative: String,
        public: String,
    }
    #[derive(Deserialize)]
    struct Vectors {
        keys: Vec<KeyVec>,
        representatives: Vec<ReprVec>,
    }

    fn arr(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../../../tests/vectors/x25519ell2.json")).unwrap()
    }

    #[test]
    fn dirty_u_matches_go() {
        for v in vectors().keys {
            let u = scalar_base_mult_dirty(&arr(&v.private));
            assert_eq!(
                hex::encode(u.to_bytes()),
                v.dirty_u,
                "private {}",
                v.private
            );
        }
    }

    #[test]
    fn scalar_base_mult_matches_go() {
        for v in vectors().keys {
            let got = scalar_base_mult(&arr(&v.private), v.tweak);
            assert_eq!(got.is_some(), v.ok, "private {}", v.private);
            if let Some((public, representative)) = got {
                assert_eq!(hex::encode(public), v.public);
                assert_eq!(hex::encode(representative), v.representative);
            }
        }
    }

    #[test]
    fn representative_to_public_matches_go() {
        for v in vectors().representatives {
            let public = representative_to_public_key(&arr(&v.representative));
            assert_eq!(hex::encode(public), v.public);
        }
    }

    #[test]
    fn dirty_keys_agree_with_clean_x25519() {
        let peer = [7u8; 32];
        for v in vectors().keys.iter().filter(|v| v.ok) {
            let sk = arr(&v.private);
            let (public, representative) = scalar_base_mult(&sk, v.tweak).unwrap();
            assert_eq!(representative_to_public_key(&representative), public);
            let clean = MontgomeryPoint::mul_base_clamped(sk);
            assert_eq!(
                MontgomeryPoint(public).mul_clamped(peer),
                clean.mul_clamped(peer)
            );
        }
    }
}
