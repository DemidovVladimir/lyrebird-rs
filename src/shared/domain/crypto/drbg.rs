// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/drbg.

//! SipHash-2-4 in OFB mode, as lyrebird's `HashDrbg`.
//!
//! The SipHash state is never reset: block n is SipHash(key, iv || b1 || … || b(n-1)).
//! That matches Go's `hash.Hash` usage upstream and is what peers expect.

use std::fmt;
use std::hash::Hasher;

use siphasher::sip::SipHasher24;

use super::csrand;
use super::gorand::Source;

pub const SIZE: usize = 8;
pub const SEED_LENGTH: usize = 16 + SIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Seed(pub [u8; SEED_LENGTH]);

#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    #[error("invalid seed length: {0}")]
    Length(usize),
    #[error("invalid seed hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

impl Seed {
    /// A fresh seed from the OS CSPRNG.
    pub fn random() -> Seed {
        let mut s = [0u8; SEED_LENGTH];
        csrand::bytes(&mut s);
        Seed(s)
    }

    /// Takes the first SEED_LENGTH bytes; shorter input is an error.
    pub fn from_bytes(src: &[u8]) -> Result<Seed, SeedError> {
        if src.len() < SEED_LENGTH {
            return Err(SeedError::Length(src.len()));
        }
        let mut s = [0u8; SEED_LENGTH];
        s.copy_from_slice(&src[..SEED_LENGTH]);
        Ok(Seed(s))
    }

    pub fn from_hex(encoded: &str) -> Result<Seed, SeedError> {
        Seed::from_bytes(&hex::decode(encoded)?)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(..)")
    }
}

#[derive(Clone)]
pub struct HashDrbg {
    sip: SipHasher24,
    ofb: [u8; SIZE],
}

impl HashDrbg {
    pub fn new(seed: &Seed) -> HashDrbg {
        let mut key = [0u8; 16];
        key.copy_from_slice(&seed.0[..16]);
        let mut ofb = [0u8; SIZE];
        ofb.copy_from_slice(&seed.0[16..]);
        HashDrbg {
            sip: SipHasher24::new_with_key(&key),
            ofb,
        }
    }

    pub fn next_block(&mut self) -> [u8; SIZE] {
        self.sip.write(&self.ofb);
        self.ofb = self.sip.finish().to_le_bytes();
        self.ofb
    }
}

impl Source for HashDrbg {
    fn int63(&mut self) -> i64 {
        (u64::from_be_bytes(self.next_block()) & ((1 << 63) - 1)) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::domain::crypto::gorand::Rand;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vec_ {
        seed: String,
        blocks: Vec<String>,
        int63: Vec<i64>,
        perm10: Vec<usize>,
        perm1449: Vec<usize>,
        intn_n: Vec<i64>,
        intn: Vec<i64>,
        float64: Vec<f64>,
        int63n: Vec<i64>,
    }

    fn vectors() -> Vec<Vec_> {
        serde_json::from_str(include_str!("../../../../tests/vectors/drbg.json")).unwrap()
    }

    #[test]
    fn blocks_match_go() {
        for v in vectors() {
            let mut d = HashDrbg::new(&Seed::from_hex(&v.seed).unwrap());
            for b in &v.blocks {
                assert_eq!(&hex::encode(d.next_block()), b);
            }
            for x in &v.int63 {
                assert_eq!(d.int63(), *x);
            }
        }
    }

    #[test]
    fn go_math_rand_matches() {
        for v in vectors() {
            let mut r = Rand::new(HashDrbg::new(&Seed::from_hex(&v.seed).unwrap()));
            assert_eq!(r.perm(10), v.perm10);
            assert_eq!(r.perm(1449), v.perm1449);
            for (n, want) in v.intn_n.iter().zip(&v.intn) {
                assert_eq!(r.intn(*n), *want, "intn({n})");
            }
            for want in &v.float64 {
                assert_eq!(r.float64().to_bits(), want.to_bits());
            }
            for (n, want) in [1i64, 3, 1 << 40, i64::MAX].iter().zip(&v.int63n) {
                assert_eq!(r.int63n(*n), *want);
            }
        }
    }
}
