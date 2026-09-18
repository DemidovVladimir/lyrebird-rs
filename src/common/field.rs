//! GF(2^255 - 19) arithmetic on fiat-crypto's verified 64-bit primitives.
//!
//! Only the subset of `filippo.io/edwards25519/field` that lyrebird's
//! Elligator2 code needs. `select(a, b, c)` follows the Go argument order:
//! `a` when `c` is set, `b` otherwise.

use fiat_crypto::curve25519_64 as fiat;
use fiat_crypto::curve25519_64::{
    fiat_25519_loose_field_element as Loose, fiat_25519_tight_field_element as Tight,
};
use subtle::{Choice, ConstantTimeEq};

#[derive(Clone, Copy)]
pub struct Fe(Tight);

impl Fe {
    pub const ZERO: Fe = Fe(Tight([0; 5]));
    pub const ONE: Fe = Fe(Tight([1, 0, 0, 0, 0]));

    /// Little-endian decode; the top bit is ignored, non-canonical values are reduced.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let mut b = *bytes;
        b[31] &= 0x7f;
        let mut out = Tight([0; 5]);
        fiat::fiat_25519_from_bytes(&mut out, &b);
        Fe(out)
    }

    pub fn from_u64(x: u64) -> Fe {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&x.to_le_bytes());
        Fe::from_bytes(&b)
    }

    /// Canonical little-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        fiat::fiat_25519_to_bytes(&mut out, &self.0);
        out
    }

    fn relax(&self) -> Loose {
        let mut out = Loose([0; 5]);
        fiat::fiat_25519_relax(&mut out, &self.0);
        out
    }

    fn carry(l: &Loose) -> Fe {
        let mut out = Tight([0; 5]);
        fiat::fiat_25519_carry(&mut out, l);
        Fe(out)
    }

    pub fn add(&self, rhs: &Fe) -> Fe {
        let mut l = Loose([0; 5]);
        fiat::fiat_25519_add(&mut l, &self.0, &rhs.0);
        Fe::carry(&l)
    }

    pub fn sub(&self, rhs: &Fe) -> Fe {
        let mut l = Loose([0; 5]);
        fiat::fiat_25519_sub(&mut l, &self.0, &rhs.0);
        Fe::carry(&l)
    }

    pub fn neg(&self) -> Fe {
        let mut l = Loose([0; 5]);
        fiat::fiat_25519_opp(&mut l, &self.0);
        Fe::carry(&l)
    }

    pub fn mul(&self, rhs: &Fe) -> Fe {
        let mut out = Tight([0; 5]);
        fiat::fiat_25519_carry_mul(&mut out, &self.relax(), &rhs.relax());
        Fe(out)
    }

    pub fn square(&self) -> Fe {
        let mut out = Tight([0; 5]);
        fiat::fiat_25519_carry_square(&mut out, &self.relax());
        Fe(out)
    }

    fn pow2k(&self, k: u32) -> Fe {
        let mut t = *self;
        for _ in 0..k {
            t = t.square();
        }
        t
    }

    /// x^((p-5)/8) = x^(2^252 - 3).
    pub fn pow22523(&self) -> Fe {
        let x = self;
        let z2 = x.square();
        let z9 = z2.pow2k(2).mul(x);
        let z11 = z9.mul(&z2);
        let z2_5_0 = z11.square().mul(&z9);
        let z2_10_0 = z2_5_0.pow2k(5).mul(&z2_5_0);
        let z2_20_0 = z2_10_0.pow2k(10).mul(&z2_10_0);
        let z2_40_0 = z2_20_0.pow2k(20).mul(&z2_20_0);
        let z2_50_0 = z2_40_0.pow2k(10).mul(&z2_10_0);
        let z2_100_0 = z2_50_0.pow2k(50).mul(&z2_50_0);
        let z2_200_0 = z2_100_0.pow2k(100).mul(&z2_100_0);
        let z2_250_0 = z2_200_0.pow2k(50).mul(&z2_50_0);
        z2_250_0.pow2k(2).mul(x)
    }

    /// x^(p-2); 0 maps to 0.
    pub fn invert(&self) -> Fe {
        // p - 2 = 8 * (2^252 - 3) + 3
        let x3 = self.square().mul(self);
        self.pow22523().pow2k(3).mul(&x3)
    }

    pub fn is_negative(&self) -> Choice {
        Choice::from(self.to_bytes()[0] & 1)
    }

    pub fn ct_eq(&self, rhs: &Fe) -> Choice {
        self.to_bytes().ct_eq(&rhs.to_bytes())
    }

    /// `a` if `choice` is set, else `b`.
    pub fn select(a: &Fe, b: &Fe, choice: Choice) -> Fe {
        let mut out = [0u64; 5];
        fiat::fiat_25519_selectznz(&mut out, choice.unwrap_u8(), &b.0 .0, &a.0 .0);
        Fe(Tight(out))
    }

    pub fn abs(&self) -> Fe {
        Fe::select(&self.neg(), self, self.is_negative())
    }

    /// Non-negative sqrt(u/v) and whether u/v was square
    /// (draft-irtf-cfrg-ristretto255-decaf448-00 §4.3, as in filippo.io/edwards25519).
    pub fn sqrt_ratio(u: &Fe, v: &Fe) -> (Fe, Choice) {
        let v2 = v.square();
        let uv3 = u.mul(&v2.mul(v));
        let uv7 = uv3.mul(&v2.square());
        let rr = uv3.mul(&uv7.pow22523());

        let check = v.mul(&rr.square());
        let u_neg = u.neg();
        let correct = check.ct_eq(u);
        let flipped = check.ct_eq(&u_neg);
        let flipped_i = check.ct_eq(&u_neg.mul(&SQRT_M1));

        let r_prime = rr.mul(&SQRT_M1);
        let rr = Fe::select(&r_prime, &rr, flipped | flipped_i);
        (rr.abs(), correct | flipped)
    }
}

pub const SQRT_M1: Fe = fe_const([
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
]);

/// Decodes a canonical constant at compile time (mirrors fiat's from_bytes limb split).
pub const fn fe_const(b: [u8; 32]) -> Fe {
    const MASK: u64 = (1 << 51) - 1;
    let mut w = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 8 {
            w[i] |= (b[i * 8 + j] as u64) << (8 * j);
            j += 1;
        }
        i += 1;
    }
    let w3 = w[3] & 0x7fff_ffff_ffff_ffff;
    Fe(Tight([
        w[0] & MASK,
        ((w[0] >> 51) | (w[1] << 13)) & MASK,
        ((w[1] >> 38) | (w[2] << 26)) & MASK,
        ((w[2] >> 25) | (w3 << 39)) & MASK,
        (w3 >> 12) & MASK,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(n: u64) -> Fe {
        Fe::from_u64(n)
    }

    #[test]
    fn const_decoder_matches_fiat() {
        let bytes = SQRT_M1.to_bytes();
        assert_eq!(Fe::from_bytes(&bytes).to_bytes(), bytes);
        let x = [0x5au8; 32];
        let mut masked = x;
        masked[31] &= 0x7f;
        assert_eq!(fe_const(x).to_bytes(), Fe::from_bytes(&masked).to_bytes());
    }

    #[test]
    fn sqrt_m1_squares_to_minus_one() {
        assert!(bool::from(SQRT_M1.square().ct_eq(&Fe::ONE.neg())));
    }

    #[test]
    fn invert_and_sqrt() {
        for n in [2u64, 3, 9, 486662, 1 << 40] {
            let x = fe(n);
            assert!(bool::from(x.mul(&x.invert()).ct_eq(&Fe::ONE)));
            let (r, sq) = Fe::sqrt_ratio(&x.square(), &Fe::ONE);
            assert!(bool::from(sq));
            assert!(bool::from(r.square().ct_eq(&x.square())));
            assert!(!bool::from(r.is_negative()));
        }
        // 2 is a non-residue mod p.
        let (_, sq) = Fe::sqrt_ratio(&fe(2), &Fe::ONE);
        assert!(!bool::from(sq));
        assert_eq!(Fe::ZERO.invert().to_bytes(), [0u8; 32]);
    }
}
