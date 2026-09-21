// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/csrand.

//! OS-entropy randomness with Go `math/rand` helpers on top.

use super::gorand::{Rand, Source};

struct OsSource;

impl Source for OsSource {
    fn int63(&mut self) -> i64 {
        let mut b = [0u8; 8];
        bytes(&mut b);
        (u64::from_be_bytes(b) & ((1 << 63) - 1)) as i64
    }
}

/// Fills `buf` from the OS CSPRNG. Aborts if the OS has no entropy source,
/// as upstream does.
pub fn bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("csrand: OS entropy source failed");
}

pub fn intn(n: i64) -> i64 {
    Rand::new(OsSource).intn(n)
}

pub fn float64() -> f64 {
    Rand::new(OsSource).float64()
}

/// Uniform in [min, max] (both inclusive).
pub fn int_range(min: i64, max: i64) -> i64 {
    assert!(max >= min, "int_range: min > max ({min}, {max})");
    intn((max + 1) - min) + min
}
