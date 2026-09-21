// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/probdist.

//! Weighted distribution (Vose's alias method) generated from a DRBG seed.
//! Tables must match Go bit-for-bit: a bridge's seed fixes its clients'
//! packet-length and inter-arrival distributions.

use std::collections::VecDeque;

use super::csrand;
use super::drbg::{HashDrbg, Seed};
use super::gorand::Rand;

const MIN_VALUES: usize = 1;
const MAX_VALUES: usize = 100;

#[derive(Clone, Debug)]
pub struct WeightedDist {
    min_value: usize,
    max_value: usize,
    biased: bool,
    values: Vec<usize>,
    weights: Vec<f64>,
    alias: Vec<usize>,
    prob: Vec<f64>,
}

impl WeightedDist {
    /// Values range over [min, max]. Panics if `max <= min`, as upstream.
    pub fn new(seed: &Seed, min: usize, max: usize, biased: bool) -> WeightedDist {
        assert!(max > min, "wDist.Reset(): min >= max ({min}, {max})");
        let mut w = WeightedDist {
            min_value: min,
            max_value: max,
            biased,
            values: Vec::new(),
            weights: Vec::new(),
            alias: Vec::new(),
            prob: Vec::new(),
        };
        w.reset(seed);
        w
    }

    pub fn reset(&mut self, seed: &Seed) {
        let mut rng = Rand::new(HashDrbg::new(seed));
        self.gen_values(&mut rng);
        if self.biased {
            self.gen_biased_weights(&mut rng);
        } else {
            self.gen_uniform_weights(&mut rng);
        }
        self.gen_tables();
    }

    fn gen_values(&mut self, rng: &mut Rand<HashDrbg>) {
        let mut n_values = (self.max_value + 1) - self.min_value;
        let mut values = rng.perm(n_values);
        n_values = n_values.clamp(MIN_VALUES, MAX_VALUES);
        n_values = rng.intn(n_values as i64) as usize + 1;
        values.truncate(n_values);
        self.values = values;
    }

    fn gen_biased_weights(&mut self, rng: &mut Rand<HashDrbg>) {
        let mut culm_prob = 0.0;
        self.weights = (0..self.values.len())
            .map(|_| {
                let p = (1.0 - culm_prob) * rng.float64();
                culm_prob += p;
                p
            })
            .collect();
    }

    fn gen_uniform_weights(&mut self, rng: &mut Rand<HashDrbg>) {
        self.weights = (0..self.values.len()).map(|_| rng.float64()).collect();
    }

    fn gen_tables(&mut self) {
        let n = self.weights.len();
        let sum: f64 = self.weights.iter().fold(0.0, |acc, w| acc + w);

        let mut alias = vec![0usize; n];
        let mut prob = vec![0.0f64; n];
        let mut small = VecDeque::new();
        let mut large = VecDeque::new();
        let mut scaled = vec![0.0f64; n];
        for (i, weight) in self.weights.iter().enumerate() {
            scaled[i] = weight * n as f64 / sum;
            if scaled[i] < 1.0 {
                small.push_back(i);
            } else {
                large.push_back(i);
            }
        }

        while !small.is_empty() && !large.is_empty() {
            let l = small.pop_front().unwrap();
            let g = large.pop_front().unwrap();
            prob[l] = scaled[l];
            alias[l] = g;
            scaled[g] = (scaled[g] + scaled[l]) - 1.0;
            if scaled[g] < 1.0 {
                small.push_back(g);
            } else {
                large.push_back(g);
            }
        }
        while let Some(g) = large.pop_front() {
            prob[g] = 1.0;
        }
        // Only reachable through numerical instability.
        while let Some(l) = small.pop_front() {
            prob[l] = 1.0;
        }

        self.prob = prob;
        self.alias = alias;
    }

    /// Whether `value` can be sampled.
    pub fn contains(&self, value: usize) -> bool {
        value >= self.min_value && self.values.contains(&(value - self.min_value))
    }

    /// Every value that can be sampled.
    pub fn support(&self) -> Vec<usize> {
        self.values.iter().map(|v| self.min_value + v).collect()
    }

    pub fn sample(&self) -> usize {
        let i = csrand::intn(self.values.len() as i64) as usize;
        let idx = if csrand::float64() <= self.prob[i] {
            i
        } else {
            self.alias[i]
        };
        self.min_value + self.values[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Table {
        seed: String,
        min: usize,
        max: usize,
        biased: bool,
        values: Vec<usize>,
        weights: Vec<f64>,
        prob: Vec<f64>,
        alias: Vec<usize>,
    }

    #[test]
    fn tables_match_go() {
        let tables: Vec<Table> =
            serde_json::from_str(include_str!("../../../../tests/vectors/probdist.json")).unwrap();
        assert!(tables.len() >= 96);
        for t in tables {
            let w = WeightedDist::new(&Seed::from_hex(&t.seed).unwrap(), t.min, t.max, t.biased);
            let ctx = format!("seed {} [{}, {}] biased={}", t.seed, t.min, t.max, t.biased);
            assert_eq!(w.values, t.values, "{ctx}");
            assert_eq!(bits(&w.weights), bits(&t.weights), "{ctx}");
            assert_eq!(bits(&w.prob), bits(&t.prob), "{ctx}");
            assert_eq!(w.alias, t.alias, "{ctx}");
        }
    }

    #[test]
    fn samples_stay_in_range() {
        let w = WeightedDist::new(&Seed([9; 24]), 5, 9, false);
        for _ in 0..1000 {
            assert!((5..=9).contains(&w.sample()));
        }
    }

    fn bits(v: &[f64]) -> Vec<u64> {
        v.iter().map(|f| f.to_bits()).collect()
    }
}
