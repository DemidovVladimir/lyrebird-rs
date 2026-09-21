// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/webtunnel/servername_generator.go.

//! `servername=` specs: one TLS server name, or a comma-separated list. A
//! generator starts at a random entry and only moves to the next one when a
//! dial that used the current entry failed after the TCP connection was up
//! (a blocked SNI, most likely). Generators live for the life of the client
//! factory, one per spec.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::shared::domain::crypto::csrand;

pub const ERR_INVALID_SPEC: &str = "invalid servername spec";

#[derive(Debug)]
pub struct Generator {
    spec: String,
    names: Vec<String>,
    position: Mutex<usize>,
}

impl Generator {
    pub fn new(spec: &str) -> Result<Generator, String> {
        let mut names = Vec::new();
        if !spec.is_empty() {
            names.extend(
                spec.split(',')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string),
            );
            if names.is_empty() {
                return Err(ERR_INVALID_SPEC.into());
            }
        }
        // Upstream panics here on an empty spec (Intn(0)), which a
        // `servername=` of only whitespace reaches: the client trims the
        // value before building the generator. Use the empty name instead.
        let position = match names.len() {
            0 => 0,
            n => csrand::intn(n as i64) as usize,
        };
        Ok(Generator {
            spec: spec.to_string(),
            names,
            position: Mutex::new(position),
        })
    }

    fn current(&self, position: usize) -> String {
        if self.names.is_empty() {
            return self.spec.clone();
        }
        self.names[position].clone()
    }

    pub fn generate(&self) -> String {
        let position = self.position.lock().unwrap_or_else(|e| e.into_inner());
        self.current(*position)
    }

    /// Advances to the next name, unless another dial already did.
    pub fn reroll_if_unchanged(&self, current_name: &str) {
        let mut position = self.position.lock().unwrap_or_else(|e| e.into_inner());
        if self.names.is_empty() || self.current(*position) != current_name {
            return;
        }
        *position = (*position + 1) % self.names.len();
    }

    #[cfg(test)]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    #[cfg(test)]
    pub fn set_position(&self, position: usize) {
        *self.position.lock().unwrap_or_else(|e| e.into_inner()) = position;
    }
}

/// One generator per spec, shared by every dial of a client factory.
#[derive(Default)]
pub struct Holder {
    generators: Mutex<HashMap<String, Arc<Generator>>>,
}

impl Holder {
    pub fn get(&self, spec: &str) -> Result<Arc<Generator>, String> {
        let mut generators = self.generators.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(g) = generators.get(spec) {
            return Ok(g.clone());
        }
        let g = Arc::new(Generator::new(spec)?);
        generators.insert(spec.to_string(), g.clone());
        Ok(g)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        assert_eq!(Generator::new("a.test").unwrap().names(), ["a.test"]);
        assert_eq!(
            Generator::new(" a.test , , b.test ").unwrap().names(),
            ["a.test", "b.test"]
        );
        assert_eq!(Generator::new(",").unwrap_err(), ERR_INVALID_SPEC);
        assert_eq!(Generator::new(" , ").unwrap_err(), ERR_INVALID_SPEC);
        assert_eq!(Generator::new("a.test,").unwrap().names(), ["a.test"]);
        assert_eq!(
            Generator::new("a.test,a.test").unwrap().names(),
            ["a.test", "a.test"]
        );
        let empty = Generator::new("").unwrap();
        assert!(empty.names().is_empty());
        assert_eq!(empty.generate(), "");
        empty.reroll_if_unchanged("");
        assert_eq!(empty.generate(), "");
    }

    #[test]
    fn starts_anywhere_and_rerolls_in_order() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            seen.insert(Generator::new("a.test,b.test,c.test").unwrap().generate());
        }
        assert_eq!(seen.len(), 3, "random start position: {seen:?}");

        let g = Generator::new("a.test,b.test,c.test").unwrap();
        g.set_position(0);
        assert_eq!(g.generate(), "a.test");
        g.reroll_if_unchanged("a.test");
        assert_eq!(g.generate(), "b.test");
        // Another dial already moved on: no double advance.
        g.reroll_if_unchanged("zzz");
        assert_eq!(g.generate(), "b.test");
        g.reroll_if_unchanged("b.test");
        assert_eq!(g.generate(), "c.test");
        g.reroll_if_unchanged("c.test");
        assert_eq!(g.generate(), "a.test");
    }

    #[test]
    fn holder_shares_generators_per_spec() {
        let h = Holder::default();
        let a = h.get("a.test,b.test").unwrap();
        let b = h.get("a.test,b.test").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &h.get("a.test").unwrap()));
        assert_eq!(h.get(",").unwrap_err(), ERR_INVALID_SPEC);
    }
}
