// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! The process environment tor launched us with.

use crate::shared::ports::env::Env;

pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, key: &str) -> String {
        std::env::var(key).unwrap_or_default()
    }
}
