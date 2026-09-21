// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! The managed-transport configuration tor passes in (`TOR_PT_*`
//! environment variables).

pub trait Env: Send + Sync {
    /// The value of `key`, or `""` when unset (Go's `os.Getenv`).
    fn var(&self, key: &str) -> String;
}
