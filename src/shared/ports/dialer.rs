// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Outbound connections to bridges, brokers and CDNs.

use std::io;

use super::stream::{BoxFuture, BoxStream};

pub trait Dialer: Send + Sync {
    /// Connects to `addr` (`host:port`).
    fn dial<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, io::Result<BoxStream>>;

    /// True when connections go straight to their destination, i.e. no
    /// outbound proxy (`TOR_PT_PROXY`) is in the way.
    fn is_direct(&self) -> bool;
}
