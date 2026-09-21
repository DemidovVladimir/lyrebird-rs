// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause

//! Finding out what kind of NAT we are behind.

use std::io;

use crate::shared::ports::BoxFuture;

pub trait NatProbe: Send + Sync {
    /// RFC 5780 mapping test against the STUN server `server` (`host:port`):
    /// true if the mapped address changes with the destination.
    fn is_restricted_mapping<'a>(&'a self, server: &'a str) -> BoxFuture<'a, io::Result<bool>>;
}
