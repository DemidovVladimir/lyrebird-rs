// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Listening sockets and the outbound dialer for this process.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use super::dialer::Dialer;
use super::stream::{BoxFuture, BoxStream};
use crate::shared::domain::proxy::ProxyConfig;

pub trait Listener: Send + Sync {
    fn local_addr(&self) -> SocketAddr;
    /// The next connection and its peer address. Transient failures (e.g.
    /// out of file descriptors) are retried; an error means the listener
    /// is finished.
    fn accept(&self) -> BoxFuture<'_, io::Result<(BoxStream, SocketAddr)>>;
}

pub trait Network: Send + Sync {
    /// Listens on `addr`. The IPv6 wildcard falls back to the IPv4 one
    /// where IPv6 is unavailable.
    fn listen(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn Listener>>>;
    /// Outbound connections: direct, or through `proxy`.
    fn dialer(&self, proxy: Option<&ProxyConfig>) -> Arc<dyn Dialer>;
}
