// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of the listener handling in lyrebird cmd/lyrebird.

//! Plain TCP: direct dials, listeners, and the `Network` port.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use super::proxy::ProxyDialer;
use crate::shared::domain::proxy::ProxyConfig;
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::net::{Listener, Network};
use crate::shared::ports::stream::{BoxFuture, BoxRead, BoxStream, BoxWrite, ByteStream};

impl ByteStream for TcpStream {
    fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let (r, w) = self.into_split();
        (Box::new(r), Box::new(w))
    }
}

/// Connects straight to the destination.
pub struct DirectDialer;

impl Dialer for DirectDialer {
    fn dial<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { Ok(Box::new(TcpStream::connect(addr).await?) as BoxStream) })
    }

    fn is_direct(&self) -> bool {
        true
    }
}

/// The process's own sockets.
pub struct TcpNetwork;

impl Network for TcpNetwork {
    fn listen(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Box<dyn Listener>>> {
        Box::pin(async move {
            let ln = bind(addr).await?;
            let local_addr = ln.local_addr()?;
            Ok(Box::new(Tcp { ln, local_addr }) as Box<dyn Listener>)
        })
    }

    fn dialer(&self, proxy: Option<&ProxyConfig>) -> Arc<dyn Dialer> {
        match proxy {
            None => Arc::new(DirectDialer),
            Some(config) => Arc::new(ProxyDialer::new(config.clone())),
        }
    }
}

/// Dual-stack wildcard binds fall back to IPv4 where IPv6 is unavailable.
async fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    match TcpListener::bind(addr).await {
        Err(e) if addr.ip() == Ipv6Addr::UNSPECIFIED => {
            let v4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), addr.port());
            TcpListener::bind(v4).await.map_err(|_| e)
        }
        other => other,
    }
}

struct Tcp {
    ln: TcpListener,
    local_addr: SocketAddr,
}

impl Listener for Tcp {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn accept(&self) -> BoxFuture<'_, io::Result<(BoxStream, SocketAddr)>> {
        Box::pin(async move {
            loop {
                match self.ln.accept().await {
                    Ok((conn, peer)) => return Ok((Box::new(conn) as BoxStream, peer)),
                    Err(e) if is_temporary(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
        })
    }
}

fn is_temporary(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock
    ) || e.raw_os_error().is_some_and(|n| n == 24 || n == 23) // EMFILE / ENFILE
}
