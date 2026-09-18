// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/{transports.go,base/base.go}.

//! Transport interface and registry.
//!
//! A transport connection is a pair of independent halves driven by two
//! tasks (one per direction), mirroring the two goroutines upstream's copy
//! loop uses. Halves expose async methods rather than poll-based traits.

pub mod obfs4;
pub mod snowflake;
pub mod webtunnel;

use std::any::Any;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::Dialer;
use crate::pt::Args;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub trait ReadHalf: Send {
    /// Like `AsyncRead::read`: `Ok(0)` is EOF.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
}

pub trait WriteHalf: Send {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
    fn shutdown(&mut self) -> BoxFuture<'_, io::Result<()>>;
}

pub struct Conn {
    pub reader: Box<dyn ReadHalf>,
    pub writer: Box<dyn WriteHalf>,
}

/// Adapts any tokio reader/writer to a transport half.
pub struct Plain<T>(pub T);

impl<T: AsyncRead + Unpin + Send> ReadHalf for Plain<T> {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(self.0.read(buf))
    }
}

impl<T: AsyncWrite + Unpin + Send> WriteHalf for Plain<T> {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.0.write_all(buf))
    }

    fn shutdown(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(self.0.shutdown())
    }
}

impl Conn {
    pub fn from_tcp(stream: TcpStream) -> Conn {
        let (r, w) = stream.into_split();
        Conn {
            reader: Box::new(Plain(r)),
            writer: Box::new(Plain(w)),
        }
    }
}

/// Per-connection arguments produced by `ClientFactory::parse_args`.
pub type ClientArgs = Box<dyn Any + Send>;

/// Dial failure, keeping the I/O error kind for the SOCKS reply code.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Other(BoxError),
}

pub trait ClientFactory: Send + Sync {
    fn transport_name(&self) -> &'static str;
    fn parse_args(&self, args: &Args) -> Result<ClientArgs, BoxError>;
    fn dial<'a>(
        &'a self,
        target: &'a str,
        dialer: &'a Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>>;
    /// Transport status events, relayed to tor as `LOG` lines.
    fn on_event(&self, _f: Arc<dyn Fn(String) + Send + Sync>) {}
}

pub trait ServerFactory: Send + Sync {
    fn transport_name(&self) -> &'static str;
    /// Args for the SMETHOD line (e.g. the obfs4 cert).
    fn args(&self) -> Option<Args>;
    fn wrap(&self, conn: TcpStream) -> BoxFuture<'_, Result<Conn, BoxError>>;
}

pub trait Transport: Send + Sync {
    fn name(&self) -> &'static str;
    fn client_factory(&self, state_dir: &Path) -> Result<Arc<dyn ClientFactory>, BoxError>;
    fn server_factory(
        &self,
        state_dir: &Path,
        args: &Args,
    ) -> Result<Arc<dyn ServerFactory>, BoxError>;
}

/// All transports, in registration order.
pub fn all() -> Vec<Arc<dyn Transport>> {
    vec![
        Arc::new(obfs4::Transport),
        Arc::new(snowflake::Transport),
        Arc::new(webtunnel::Transport),
    ]
}

pub fn get(name: &str) -> Option<Arc<dyn Transport>> {
    all().into_iter().find(|t| t.name() == name)
}
