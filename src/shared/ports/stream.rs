// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Byte streams as the core sees them: anything readable and writable, no
//! matter whether a TCP socket, a proxy tunnel or TLS sits underneath.

use std::future::Future;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// A connected, bidirectional byte stream.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {
    /// Independent read and write halves, for driving each direction from
    /// its own task.
    fn split(self: Box<Self>) -> (BoxRead, BoxWrite);
}

pub type BoxStream = Box<dyn ByteStream>;

/// `ByteStream::split` for streams without a lock-free split of their own.
pub fn split_locked<S>(stream: S) -> (BoxRead, BoxWrite)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (r, w) = tokio::io::split(stream);
    (Box::new(r), Box::new(w))
}

impl ByteStream for tokio::io::DuplexStream {
    fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        split_locked(*self)
    }
}
