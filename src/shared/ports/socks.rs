// Copyright (c) 2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of the request/reply types of lyrebird common/socks5.

//! Client side: tor's SOCKS5 requests, one per connection it wants through
//! a transport. Per-connection transport arguments ride in the request.

use std::io;

use super::stream::{BoxFuture, BoxStream};
use crate::shared::domain::pt::Args;

/// The proxy type announced in `CMETHOD` lines.
pub const VERSION_STRING: &str = "socks5";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplyCode {
    Succeeded = 0,
    GeneralFailure = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressNotSupported = 8,
}

/// Maps a dial error to a reply code the way upstream maps `syscall.Errno`s.
pub fn error_to_reply_code(e: &io::Error) -> ReplyCode {
    if e.raw_os_error().is_none() {
        return ReplyCode::GeneralFailure;
    }
    match e.kind() {
        io::ErrorKind::AddrNotAvailable => ReplyCode::AddressNotSupported,
        io::ErrorKind::TimedOut => ReplyCode::TtlExpired,
        io::ErrorKind::NetworkUnreachable => ReplyCode::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => ReplyCode::HostUnreachable,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
            ReplyCode::ConnectionRefused
        }
        _ => ReplyCode::GeneralFailure,
    }
}

/// A CONNECT request awaiting its reply.
pub trait SocksRequest: Send {
    /// `host:port` tor asked for.
    fn target(&self) -> &str;
    /// Transport arguments from the bridge line.
    fn args(&self) -> &Args;
    fn reply(&mut self, code: ReplyCode) -> BoxFuture<'_, io::Result<()>>;
    /// The connection to tor, after a successful reply.
    fn into_stream(self: Box<Self>) -> BoxStream;
}

pub trait SocksServer: Send + Sync {
    /// Runs the server side of the SOCKS5 handshake on a connection from tor.
    fn handshake(&self, conn: BoxStream) -> BoxFuture<'static, io::Result<Box<dyn SocksRequest>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_codes() {
        let refused = io::Error::from_raw_os_error(libc_econnrefused());
        assert_eq!(error_to_reply_code(&refused), ReplyCode::ConnectionRefused);
        let custom = io::Error::new(io::ErrorKind::ConnectionRefused, "not an errno");
        assert_eq!(error_to_reply_code(&custom), ReplyCode::GeneralFailure);
    }

    fn libc_econnrefused() -> i32 {
        if cfg!(target_os = "linux") {
            111
        } else {
            61
        }
    }
}
