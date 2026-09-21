// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// The TLS configuration lyrebird's webtunnel builds (transports/webtunnel
// client.go, utls.go), as an interface.

//! TLS to the bridge's web server.

use crate::shared::ports::{BoxFuture, BoxStream};

/// How the server's certificate chain is checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verify {
    /// Against the name sent as SNI (Go `crypto/tls` with `ServerName`).
    ServerName,
    /// Against this name instead of the SNI (uTLS
    /// `InsecureServerNameToVerify`).
    Name(String),
    /// Only against pinned chain hashes, no chain validation at all
    /// (`InsecureSkipVerify` plus `VerifyPeerCertificate`).
    Pins(Vec<Vec<u8>>),
}

pub trait TlsConnector: Send + Sync {
    /// Checks the names and builds the client configuration for one dial,
    /// before any I/O. `sni` is `None` to send no SNI extension. Errors are
    /// configuration errors (e.g. a name that is neither DNS nor IP).
    fn prepare(&self, verify: Verify, sni: Option<&str>) -> Result<Box<dyn TlsHandshake>, String>;
}

/// A prepared client handshake.
pub trait TlsHandshake: Send {
    fn connect(self: Box<Self>, stream: BoxStream)
        -> BoxFuture<'static, Result<BoxStream, String>>;
}
