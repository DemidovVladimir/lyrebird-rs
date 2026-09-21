// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Server side: handing bridge clients over to tor's (Extended) ORPort.

use std::io;
use std::net::SocketAddr;

use super::stream::{BoxFuture, BoxStream};
use crate::shared::domain::pt::ServerInfo;

pub trait OrConnector: Send + Sync {
    /// Connects to the ORPort from `info` for a client at `peer` that came
    /// in over `method`.
    fn connect<'a>(
        &'a self,
        info: &'a ServerInfo,
        peer: &'a SocketAddr,
        method: &'a str,
    ) -> BoxFuture<'a, io::Result<BoxStream>>;
}
