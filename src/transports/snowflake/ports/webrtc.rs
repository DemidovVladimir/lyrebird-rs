// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause

//! A WebRTC stack: one peer connection with one reliable, ordered data
//! channel per snowflake.

use std::io;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use crate::shared::ports::BoxFuture;
use crate::transports::snowflake::domain::peer::Peer;

pub trait WebRtc: Send + Sync {
    /// Gathers candidates (host, and server-reflexive via `ice_servers`) and
    /// creates an offer for a data channel labeled `label`. Local host
    /// candidates are left out unless `keep_local_addresses`.
    fn offer<'a>(
        &'a self,
        label: &'a str,
        ice_servers: &'a [String],
        keep_local_addresses: bool,
    ) -> BoxFuture<'a, io::Result<Box<dyn PendingOffer>>>;
}

/// An offer waiting for the proxy's answer.
pub trait PendingOffer: Send {
    /// The offer SDP for the broker.
    fn sdp(&self) -> &str;
    /// Applies `answer_sdp` and runs the connection in the background,
    /// wired to `link`, until the peer closes.
    fn start(self: Box<Self>, answer_sdp: &str, link: ChannelLink) -> io::Result<()>;
}

/// How the WebRTC stack and a snowflake exchange data channel messages.
pub struct ChannelLink {
    /// Messages to send.
    pub outgoing: mpsc::Receiver<Vec<u8>>,
    /// Messages received.
    pub incoming: mpsc::UnboundedSender<Vec<u8>>,
    /// Fired once the data channel is open.
    pub opened: oneshot::Sender<()>,
    /// The snowflake's lifecycle: closed from either side.
    pub peer: Arc<Peer>,
}
