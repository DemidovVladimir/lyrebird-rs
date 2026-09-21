// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 client/lib/webrtc.go (WebRTCPeer, minus the WebRTC
// stack itself).

//! One snowflake: catching it (offer, broker rendezvous, answer), its data
//! channel as a pipe, and its lifecycle.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, watch};

use super::broker::BrokerChannel;
use super::encapsulation;
use super::events::{Event, EventSink};
use super::nat::NatPolicy;
use super::turbotunnel::PacketCarrier;
use crate::shared::ports::log;
use crate::shared::ports::BoxFuture;
use crate::transports::snowflake::ports::webrtc::{ChannelLink, WebRtc};

pub const SNOWFLAKE_TIMEOUT: Duration = Duration::from_secs(20);
pub const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

struct Incoming {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

pub struct Peer {
    pub id: String,
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: tokio::sync::Mutex<Incoming>,
    closed: watch::Sender<bool>,
    last_receive: Mutex<Instant>,
    events: EventSink,
}

impl Peer {
    /// Catches one snowflake through `broker`.
    pub async fn connect(
        webrtc: &dyn WebRtc,
        ice_servers: &[String],
        broker: &BrokerChannel,
        nat_policy: &NatPolicy,
        events: EventSink,
    ) -> io::Result<Arc<Peer>> {
        let mut idb = [0u8; 8];
        crate::shared::domain::crypto::csrand::bytes(&mut idb);
        let id = format!("snowflake-{}", hex::encode(idb));
        log::print(&format!("{id}  connecting..."));

        let offer = match webrtc
            .offer(&id, ice_servers, broker.keep_local_addresses)
            .await
        {
            Ok(o) => {
                events.emit(Event::OfferCreated(None));
                o
            }
            Err(e) => {
                events.emit(Event::OfferCreated(Some(e.to_string())));
                return Err(e);
            }
        };

        let actual = broker.nat_type();
        let to_send = nat_policy.nat_type_to_send(&actual);
        if to_send != actual {
            log::print(&format!(
                "Our NAT type is \"{actual}\", but let's tell the broker it's \"{to_send}\"."
            ));
        }
        let answer = match broker.negotiate(offer.sdp(), &to_send).await {
            Ok(a) => {
                events.emit(Event::BrokerRendezvous(None));
                a
            }
            Err(e) => {
                events.emit(Event::BrokerRendezvous(Some(e.to_string())));
                return Err(e);
            }
        };
        log::print("Received Answer.");

        let (out_tx, out_rx) = mpsc::channel(512);
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (open_tx, open_rx) = oneshot::channel();
        let peer = Arc::new(Peer {
            id,
            outgoing: out_tx,
            incoming: tokio::sync::Mutex::new(Incoming {
                rx: in_rx,
                buf: Vec::new(),
                pos: 0,
            }),
            closed: watch::channel(false).0,
            last_receive: Mutex::new(Instant::now()),
            events: events.clone(),
        });

        offer.start(
            &answer,
            ChannelLink {
                outgoing: out_rx,
                incoming: in_tx,
                opened: open_tx,
                peer: peer.clone(),
            },
        )?;
        let mut guard = CloseOnDrop(Some(peer.clone()));

        let opened = tokio::select! {
            r = open_rx => r.is_ok(),
            _ = tokio::time::sleep(DATA_CHANNEL_TIMEOUT) => false,
            _ = peer.wait_closed() => false,
        };
        if !opened {
            peer.close();
            nat_policy.failure(&actual, &to_send);
            let msg = "timeout waiting for DataChannel.OnOpen";
            events.emit(Event::ConnectionFailed(msg.into()));
            return Err(io::Error::new(io::ErrorKind::TimedOut, msg));
        }
        guard.0 = None;
        nat_policy.success(&actual, &to_send);
        tokio::spawn(check_for_staleness(peer.clone(), SNOWFLAKE_TIMEOUT));
        Ok(peer)
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    pub async fn wait_closed(&self) {
        let mut rx = self.closed.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    pub fn close(&self) {
        if self
            .closed
            .send_if_modified(|c| !std::mem::replace(c, true))
        {
            log::print("WebRTC: Closing");
        }
    }

    /// The data channel opened.
    pub fn opened(&self) {
        self.events.emit(Event::Connected);
    }

    /// A message arrived (keeps the snowflake from going stale).
    pub fn received(&self) {
        *self.last_receive.lock().unwrap() = Instant::now();
    }

    /// Pipe-like read of the concatenated data channel messages.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut inc = self.incoming.lock().await;
        while inc.pos >= inc.buf.len() {
            let msg = tokio::select! {
                m = inc.rx.recv() => m,
                _ = self.wait_closed() => None,
            };
            match msg {
                Some(m) => {
                    inc.buf = m;
                    inc.pos = 0;
                }
                None => return Ok(0),
            }
        }
        let n = (inc.buf.len() - inc.pos).min(buf.len());
        let pos = inc.pos;
        buf[..n].copy_from_slice(&inc.buf[pos..pos + n]);
        inc.pos += n;
        Ok(n)
    }

    /// Sends one data channel message.
    pub async fn write(&self, msg: Vec<u8>) -> io::Result<()> {
        if self.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.outgoing
            .send(msg)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

/// Closes a peer whose `connect` was cancelled before it was handed out.
struct CloseOnDrop(Option<Arc<Peer>>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            p.close();
        }
    }
}

async fn check_for_staleness(peer: Arc<Peer>, timeout: Duration) {
    peer.received();
    loop {
        let last = *peer.last_receive.lock().unwrap();
        if last.elapsed() > timeout {
            log::print(&format!(
                "WebRTC: No messages received for {timeout:?} -- closing stale connection."
            ));
            peer.events.emit(Event::ConnectionFailed(
                "no messages received, closing stale connection".into(),
            ));
            peer.close();
            return;
        }
        tokio::select! {
            _ = peer.wait_closed() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

/// Turbo Tunnel carrier over one snowflake: each packet is one
/// encapsulated data channel message.
pub struct SnowflakeCarrier {
    peer: Arc<Peer>,
    reader: tokio::sync::Mutex<PeerReader>,
}

struct PeerReader(Arc<Peer>);

impl encapsulation::ByteRead for PeerReader {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(self.0.read(buf))
    }
}

impl SnowflakeCarrier {
    pub fn new(peer: Arc<Peer>) -> SnowflakeCarrier {
        SnowflakeCarrier {
            reader: tokio::sync::Mutex::new(PeerReader(peer.clone())),
            peer,
        }
    }
}

impl PacketCarrier for SnowflakeCarrier {
    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            let mut r = self.reader.lock().await;
            match encapsulation::read_data(&mut *r, buf).await? {
                Some(n) => Ok(n),
                None => Err(io::ErrorKind::UnexpectedEof.into()),
            }
        })
    }

    fn send<'a>(&'a self, pkt: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.peer.write(encapsulation::encode_data(pkt)?).await })
    }

    fn close(&self) {
        self.peer.close();
    }
}
