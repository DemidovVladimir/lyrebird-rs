// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 client/lib/webrtc.go on top of str0m (sans-IO WebRTC)
// instead of pion.

//! One snowflake: a WebRTC data channel to a volunteer proxy.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};

use super::broker::BrokerChannel;
use super::events::{Event as SfEvent, EventSink};
use super::nat::NatPolicy;
use super::stun;
use super::turbotunnel::PacketCarrier;
use super::{encapsulation, ICE_GATHER_TIMEOUT};
use crate::log;
use crate::transports::BoxFuture;

pub const SNOWFLAKE_TIMEOUT: Duration = Duration::from_secs(20);
pub const DATA_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
/// Channel buffer level below which writes resume.
const BUFFERED_LOW: usize = 256 * 1024;

/// snowflake `util.IsLocal`: private, link-local or CGNAT (100.64/10).
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64)
        }
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn keep_host_candidate(ip: IpAddr, keep_local: bool) -> bool {
    keep_local || !(is_local(ip) || ip.is_loopback() || ip.is_unspecified())
}

/// Drops `a=candidate:` lines for host candidates we must not reveal
/// (pion never gathers them when local addresses are filtered).
fn strip_host_candidates(sdp: &str, keep_local: bool) -> String {
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive("\r\n") {
        if let Some(cand) = line.trim_end().strip_prefix("a=candidate:") {
            let fields: Vec<&str> = cand.split_whitespace().collect();
            let is_host = fields.windows(2).any(|w| w == ["typ", "host"]);
            if is_host {
                if let Some(ip) = fields.get(4).and_then(|a| a.parse::<IpAddr>().ok()) {
                    if !keep_host_candidate(ip, keep_local) {
                        continue;
                    }
                }
            }
        }
        out.push_str(line);
    }
    out
}

/// The local address the OS would use to reach `toward`.
async fn route_source(toward: SocketAddr) -> Option<IpAddr> {
    let probe = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    probe.connect(toward).await.ok()?;
    Some(probe.local_addr().ok()?.ip())
}

/// Resolves normalized `stun:host:port` URLs to IPv4 addresses.
async fn resolve_ice(servers: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for s in servers {
        let hostport = s.strip_prefix("stun:").unwrap_or(s).to_string();
        let lookup =
            tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(hostport)).await;
        if let Ok(Ok(mut addrs)) = lookup {
            if let Some(a) = addrs.find(SocketAddr::is_ipv4) {
                out.push(a);
            }
        }
    }
    out
}

struct Incoming {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

pub struct WebRtcPeer {
    pub id: String,
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: tokio::sync::Mutex<Incoming>,
    closed: watch::Sender<bool>,
    last_receive: Arc<Mutex<Instant>>,
    events: EventSink,
}

impl WebRtcPeer {
    pub async fn connect(
        ice_servers: &[String],
        broker: &BrokerChannel,
        nat_policy: &NatPolicy,
        events: EventSink,
    ) -> io::Result<Arc<WebRtcPeer>> {
        let mut idb = [0u8; 8];
        crate::common::csrand::bytes(&mut idb);
        let id = format!("snowflake-{}", hex::encode(idb));
        log::print(&format!("{id}  connecting..."));

        let prepared = prepare(&id, ice_servers, broker.keep_local_addresses).await;
        let (rtc, socket, host, cid, offer_sdp, pending) = match prepared {
            Ok(p) => {
                events.emit(SfEvent::OfferCreated(None));
                p
            }
            Err(e) => {
                events.emit(SfEvent::OfferCreated(Some(e.to_string())));
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
        let answer = match broker.negotiate(&offer_sdp, &to_send).await {
            Ok(a) => {
                events.emit(SfEvent::BrokerRendezvous(None));
                a
            }
            Err(e) => {
                events.emit(SfEvent::BrokerRendezvous(Some(e.to_string())));
                return Err(e);
            }
        };
        log::print("Received Answer.");

        let (out_tx, out_rx) = mpsc::channel(512);
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (open_tx, open_rx) = oneshot::channel();
        let peer = Arc::new(WebRtcPeer {
            id,
            outgoing: out_tx,
            incoming: tokio::sync::Mutex::new(Incoming {
                rx: in_rx,
                buf: Vec::new(),
                pos: 0,
            }),
            closed: watch::channel(false).0,
            last_receive: Arc::new(Mutex::new(Instant::now())),
            events: events.clone(),
        });

        let mut rtc = rtc;
        let answer = SdpAnswer::from_sdp_string(&answer)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if let Err(e) = rtc.sdp_api().accept_answer(pending, answer) {
            log::print(&format!("WebRTC: Unable to SetRemoteDescription: {e}"));
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }

        let mut guard = CloseOnDrop(Some(peer.clone()));
        tokio::spawn(drive(
            rtc,
            socket,
            host,
            cid,
            out_rx,
            in_tx,
            open_tx,
            peer.clone(),
        ));

        let opened = tokio::select! {
            r = open_rx => r.is_ok(),
            _ = tokio::time::sleep(DATA_CHANNEL_TIMEOUT) => false,
            _ = peer.wait_closed() => false,
        };
        if !opened {
            peer.close();
            nat_policy.failure(&actual, &to_send);
            let msg = "timeout waiting for DataChannel.OnOpen";
            events.emit(SfEvent::ConnectionFailed(msg.into()));
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
struct CloseOnDrop(Option<Arc<WebRtcPeer>>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            p.close();
        }
    }
}

type Prepared = (
    Rtc,
    UdpSocket,
    SocketAddr,
    ChannelId,
    String,
    SdpPendingOffer,
);

async fn prepare(id: &str, ice_servers: &[String], keep_local: bool) -> io::Result<Prepared> {
    let servers = resolve_ice(ice_servers).await;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let port = socket.local_addr()?.port();
    let toward = servers
        .first()
        .copied()
        .unwrap_or_else(|| "192.0.2.1:3478".parse().unwrap());
    let local_ip = route_source(toward)
        .await
        .filter(|ip| !ip.is_unspecified())
        .ok_or_else(|| io::Error::other("no usable local address"))?;
    let host = SocketAddr::new(local_ip, port);

    let mut rtc = RtcConfig::new().build(Instant::now());
    let host_candidate = Candidate::host(host, "udp")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    rtc.add_local_candidate(host_candidate);

    let mut seen = Vec::new();
    for (_, resp) in stun::bind_all(&socket, &servers, ICE_GATHER_TIMEOUT).await {
        if let Some(mapped) = resp.mapped.filter(|m| m.is_ipv4() && !seen.contains(m)) {
            seen.push(mapped);
            if let Ok(c) = Candidate::server_reflexive(mapped, host, "udp") {
                rtc.add_local_candidate(c);
            }
        }
    }

    let mut change = rtc.sdp_api();
    let cid = change.add_channel_with_config(ChannelConfig {
        label: id.to_string(),
        ordered: true,
        reliability: Reliability::Reliable,
        ..Default::default()
    });
    let (offer, pending) = change
        .apply()
        .ok_or_else(|| io::Error::other("Failed to prepare offer"))?;
    log::print("WebRTC: Created offer");
    let sdp = strip_host_candidates(&offer.to_sdp_string(), keep_local);
    Ok((rtc, socket, host, cid, sdp, pending))
}

#[allow(clippy::too_many_arguments)]
async fn drive(
    mut rtc: Rtc,
    socket: UdpSocket,
    host: SocketAddr,
    cid: ChannelId,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    incoming: mpsc::UnboundedSender<Vec<u8>>,
    open_tx: oneshot::Sender<()>,
    peer: Arc<WebRtcPeer>,
) {
    let mut open_tx = Some(open_tx);
    let mut open = false;
    let mut blocked: Option<Vec<u8>> = None;
    let mut buf = vec![0u8; 2048];
    loop {
        let timeout = loop {
            match rtc.poll_output() {
                Ok(Output::Timeout(t)) => break t,
                Ok(Output::Transmit(t)) => {
                    let _ = socket.send_to(&t.contents, t.destination).await;
                }
                Ok(Output::Event(e)) => match e {
                    Event::ChannelOpen(id, _) if id == cid => {
                        log::print("WebRTC: DataChannel.OnOpen");
                        peer.events.emit(SfEvent::Connected);
                        open = true;
                        if let Some(mut ch) = rtc.channel(cid) {
                            ch.set_buffered_amount_low_threshold(BUFFERED_LOW);
                        }
                        if let Some(tx) = open_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                    Event::ChannelData(d) if d.id == cid => {
                        if d.data.is_empty() {
                            log::print("0 length message---");
                        }
                        *peer.last_receive.lock().unwrap() = Instant::now();
                        let _ = incoming.send(d.data);
                    }
                    Event::ChannelClose(id) if id == cid => {
                        log::print("WebRTC: DataChannel.OnClose");
                        peer.close();
                    }
                    Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                        peer.close();
                    }
                    _ => {}
                },
                Err(e) => {
                    log::print(&format!("WebRTC: {e}"));
                    peer.close();
                    break Instant::now();
                }
            }
        };
        if peer.is_closed() || !rtc.is_alive() {
            peer.close();
            rtc.disconnect();
            return;
        }

        // Retry a message the channel refused earlier.
        if open {
            if let Some(msg) = blocked.take() {
                match rtc.channel(cid).map(|mut ch| ch.write(true, &msg)) {
                    Some(Ok(true)) => continue,
                    Some(Ok(false)) => blocked = Some(msg),
                    _ => {
                        peer.close();
                        continue;
                    }
                }
            }
        }

        let wait = timeout.saturating_duration_since(Instant::now());
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                if let Ok((n, source)) = r {
                    if let Ok(receive) = Receive::new(Protocol::Udp, source, host, &buf[..n]) {
                        let input = Input::Receive(Instant::now(), receive);
                        if rtc.accepts(&input) {
                            if let Err(e) = rtc.handle_input(input) {
                                log::print(&format!("WebRTC: {e}"));
                            }
                        }
                    }
                }
            }
            m = outgoing.recv(), if open && blocked.is_none() => {
                match m {
                    Some(msg) => match rtc.channel(cid).map(|mut ch| ch.write(true, &msg)) {
                        Some(Ok(true)) => {}
                        Some(Ok(false)) => blocked = Some(msg),
                        _ => peer.close(),
                    },
                    None => peer.close(),
                }
            }
            _ = tokio::time::sleep(wait) => {
                let _ = rtc.handle_input(Input::Timeout(Instant::now()));
            }
            _ = peer.wait_closed() => {}
        }
    }
}

async fn check_for_staleness(peer: Arc<WebRtcPeer>, timeout: Duration) {
    *peer.last_receive.lock().unwrap() = Instant::now();
    loop {
        let last = *peer.last_receive.lock().unwrap();
        if last.elapsed() > timeout {
            log::print(&format!(
                "WebRTC: No messages received for {timeout:?} -- closing stale connection."
            ));
            peer.events.emit(SfEvent::ConnectionFailed(
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
    peer: Arc<WebRtcPeer>,
    reader: tokio::sync::Mutex<PeerReader>,
}

struct PeerReader(Arc<WebRtcPeer>);

impl encapsulation::ByteRead for PeerReader {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(self.0.read(buf))
    }
}

impl SnowflakeCarrier {
    pub fn new(peer: Arc<WebRtcPeer>) -> SnowflakeCarrier {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "100.128.0.1", "2001:db8::1"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn strips_only_local_host_candidates() {
        let sdp = "v=0\r\n\
            a=candidate:1 1 udp 2130706431 172.21.0.5 44209 typ host\r\n\
            a=candidate:2 1 udp 2130706431 203.0.113.5 44209 typ host\r\n\
            a=candidate:3 1 udp 1694498815 172.21.0.5 41627 typ srflx raddr 0.0.0.0 rport 41627\r\n\
            a=end-of-candidates\r\n";
        let out = strip_host_candidates(sdp, false);
        assert!(!out.contains("172.21.0.5 44209 typ host"));
        assert!(out.contains("203.0.113.5 44209 typ host"));
        assert!(out.contains("typ srflx"));
        assert_eq!(strip_host_candidates(sdp, true), sdp);
    }
}
