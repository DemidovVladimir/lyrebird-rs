// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 client/lib (snowflake.go, peers.go).

//! A snowflake session: a pool of snowflakes kept topped up, and a Turbo
//! Tunnel (KCP + smux) across them so one tor connection survives proxy
//! churn.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use super::broker::BrokerChannel;
use super::config::{parse_ice_servers, shuffle, ClientConfig};
use super::events::EventSink;
use super::kcp_session::KcpSession;
use super::nat::{self, NatPolicy};
use super::peer::{Peer, SnowflakeCarrier};
use super::smux;
use super::transport::{Ports, RECONNECT_TIMEOUT, STREAM_SIZE, WINDOW_SIZE};
use super::turbotunnel::{self, DialFn, PacketCarrier, RedialPacketConn, TOKEN};
use crate::shared::ports::log;
use crate::shared::ports::transport::{Conn, ReadHalf, WriteHalf};
use crate::shared::ports::BoxFuture;
use crate::transports::snowflake::ports::webrtc::WebRtc;

/// snowflake `WebRTCDialer`: catches one snowflake per call.
struct WebRtcDialer {
    webrtc: Arc<dyn WebRtc>,
    broker: Arc<BrokerChannel>,
    nat_policy: NatPolicy,
    ice_servers: Vec<String>,
    max: usize,
    events: EventSink,
}

impl WebRtcDialer {
    async fn catch(&self) -> io::Result<Arc<Peer>> {
        Peer::connect(
            &*self.webrtc,
            &self.ice_servers,
            &self.broker,
            &self.nat_policy,
            self.events.clone(),
        )
        .await
    }
}

/// snowflake `Peers`: the pool of connected snowflakes for one session.
struct Peers {
    dialer: WebRtcDialer,
    tx: mpsc::Sender<Arc<Peer>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Arc<Peer>>>,
    active: Mutex<Vec<Arc<Peer>>>,
    melt: watch::Sender<bool>,
    collect_lock: tokio::sync::Mutex<()>,
}

impl Peers {
    fn new(dialer: WebRtcDialer) -> Arc<Peers> {
        let (tx, rx) = mpsc::channel(dialer.max);
        Arc::new(Peers {
            dialer,
            tx,
            rx: tokio::sync::Mutex::new(rx),
            active: Mutex::new(Vec::new()),
            melt: watch::channel(false).0,
            collect_lock: tokio::sync::Mutex::new(()),
        })
    }

    fn is_melted(&self) -> bool {
        *self.melt.borrow()
    }

    async fn melted(&self) {
        let mut rx = self.melt.subscribe();
        let _ = rx.wait_for(|m| *m).await;
    }

    fn count(&self) -> usize {
        let mut active = self.active.lock().unwrap();
        active.retain(|p| !p.is_closed());
        active.len()
    }

    async fn collect(&self) -> Result<(), String> {
        let _guard = self.collect_lock.lock().await;
        if self.is_melted() {
            return Err("Snowflakes have melted".into());
        }
        let cnt = self.count();
        let capacity = self.dialer.max;
        if cnt >= capacity {
            return Err(format!("At capacity [{cnt}/{capacity}]"));
        }
        log::print(&format!(
            "WebRTC: Collecting a new Snowflake. Currently at [{cnt}/{capacity}]"
        ));
        let peer = tokio::select! {
            r = self.dialer.catch() => r.map_err(|e| e.to_string())?,
            _ = self.melted() => return Err("Snowflakes have melted".into()),
        };
        self.active.lock().unwrap().push(peer.clone());
        tokio::select! {
            r = self.tx.send(peer.clone()) => r.map_err(|_| "Snowflakes have melted".to_string()),
            _ = self.melted() => {
                peer.close();
                Err("Snowflakes have melted".into())
            }
        }
    }

    /// Next open snowflake, or `None` once melted.
    async fn pop(&self) -> Option<Arc<Peer>> {
        let mut rx = self.rx.lock().await;
        loop {
            tokio::select! {
                p = rx.recv() => match p {
                    Some(p) if p.is_closed() => continue,
                    other => return other,
                },
                _ = self.melted() => return None,
            }
        }
    }

    fn end(&self) {
        if !self.melt.send_if_modified(|m| !std::mem::replace(m, true)) {
            return;
        }
        let peers: Vec<_> = self.active.lock().unwrap().drain(..).collect();
        let cnt = peers.iter().filter(|p| !p.is_closed()).count();
        for p in peers {
            p.close();
        }
        log::print(&format!("WebRTC: melted all {cnt} snowflakes."));
    }
}

async fn connect_loop(peers: Arc<Peers>) {
    loop {
        let timer = tokio::time::sleep(RECONNECT_TIMEOUT);
        if let Err(e) = peers.collect().await {
            log::print(&format!("WebRTC: {e}  Retrying..."));
        }
        tokio::select! {
            _ = timer => continue,
            _ = peers.melted() => {
                log::print("ConnectLoop: stopped.");
                return;
            }
        }
    }
}

type Session = (Arc<RedialPacketConn>, Arc<KcpSession>, smux::Session);

/// snowflake `newSession`: Turbo Tunnel over redialed snowflakes.
fn new_session(peers: Arc<Peers>) -> io::Result<Session> {
    let client_id = turbotunnel::new_client_id();
    let dial: DialFn = Box::new(move || {
        let peers = peers.clone();
        Box::pin(async move {
            log::print("redialing on same connection");
            let peer = peers
                .pop()
                .await
                .ok_or_else(|| io::Error::other("handler: Received invalid Snowflake"))?;
            log::print("---- Handler: snowflake assigned ----");
            peer.write(TOKEN.to_vec()).await?;
            peer.write(client_id.to_vec()).await?;
            Ok(Arc::new(SnowflakeCarrier::new(peer)) as Arc<dyn PacketCarrier>)
        })
    });
    let pconn = RedialPacketConn::new(dial);
    let kcp = KcpSession::new(pconn.clone());
    kcp.configure(|k| {
        k.set_stream(true);
        k.wnd_size(WINDOW_SIZE, WINDOW_SIZE);
        // Default nodelay, interval and resend; congestion window off.
        k.nodelay(0, 0, 0, 1);
    });
    let config = smux::Config {
        version: 2,
        keepalive_timeout: Duration::from_secs(600),
        max_stream_buffer: STREAM_SIZE,
        ..Default::default()
    };
    match smux::Session::client(kcp.clone(), config) {
        Ok(sess) => Ok((pconn, kcp, sess)),
        Err(e) => {
            kcp.close();
            pconn.close();
            Err(io::Error::other(e))
        }
    }
}

/// snowflake `Transport`, built per dial as lyrebird does.
pub struct SnowflakeClient {
    dialer: WebRtcDialer,
}

impl SnowflakeClient {
    pub fn new(
        config: &ClientConfig,
        ports: &Ports,
        events: EventSink,
    ) -> Result<SnowflakeClient, String> {
        log::print("\n\n\n --- Starting Snowflake Client ---");
        let mut ice_servers = parse_ice_servers(&config.ice_addresses);
        shuffle(&mut ice_servers);
        if ice_servers.len() > 2 {
            ice_servers.truncate(ice_servers.len().div_ceil(2));
        }
        log::print("Using ICE servers:");
        for s in &ice_servers {
            log::print(&format!("url: {s}"));
        }
        let broker = Arc::new(BrokerChannel::new(&config.broker, &*ports.rendezvous)?);
        tokio::spawn(nat::update_nat_type(
            ice_servers.clone(),
            broker.clone(),
            ports.nat_probe.clone(),
        ));
        Ok(SnowflakeClient {
            dialer: WebRtcDialer {
                webrtc: ports.webrtc.clone(),
                broker,
                nat_policy: NatPolicy::default(),
                ice_servers,
                max: config.max.max(1) as usize,
                events,
            },
        })
    }

    pub async fn dial(self) -> io::Result<Conn> {
        let peers = Peers::new(self.dialer);
        log::print("---- SnowflakeConn: begin collecting snowflakes ---");
        tokio::spawn(connect_loop(peers.clone()));
        log::print("---- SnowflakeConn: starting a new session ---");
        let (pconn, kcp, sess) = match new_session(peers.clone()) {
            Ok(s) => s,
            Err(e) => {
                peers.end();
                return Err(e);
            }
        };
        let stream = match sess.open_stream().await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                pconn.close();
                sess.close();
                peers.end();
                return Err(e);
            }
        };
        log::print(&format!(
            "---- SnowflakeConn: begin stream {} ---",
            stream.id()
        ));
        let inner = Arc::new(SnowflakeConn {
            stream,
            sess: Arc::new(sess),
            pconn,
            _kcp: kcp,
            peers,
        });
        Ok(Conn {
            reader: Box::new(ConnHalf(inner.clone())),
            writer: Box::new(ConnHalf(inner)),
        })
    }
}

/// An smux stream plus everything that keeps it alive; torn down when both
/// halves are dropped (upstream `SnowflakeConn.Close`).
struct SnowflakeConn {
    stream: Arc<smux::Stream>,
    sess: Arc<smux::Session>,
    pconn: Arc<RedialPacketConn>,
    _kcp: Arc<KcpSession>,
    peers: Arc<Peers>,
}

impl Drop for SnowflakeConn {
    fn drop(&mut self) {
        let stream = self.stream.clone();
        let sess = self.sess.clone();
        let pconn = self.pconn.clone();
        let peers = self.peers.clone();
        let close = async move {
            log::print(&format!(
                "---- SnowflakeConn: closed stream {} ---",
                stream.id()
            ));
            let _ = stream.close().await;
            log::print("---- SnowflakeConn: end collecting snowflakes ---");
            peers.end();
            pconn.close();
            log::print("---- SnowflakeConn: discarding finished session ---");
            sess.close();
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(close);
            }
            Err(_) => {
                self.peers.end();
                self.pconn.close();
                self.sess.close();
            }
        }
    }
}

struct ConnHalf(Arc<SnowflakeConn>);

impl ReadHalf for ConnHalf {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            match self.0.stream.read(buf).await {
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
                r => r,
            }
        })
    }
}

impl WriteHalf for ConnHalf {
    fn write_all<'a>(&'a mut self, mut buf: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            while !buf.is_empty() {
                let n = self.0.stream.write(buf).await?;
                if n == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                buf = &buf[n..];
            }
            Ok(())
        })
    }

    fn shutdown(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move { self.0.stream.close().await })
    }
}
