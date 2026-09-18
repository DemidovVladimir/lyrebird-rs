// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of lyrebird transports/snowflake and snowflake/v2 client/lib
// (snowflake.go, peers.go).

//! Snowflake: WebRTC data channels to volunteer proxies, rendezvous via a
//! broker, with KCP + smux (Turbo Tunnel) on top so sessions survive proxy
//! churn.

pub mod amp;
pub mod broker;
pub mod encapsulation;
pub mod events;
pub mod kcp;
pub mod kcp_session;
pub mod nat;
pub mod smux;
pub mod sqs;
pub mod stun;
pub mod turbotunnel;
pub mod webrtc;

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use self::broker::{BrokerChannel, BrokerConfig};
use self::events::EventSink;
use self::kcp_session::KcpSession;
use self::nat::NatPolicy;
use self::turbotunnel::{DialFn, PacketCarrier, RedialPacketConn, TOKEN};
use self::webrtc::{SnowflakeCarrier, WebRtcPeer};
use crate::log;
use crate::proxy::Dialer;
use crate::pt::Args;
use crate::transports::{
    self, BoxError, BoxFuture, ClientArgs, Conn, DialError, ReadHalf, WriteHalf,
};

const TRANSPORT_NAME: &str = "snowflake";
/// pion's server-reflexive gathering timeout.
pub const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const WINDOW_SIZE: i32 = 65535;
pub const STREAM_SIZE: usize = 1024 * 1024;

pub struct Transport;

impl transports::Transport for Transport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn client_factory(
        &self,
        _state_dir: &Path,
    ) -> Result<Arc<dyn transports::ClientFactory>, BoxError> {
        Ok(Arc::new(ClientFactory {
            events: EventSink::default(),
        }))
    }

    fn server_factory(
        &self,
        _state_dir: &Path,
        _args: &Args,
    ) -> Result<Arc<dyn transports::ServerFactory>, BoxError> {
        Err("ServerFactory not implemented for the snowflake transport".into())
    }
}

/// snowflake `ClientConfig`.
#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    pub broker: BrokerConfig,
    pub ice_addresses: Vec<String>,
    pub max: i64,
}

fn split_list(s: &str) -> Vec<String> {
    s.trim().split(',').map(str::to_string).collect()
}

/// lyrebird's snowflake `ParseArgs`.
pub fn parse_client_args(args: &Args) -> Result<ClientConfig, String> {
    let mut c = ClientConfig::default();
    if let Some(v) = args.get("ampcache") {
        c.broker.amp_cache_url = v.into();
    }
    if let Some(v) = args.get("sqsqueue") {
        c.broker.sqs_queue_url = v.into();
    }
    if let Some(v) = args.get("sqscreds") {
        c.broker.sqs_creds = v.into();
    }
    if let Some(v) = args.get("fronts") {
        if !v.is_empty() {
            c.broker.front_domains = split_list(v);
        }
    } else if let Some(v) = args.get("front") {
        c.broker.front_domains = split_list(v);
    }
    if let Some(v) = args.get("ice") {
        c.ice_addresses = split_list(v);
    }
    if let Some(v) = args.get("max") {
        c.max = v
            .parse()
            .map_err(|_| format!("Invalid SOCKS arg: max={v}"))?;
    }
    if let Some(v) = args.get("url") {
        c.broker.broker_url = v.into();
    }
    if let Some(v) = args.get("utls-nosni") {
        c.broker.utls_remove_sni = matches!(v.to_ascii_lowercase().as_str(), "true" | "yes");
    }
    if let Some(v) = args.get("utls-imitate") {
        c.broker.utls_client_id = v.into();
    }
    if let Some(v) = args.get("fingerprint") {
        c.broker.bridge_fingerprint = v.into();
    }
    if let Some(v) = args.get("proxy") {
        let spec = crate::proxy::parse_proxy_uri(v)
            .map_err(|_| format!("Invalid SOCKS arg: proxy={v}"))?;
        if spec.scheme != "socks5" {
            return Err("proxy is not supported: unsupported proxy type".into());
        }
        // Upstream relays WebRTC through SOCKS5 UDP ASSOCIATE; not ported yet.
        return Err(
            "proxy is not supported: SOCKS5 UDP relaying is not implemented in lyrebird-rs".into(),
        );
    }
    Ok(c)
}

/// pion `ice.ParseURL` for `stun:` URLs, re-serialized as `stun:host:port`.
fn parse_stun_url(address: &str) -> Result<String, String> {
    let rest = address.strip_prefix("stun:").ok_or("unknown scheme type")?;
    if rest.contains(['?', '/', '#']) {
        return Err("queries not supported in stun address".into());
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').ok_or("missing ']' in address")?;
        match tail {
            "" => (h, None),
            t => (h, Some(t.strip_prefix(':').ok_or("invalid port")?)),
        }
    } else {
        match rest.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return Err("too many colons in address".into()),
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    let port: u16 = match port {
        None => 3478,
        Some(p) => p.parse().map_err(|_| "invalid port".to_string())?,
    };
    Ok(if host.contains(':') {
        format!("stun:[{host}]:{port}")
    } else {
        format!("stun:{host}:{port}")
    })
}

/// snowflake `parseIceServers`: keeps valid `stun:` servers only.
pub fn parse_ice_servers(addresses: &[String]) -> Vec<String> {
    let mut servers = Vec::new();
    for address in addresses {
        let address = address.trim();
        let scheme = address.split_once(':').map(|(s, _)| s.to_ascii_lowercase());
        if scheme.as_deref() != Some("stun") {
            log::print(&format!(
                "Warning: Only stun: (STUN over UDP) servers are supported currently, skipping {address}"
            ));
            continue;
        }
        match parse_stun_url(address) {
            Ok(s) => servers.push(s),
            Err(e) => log::print(&format!(
                "Warning: Parsing ICE server {address} resulted in error: {e}, skipping"
            )),
        }
    }
    servers
}

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = crate::common::csrand::intn(i as i64 + 1) as usize;
        v.swap(i, j);
    }
}

/// snowflake `WebRTCDialer`: catches one snowflake per call.
struct WebRtcDialer {
    broker: Arc<BrokerChannel>,
    nat_policy: NatPolicy,
    ice_servers: Vec<String>,
    max: usize,
    events: EventSink,
}

impl WebRtcDialer {
    async fn catch(&self) -> io::Result<Arc<WebRtcPeer>> {
        WebRtcPeer::connect(
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
    tx: mpsc::Sender<Arc<WebRtcPeer>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Arc<WebRtcPeer>>>,
    active: Mutex<Vec<Arc<WebRtcPeer>>>,
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
    async fn pop(&self) -> Option<Arc<WebRtcPeer>> {
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
    pub fn new(config: &ClientConfig, events: EventSink) -> Result<SnowflakeClient, String> {
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
        let broker = Arc::new(BrokerChannel::new(&config.broker, Dialer::Direct)?);
        tokio::spawn(nat::update_nat_type(ice_servers.clone(), broker.clone()));
        Ok(SnowflakeClient {
            dialer: WebRtcDialer {
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

pub struct ClientFactory {
    events: EventSink,
}

impl transports::ClientFactory for ClientFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn parse_args(&self, args: &Args) -> Result<ClientArgs, BoxError> {
        Ok(Box::new(parse_client_args(args)?))
    }

    fn dial<'a>(
        &'a self,
        _target: &'a str,
        dialer: &'a Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>> {
        Box::pin(async move {
            let config = args
                .downcast::<ClientConfig>()
                .map_err(|_| DialError::Other("invalid type for args".into()))?;
            if *dialer != Dialer::Direct {
                // Upstream silently bypasses TOR_PT_PROXY here; refuse instead.
                return Err(DialError::Other(
                    "snowflake: TOR_PT_PROXY is not supported yet (needs SOCKS5 UDP relaying)"
                        .into(),
                ));
            }
            let client = SnowflakeClient::new(&config, self.events.clone())
                .map_err(|e| DialError::Other(e.into()))?;
            Ok(client.dial().await?)
        })
    }

    fn on_event(&self, f: Arc<dyn Fn(String) + Send + Sync>) {
        self.events.set(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Args {
        let mut a = Args::new();
        for (k, v) in pairs {
            a.add(k, v);
        }
        a
    }

    #[test]
    fn parses_lyrebird_args() {
        let c = parse_client_args(&args(&[
            ("url", "https://1098762253.rsc.cdn77.org/"),
            ("fronts", "www.cdn77.com,www.phpmyadmin.net"),
            ("front", "ignored.example"),
            (
                "ice",
                " stun:stun.antisip.com:3478,stun:stun.epygi.com:3478 ",
            ),
            ("utls-imitate", "hellorandomizedalpn"),
            ("utls-nosni", "YES"),
            ("fingerprint", "2B280B23E1107BB62ABFC40DDCC8824814F80A72"),
            ("max", "3"),
        ]))
        .unwrap();
        assert_eq!(c.broker.broker_url, "https://1098762253.rsc.cdn77.org/");
        assert_eq!(
            c.broker.front_domains,
            ["www.cdn77.com", "www.phpmyadmin.net"]
        );
        assert_eq!(
            c.ice_addresses,
            ["stun:stun.antisip.com:3478", "stun:stun.epygi.com:3478"]
        );
        assert_eq!(c.broker.utls_client_id, "hellorandomizedalpn");
        assert!(c.broker.utls_remove_sni);
        assert_eq!(
            c.broker.bridge_fingerprint,
            "2B280B23E1107BB62ABFC40DDCC8824814F80A72"
        );
        assert_eq!(c.max, 3);

        let c =
            parse_client_args(&args(&[("fronts", ""), ("front", "a.example,b.example")])).unwrap();
        assert!(c.broker.front_domains.is_empty());
        let c = parse_client_args(&args(&[("front", "a.example,b.example")])).unwrap();
        assert_eq!(c.broker.front_domains, ["a.example", "b.example"]);
        assert_eq!(
            parse_client_args(&args(&[("max", "x")])).unwrap_err(),
            "Invalid SOCKS arg: max=x"
        );
        assert!(parse_client_args(&args(&[("proxy", "http://127.0.0.1:1")]))
            .unwrap_err()
            .contains("unsupported proxy type"));
        assert!(parse_client_args(&args(&[("proxy", "socks5://127.0.0.1:1")])).is_err());
    }

    #[test]
    fn parses_ice_servers_like_pion() {
        let input: Vec<String> = [
            "stun:stun.l.google.com:19302",
            " stun:stun.example ",
            "stun:[2001:db8::1]:3479",
            "stun:[2001:db8::2]",
            "turn:turn.example:3478",
            "stuns:stun.example:5349",
            "stun:host:notaport",
            "stun::3478",
            "stun:host:3478?transport=udp",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            parse_ice_servers(&input),
            [
                "stun:stun.l.google.com:19302",
                "stun:stun.example:3478",
                "stun:[2001:db8::1]:3479",
                "stun:[2001:db8::2]:3478",
            ]
        );
    }

    #[test]
    fn shuffles_every_element() {
        let mut v: Vec<u32> = (0..32).collect();
        shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(sorted, (0..32).collect::<Vec<_>>());
    }
}
