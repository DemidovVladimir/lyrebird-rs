// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of lyrebird cmd/lyrebird (clientSetup, clientAcceptLoop,
// clientHandler).

//! Client mode: one SOCKS5 listener per transport tor asked for; each
//! request is dialed through the transport and relayed.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;

use super::registry::Registry;
use super::relay::copy_loop;
use super::termmon::TermMonitor;
use super::Ports;
use crate::shared::domain::proxy;
use crate::shared::domain::pt::managed;
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::log;
use crate::shared::ports::net::Listener;
use crate::shared::ports::socks::{self, ReplyCode, SocksServer};
use crate::shared::ports::stream::BoxStream;
use crate::shared::ports::transport::{ClientFactory, Conn, DialError};
use crate::VERSION;

/// tor connects to the SOCKS listeners over loopback.
const SOCKS_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

/// Registers the requested transports with tor (`CMETHOD` lines) and starts
/// their listeners. `Err` is fatal.
pub async fn setup(
    ports: &Ports,
    registry: &Registry,
    term: &TermMonitor,
) -> Result<Vec<JoinHandle<()>>, String> {
    let (env, tor) = (&*ports.env, &ports.tor);
    let info = managed::client_setup(env, tor).map_err(|e| e.to_string())?;
    tor.report_version("lyrebird-rs", VERSION);
    let dialer = match proxy::from_env(env, tor) {
        Ok(None) => ports.net.dialer(None),
        Ok(Some(config)) => {
            tor.proxy_done();
            ports.net.dialer(Some(&config))
        }
        Err(e) => return Err(e.to_string()),
    };

    let mut listeners = Vec::new();
    for name in &info.method_names {
        let Some(t) = registry.get(name) else {
            tor.cmethod_error(name, "no such transport is supported");
            continue;
        };
        let Ok(f) = t.client_factory() else {
            tor.cmethod_error(name, "failed to get ClientFactory");
            continue;
        };
        let ln = match ports.net.listen(SOCKS_ADDR).await {
            Ok(l) => l,
            Err(e) => {
                tor.cmethod_error(name, &e.to_string());
                continue;
            }
        };
        let addr = ln.local_addr();
        let task = tokio::spawn(accept_loop(
            f,
            ln,
            ports.socks.clone(),
            dialer.clone(),
            term.clone(),
        ));
        tor.cmethod(name, socks::VERSION_STRING, &addr);
        log::info(&format!("{name} - registered listener: {addr}"));
        listeners.push(task);
    }
    tor.cmethods_done();
    Ok(listeners)
}

async fn accept_loop(
    f: Arc<dyn ClientFactory>,
    ln: Box<dyn Listener>,
    socks: Arc<dyn SocksServer>,
    dialer: Arc<dyn Dialer>,
    term: TermMonitor,
) {
    while let Ok((conn, _)) = ln.accept().await {
        let (f, socks, dialer, term) = (f.clone(), socks.clone(), dialer.clone(), term.clone());
        tokio::spawn(async move {
            let _guard = term.handler();
            handle(f, conn, &*socks, &*dialer).await;
        });
    }
}

/// One connection from tor: SOCKS request, dial through the transport,
/// relay until either side is done.
async fn handle(
    f: Arc<dyn ClientFactory>,
    conn: BoxStream,
    socks: &dyn SocksServer,
    dialer: &dyn Dialer,
) {
    let name = f.transport_name();
    let mut req = match socks.handshake(conn).await {
        Ok(r) => r,
        Err(e) => {
            log::error(&format!("{name} - client failed socks handshake: {e}"));
            return;
        }
    };
    let addr_str = log::elide_addr(req.target());
    let args = match f.parse_args(req.args()) {
        Ok(a) => a,
        Err(e) => {
            log::error(&format!("{name}({addr_str}) - invalid arguments: {e}"));
            let _ = req.reply(ReplyCode::GeneralFailure).await;
            return;
        }
    };
    let remote = match f.dial(req.target(), dialer, args).await {
        Ok(c) => c,
        Err(e) => {
            let (text, code) = match &e {
                DialError::Io(io) => (log::elide_error(io), socks::error_to_reply_code(io)),
                DialError::Other(o) => (log::elide_error(o.as_ref()), ReplyCode::GeneralFailure),
            };
            log::error(&format!(
                "{name}({addr_str}) - outgoing connection failed: {text}"
            ));
            let _ = req.reply(code).await;
            return;
        }
    };
    if let Err(e) = req.reply(ReplyCode::Succeeded).await {
        log::error(&format!(
            "{name}({addr_str}) - SOCKS reply failed: {}",
            log::elide_error(&e)
        ));
        return;
    }
    match copy_loop(Conn::from_stream(req.into_stream()), remote).await {
        Ok(()) => log::info(&format!("{name}({addr_str}) - closed connection")),
        Err(e) => log::warn(&format!(
            "{name}({addr_str}) - closed connection: {}",
            log::elide_error(&e)
        )),
    }
}
