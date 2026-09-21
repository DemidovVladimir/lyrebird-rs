// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of lyrebird cmd/lyrebird (serverSetup, serverAcceptLoop,
// serverHandler).

//! Server (bridge) mode: one listener per transport; each client is
//! unwrapped by the transport and relayed to tor's ORPort.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::task::JoinHandle;

use super::registry::Registry;
use super::relay::copy_loop;
use super::termmon::TermMonitor;
use super::Ports;
use crate::shared::domain::pt::{managed, ServerInfo};
use crate::shared::ports::log;
use crate::shared::ports::net::Listener;
use crate::shared::ports::orport::OrConnector;
use crate::shared::ports::stream::BoxStream;
use crate::shared::ports::transport::{Conn, ServerFactory};
use crate::VERSION;

/// Registers the configured transports with tor (`SMETHOD` lines) and
/// starts their listeners. `Err` is fatal.
pub async fn setup(
    ports: &Ports,
    registry: &Registry,
    term: &TermMonitor,
) -> Result<Vec<JoinHandle<()>>, String> {
    let tor = &ports.tor;
    let info = Arc::new(managed::server_setup(&*ports.env, tor).map_err(|e| e.to_string())?);
    tor.report_version("lyrebird-rs", VERSION);

    let mut listeners = Vec::new();
    for bindaddr in &info.bindaddrs {
        let name = &bindaddr.method_name;
        let Some(t) = registry.get(name) else {
            tor.smethod_error(name, "no such transport is supported");
            continue;
        };
        let f = match t.server_factory(&bindaddr.options) {
            Ok(f) => f,
            Err(e) => {
                tor.smethod_error(name, &e.to_string());
                continue;
            }
        };
        // 0.0.0.0 means "all addresses", as with Go's nil-IP listener.
        let mut addr = bindaddr.addr;
        if addr.ip() == Ipv4Addr::UNSPECIFIED {
            addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), addr.port());
        }
        let ln = match ports.net.listen(addr).await {
            Ok(l) => l,
            Err(e) => {
                tor.smethod_error(name, &e.to_string());
                continue;
            }
        };
        let local = ln.local_addr();
        let task = tokio::spawn(accept_loop(
            f.clone(),
            ln,
            info.clone(),
            ports.orport.clone(),
            term.clone(),
        ));
        tor.smethod_args(name, &local, f.args().as_ref());
        log::info(&format!(
            "{name} - registered listener: {}",
            log::elide_addr(&local.to_string())
        ));
        listeners.push(task);
    }
    tor.smethods_done();
    Ok(listeners)
}

async fn accept_loop(
    f: Arc<dyn ServerFactory>,
    ln: Box<dyn Listener>,
    info: Arc<ServerInfo>,
    orport: Arc<dyn OrConnector>,
    term: TermMonitor,
) {
    while let Ok((conn, peer)) = ln.accept().await {
        let (f, info, orport, term) = (f.clone(), info.clone(), orport.clone(), term.clone());
        tokio::spawn(async move {
            let _guard = term.handler();
            handle(f, conn, peer, &info, &*orport).await;
        });
    }
}

/// One bridge client: transport handshake, ORPort connection, relay.
async fn handle(
    f: Arc<dyn ServerFactory>,
    conn: BoxStream,
    peer: SocketAddr,
    info: &ServerInfo,
    orport: &dyn OrConnector,
) {
    let name = f.transport_name();
    let addr_str = log::elide_addr(&peer.to_string());
    log::info(&format!("{name}({addr_str}) - new connection"));
    let remote = match f.wrap(conn).await {
        Ok(c) => c,
        Err(e) => {
            log::warn(&format!(
                "{name}({addr_str}) - handshake failed: {}",
                log::elide_error(e.as_ref())
            ));
            return;
        }
    };
    let or_conn = match orport.connect(info, &peer, name).await {
        Ok(c) => c,
        Err(e) => {
            log::error(&format!(
                "{name}({addr_str}) - failed to connect to ORPort: {}",
                log::elide_error(&e)
            ));
            return;
        }
    };
    match copy_loop(Conn::from_stream(or_conn), remote).await {
        Ok(()) => log::info(&format!("{name}({addr_str}) - closed connection")),
        Err(e) => log::warn(&format!(
            "{name}({addr_str}) - closed connection: {}",
            log::elide_error(&e)
        )),
    }
}
