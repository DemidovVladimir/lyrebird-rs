// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of lyrebird cmd/lyrebird.

//! The application: lyrebird as a Tor managed pluggable transport, client
//! or server as the environment tor sets up says. Use cases only; every
//! outside dependency comes in through `Ports`.

pub mod client;
pub mod registry;
pub mod relay;
pub mod server;
pub mod termmon;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use crate::shared::domain::pt::{managed, TorControl};
use crate::shared::ports::env::Env;
use crate::shared::ports::log;
use crate::shared::ports::net::Network;
use crate::shared::ports::orport::OrConnector;
use crate::shared::ports::signals::{Signal, SignalSource};
use crate::shared::ports::socks::SocksServer;
use crate::shared::ports::storage::Storage;
use crate::VERSION;

use registry::Registry;
use termmon::TermMonitor;

const LOG_FILE: &str = "lyrebird.log";

/// Everything the application needs from the outside world.
pub struct Ports {
    pub env: Arc<dyn Env>,
    pub tor: TorControl,
    pub storage: Arc<dyn Storage>,
    pub net: Arc<dyn Network>,
    pub socks: Arc<dyn SocksServer>,
    pub orport: Arc<dyn OrConnector>,
    pub signals: Arc<dyn SignalSource>,
    /// Builds the transports once the state directory is known.
    pub transports: Box<dyn Fn(&Path) -> Registry + Send + Sync>,
}

pub struct Settings {
    /// Executable name, for log and error lines.
    pub exec: String,
    pub enable_logging: bool,
    pub unsafe_logging: bool,
}

/// Runs until shutdown. `Err` is a fatal error message, to be printed the
/// way Go's `log.Fatal` does.
pub async fn run(settings: Settings, ports: Ports) -> Result<ExitCode, String> {
    let exec = &settings.exec;
    let env = &*ports.env;
    let term = TermMonitor::start(&*ports.signals, managed::exit_on_stdin_close(env));

    let Ok(client) = managed::is_client(env, &ports.tor) else {
        return Err(format!(
            "[ERROR]: {exec} - must be run as a managed transport"
        ));
    };
    let state_dir = managed::make_state_dir(env, &ports.tor, &*ports.storage)
        .map_err(|e| format!("[ERROR]: {exec} - No state directory: {e}"))?;
    if settings.enable_logging {
        let sink = ports
            .storage
            .open_log(&state_dir.join(LOG_FILE))
            .map_err(|_| format!("[ERROR]: {exec} - failed to initialize logging"))?;
        log::install(sink);
    }
    log::set_unsafe_logging(settings.unsafe_logging);
    log::notice(&format!("{VERSION} - launched"));

    let registry = (ports.transports)(&state_dir);
    let listeners = if client {
        log::info(&format!("{exec} - initializing client transport listeners"));
        client::setup(&ports, &registry, &term).await?
    } else {
        log::info(&format!("{exec} - initializing server transport listeners"));
        server::setup(&ports, &registry, &term).await?
    };
    if listeners.is_empty() {
        // Go's os.Exit(-1).
        return Ok(ExitCode::from(255));
    }

    log::info(&format!("{exec} - accepting connections"));
    if term.wait(false).await != Signal::Term {
        for l in &listeners {
            l.abort();
        }
        term.wait(true).await;
    }
    log::notice(&format!("{exec} - terminated"));
    Ok(ExitCode::SUCCESS)
}
