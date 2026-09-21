// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of lyrebird cmd/lyrebird (main).

//! `lyrebird`: a Tor managed pluggable transport (client or server, chosen
//! from the environment tor/Arti sets). This is the composition root: it
//! picks the adapter behind every port and hands them to `app::run`.

use std::process::ExitCode;
use std::sync::Arc;

use lyrebird::app::registry::Registry;
use lyrebird::app::{self, Ports, Settings};
use lyrebird::shared::adapters::cli::{self, parse_flags};
use lyrebird::shared::adapters::extorport::ExtOrPortConnector;
use lyrebird::shared::adapters::fs::FsStorage;
use lyrebird::shared::adapters::process_env::ProcessEnv;
use lyrebird::shared::adapters::signals::OsSignals;
use lyrebird::shared::adapters::socks5::Socks5Server;
use lyrebird::shared::adapters::stdout::StdoutControl;
use lyrebird::shared::adapters::tcp::{DirectDialer, TcpNetwork};
use lyrebird::shared::domain::pt::TorControl;
use lyrebird::shared::ports::log;
use lyrebird::transports::obfs4::adapters::fs_state_store::FsBridgeStateStore;
use lyrebird::transports::snowflake::adapters::rendezvous::RendezvousClients;
use lyrebird::transports::snowflake::adapters::stun::StunNatProbe;
use lyrebird::transports::snowflake::adapters::webrtc::Str0mWebRtc;
use lyrebird::transports::webtunnel::adapters::rustls::RustlsConnector;
use lyrebird::transports::{obfs4, snowflake, webtunnel};
use lyrebird::VERSION;

/// Go's `log.Fatal`: timestamped line on stderr, exit status 1.
fn fatal(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{} {msg}", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"));
    ExitCode::from(1)
}

fn exec_name() -> String {
    std::env::args()
        .next()
        .and_then(|a| {
            std::path::Path::new(&a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "lyrebird".into())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags = match parse_flags(&args) {
        Ok(f) => f,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(if e.is_empty() { 0 } else { 2 });
        }
    };
    if flags.show_version {
        println!("lyrebird-rs {VERSION}");
        return ExitCode::SUCCESS;
    }
    let exec = exec_name();
    if let Err(e) = log::set_log_level(&flags.log_level) {
        return fatal(format!("[ERROR]: {exec} - failed to set log level: {e}"));
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fatal(format!("[ERROR]: {exec} - failed to start runtime: {e}")),
    };

    let tor = TorControl::new(Arc::new(StdoutControl));
    let dist_bias = flags.dist_bias;
    let transports_tor = tor.clone();
    let ports = Ports {
        env: Arc::new(ProcessEnv),
        tor,
        storage: Arc::new(FsStorage),
        net: Arc::new(TcpNetwork),
        socks: Arc::new(Socks5Server),
        orport: Arc::new(ExtOrPortConnector),
        signals: Arc::new(OsSignals),
        transports: Box::new(move |state_dir| {
            Registry::new(vec![
                Arc::new(obfs4::Transport::new(
                    Arc::new(FsBridgeStateStore::new(state_dir)),
                    dist_bias,
                )),
                Arc::new(snowflake::Transport::new(
                    snowflake::Ports {
                        rendezvous: Arc::new(RendezvousClients::new(Arc::new(DirectDialer))),
                        webrtc: Arc::new(Str0mWebRtc),
                        nat_probe: Arc::new(StunNatProbe),
                    },
                    transports_tor.clone(),
                )),
                Arc::new(webtunnel::Transport::new(
                    Arc::new(RustlsConnector::new()),
                    transports_tor.clone(),
                )),
            ])
        }),
    };
    let settings = Settings {
        exec,
        enable_logging: flags.enable_logging,
        unsafe_logging: flags.unsafe_logging,
    };
    let code = runtime.block_on(app::run(settings, ports));
    // Don't wait on connection tasks or blocking reads at exit.
    runtime.shutdown_background();
    code.unwrap_or_else(fatal)
}
