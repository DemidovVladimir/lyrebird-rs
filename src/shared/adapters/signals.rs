// Copyright (c) 2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird cmd/lyrebird/termmon{,_linux}.go (the triggers).

//! Shutdown triggers: SIGINT/SIGTERM, stdin closing
//! (`TOR_PT_EXIT_ON_STDIN_CLOSE=1`), or the parent process dying.

use std::time::Duration;

use tokio::sync::mpsc;

use crate::shared::ports::log;
use crate::shared::ports::signals::{Signal, SignalSource};

pub struct OsSignals;

impl SignalSource for OsSignals {
    /// Must be called inside a tokio runtime.
    fn watch(&self, tx: mpsc::UnboundedSender<Signal>, exit_on_stdin_close: bool) {
        spawn_signal_listener(tx.clone());
        if exit_on_stdin_close {
            // A plain thread: a pending stdin read must not hold up runtime shutdown.
            std::thread::spawn(move || {
                let res = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
                match res {
                    Ok(_) => log::notice("Stdin is closed or unreadable: <nil>"),
                    Err(e) => log::notice(&format!("Stdin is closed or unreadable: {e}")),
                }
                let _ = tx.send(Signal::Term);
            });
        } else if !set_parent_death_signal() {
            watch_parent(tx);
        }
    }
}

#[cfg(unix)]
fn spawn_signal_listener(tx: mpsc::UnboundedSender<Signal>) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut int), Ok(mut term)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        log::error("failed to install signal handlers");
        return;
    };
    tokio::spawn(async move {
        loop {
            let s = tokio::select! {
                _ = int.recv() => Signal::Int,
                _ = term.recv() => Signal::Term,
            };
            if tx.send(s).is_err() {
                return;
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_signal_listener(tx: mpsc::UnboundedSender<Signal>) {
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if tx.send(Signal::Int).is_err() {
                return;
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn set_parent_death_signal() -> bool {
    match rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM)) {
        Ok(()) => true,
        Err(e) => {
            log::warn(&format!("prctl(PR_SET_PDEATHSIG, SIGTERM) returned: {e}"));
            false
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_parent_death_signal() -> bool {
    false
}

#[cfg(unix)]
fn watch_parent(tx: mpsc::UnboundedSender<Signal>) {
    let ppid = std::os::unix::process::parent_id();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let now = std::os::unix::process::parent_id();
            if now != ppid {
                log::notice(&format!("Parent pid changed: {now} (was {ppid})"));
                let _ = tx.send(Signal::Term);
                return;
            }
        }
    });
}

#[cfg(not(unix))]
fn watch_parent(_tx: mpsc::UnboundedSender<Signal>) {}
