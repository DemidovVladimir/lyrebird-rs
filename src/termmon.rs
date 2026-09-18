// Copyright (c) 2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird cmd/lyrebird/termmon{,_linux}.go.

//! Shutdown triggers: SIGINT/SIGTERM, stdin closing
//! (`TOR_PT_EXIT_ON_STDIN_CLOSE=1`), or the parent process dying.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch, Mutex};

use crate::log;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Int,
    Term,
}

#[derive(Clone)]
pub struct TermMonitor {
    inner: Arc<Inner>,
}

struct Inner {
    handlers: watch::Sender<usize>,
    signals: Mutex<mpsc::UnboundedReceiver<Signal>>,
}

/// Counts a live connection handler until dropped.
pub struct HandlerGuard {
    inner: Arc<Inner>,
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        self.inner.handlers.send_modify(|n| *n -= 1);
    }
}

impl TermMonitor {
    /// Must be called inside a tokio runtime.
    pub fn start() -> TermMonitor {
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_signal_listener(tx.clone());

        if std::env::var("TOR_PT_EXIT_ON_STDIN_CLOSE").as_deref() == Ok("1") {
            let tx = tx.clone();
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

        TermMonitor {
            inner: Arc::new(Inner {
                handlers: watch::channel(0).0,
                signals: Mutex::new(rx),
            }),
        }
    }

    pub fn handler(&self) -> HandlerGuard {
        self.inner.handlers.send_modify(|n| *n += 1);
        HandlerGuard {
            inner: self.inner.clone(),
        }
    }

    /// Next signal; with `term_on_no_handlers`, also returns `Term` once no
    /// handlers are running.
    pub async fn wait(&self, term_on_no_handlers: bool) -> Signal {
        let mut signals = self.inner.signals.lock().await;
        let mut handlers = self.inner.handlers.subscribe();
        if !term_on_no_handlers {
            return signals.recv().await.unwrap_or(Signal::Term);
        }
        tokio::select! {
            s = signals.recv() => s.unwrap_or(Signal::Term),
            _ = handlers.wait_for(|n| *n == 0) => Signal::Term,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_handlers() {
        let m = TermMonitor::start();
        let g = m.handler();
        let waiter = {
            let m = m.clone();
            tokio::spawn(async move { m.wait(true).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished());
        drop(g);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap(),
            Signal::Term
        );
    }
}
