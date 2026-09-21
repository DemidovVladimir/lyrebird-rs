// Copyright (c) 2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird cmd/lyrebird/termmon.go.

//! When to exit: shutdown signals, and (after SIGINT) the last connection
//! handler finishing.

use std::sync::Arc;

use tokio::sync::{mpsc, watch, Mutex};

use crate::shared::ports::signals::{Signal, SignalSource};

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
    pub fn start(source: &dyn SignalSource, exit_on_stdin_close: bool) -> TermMonitor {
        let (tx, rx) = mpsc::unbounded_channel();
        source.watch(tx, exit_on_stdin_close);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Holds the sender so the channel stays open; sends nothing.
    struct Quiet(std::sync::Mutex<Vec<mpsc::UnboundedSender<Signal>>>);

    impl SignalSource for Quiet {
        fn watch(&self, tx: mpsc::UnboundedSender<Signal>, _: bool) {
            self.0.lock().unwrap().push(tx);
        }
    }

    #[tokio::test]
    async fn waits_for_handlers() {
        let quiet = Quiet(Default::default());
        let m = TermMonitor::start(&quiet, false);
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

    #[tokio::test]
    async fn interrupt_is_passed_on() {
        let quiet = Quiet(Default::default());
        let m = TermMonitor::start(&quiet, false);
        quiet.0.lock().unwrap()[0].send(Signal::Int).unwrap();
        assert_eq!(m.wait(false).await, Signal::Int);
    }
}
