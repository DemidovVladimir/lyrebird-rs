// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Shutdown triggers from outside the process.

use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// SIGINT: stop accepting, exit once connections are done.
    Int,
    /// SIGTERM, stdin closed, or the parent died: exit now.
    Term,
}

pub trait SignalSource: Send + Sync {
    /// Starts sending signals to `tx`. With `exit_on_stdin_close`
    /// (`TOR_PT_EXIT_ON_STDIN_CLOSE=1`), stdin closing sends `Term`.
    fn watch(&self, tx: mpsc::UnboundedSender<Signal>, exit_on_stdin_close: bool);
}
