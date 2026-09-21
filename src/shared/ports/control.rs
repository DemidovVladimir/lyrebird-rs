// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! The pt-spec control channel to tor (lyrebird writes it to stdout).

pub trait ControlOutput: Send + Sync {
    /// Writes one complete control line (without the newline) and flushes.
    fn write_line(&self, line: &str);
}
