// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! The PT state directory (`TOR_PT_STATE_LOCATION`) and the log file in it.

use std::io;
use std::path::Path;

use super::log::LogSink;

pub trait Storage: Send + Sync {
    /// Creates `dir` and its parents, readable by this user only.
    fn create_private_dir(&self, dir: &Path) -> io::Result<()>;
    /// Opens `path` for appending log records.
    fn open_log(&self, path: &Path) -> io::Result<Box<dyn LogSink>>;
}
