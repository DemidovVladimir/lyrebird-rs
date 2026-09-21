// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/log.

//! Logging: the level/scrubbing policy and the functions the core calls,
//! over a `LogSink` installed at startup (lyrebird writes
//! `TOR_PT_STATE_LOCATION/lyrebird.log`). Nothing is written until a sink
//! is installed, as with logging disabled upstream.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

use crate::shared::domain::pt::split_host_port;
use crate::shared::domain::scrub::{scrub, ELIDED_ADDR};

/// Where log records end up.
pub trait LogSink: Send + Sync {
    /// Writes one record. `tag` is the level tag (`NOTICE`, `ERROR`, ...),
    /// or `None` for a line in the style of Go's `log.Print`.
    fn write(&self, tag: Option<&str>, msg: &str);
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static UNSAFE: AtomicBool = AtomicBool::new(false);
static SINK: OnceLock<Box<dyn LogSink>> = OnceLock::new();

pub fn set_log_level(s: &str) -> Result<(), String> {
    let level = match s.to_ascii_uppercase().as_str() {
        "ERROR" => Level::Error,
        "WARN" => Level::Warn,
        "INFO" => Level::Info,
        "DEBUG" => Level::Debug,
        _ => return Err(format!("invalid log level '{s}'")),
    };
    LEVEL.store(level as u8, Ordering::Relaxed);
    Ok(())
}

/// Starts writing to `sink` (once per process).
pub fn install(sink: Box<dyn LogSink>) {
    let _ = SINK.set(sink);
}

/// `-unsafeLogging`: keep addresses in logs.
pub fn set_unsafe_logging(on: bool) {
    UNSAFE.store(on, Ordering::Relaxed);
}

pub fn unsafe_logging() -> bool {
    UNSAFE.load(Ordering::Relaxed)
}

fn write(tag: &str, msg: &str) {
    if let Some(sink) = SINK.get() {
        sink.write(Some(tag), msg);
    }
}

/// Go's standard `log.Print*`, which lyrebird points at the same file: no
/// level tag, always written when logging is enabled. Transport libraries
/// (snowflake) log this way; addresses are scrubbed unless `-unsafeLogging`.
pub fn print(msg: &str) {
    let Some(sink) = SINK.get() else {
        return;
    };
    if unsafe_logging() {
        sink.write(None, msg);
    } else {
        sink.write(None, &scrub(msg));
    }
}

fn at(level: Level) -> bool {
    LEVEL.load(Ordering::Relaxed) >= level as u8
}

/// Always logged when logging is enabled, regardless of level.
pub fn notice(msg: &str) {
    write("NOTICE", msg);
}

pub fn error(msg: &str) {
    if at(Level::Error) {
        write("ERROR", msg);
    }
}

pub fn warn(msg: &str) {
    if at(Level::Warn) {
        write("WARN", msg);
    }
}

pub fn info(msg: &str) {
    if at(Level::Info) {
        write("INFO", msg);
    }
}

pub fn debug(msg: &str) {
    if at(Level::Debug) {
        write("DEBUG", msg);
    }
}

/// `msg` with addresses scrubbed unless `-unsafeLogging`.
pub fn scrubbed(msg: &str) -> String {
    if unsafe_logging() {
        msg.to_string()
    } else {
        scrub(msg)
    }
}

/// `[scrubbed]:port` unless `-unsafeLogging`.
pub fn elide_addr(addr: &str) -> String {
    if unsafe_logging() {
        return addr.to_string();
    }
    match split_host_port(addr) {
        Ok((_, port)) => format!("{ELIDED_ADDR}:{port}"),
        Err(_) => ELIDED_ADDR.to_string(),
    }
}

/// Error text for logs. Errors built by this crate never embed peer
/// addresses; I/O errors are reduced to their kind unless `-unsafeLogging`.
pub fn elide_error(e: &(dyn std::error::Error + 'static)) -> String {
    if unsafe_logging() {
        return e.to_string();
    }
    match e.downcast_ref::<std::io::Error>() {
        Some(io) => match io.raw_os_error() {
            Some(_) => std::io::Error::from(io.kind()).to_string(),
            None => io.to_string(),
        },
        None => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubbing() {
        assert_eq!(elide_addr("192.0.2.1:443"), "[scrubbed]:443");
        assert_eq!(elide_addr("[2001:db8::1]:80"), "[scrubbed]:80");
        assert_eq!(elide_addr("nonsense"), "[scrubbed]");
        assert!(set_log_level("debug").is_ok());
        assert!(set_log_level("verbose").is_err());
        assert!(set_log_level("error").is_ok());
    }
}
