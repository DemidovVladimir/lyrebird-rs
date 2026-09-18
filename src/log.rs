// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/log.

//! File logging to `TOR_PT_STATE_LOCATION/lyrebird.log` with address scrubbing.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;

const ELIDED_ADDR: &str = "[scrubbed]";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static ENABLED: AtomicBool = AtomicBool::new(false);
static UNSAFE: AtomicBool = AtomicBool::new(false);
static FILE: Mutex<Option<File>> = Mutex::new(None);

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

pub fn init(enable: bool, path: &Path, unsafe_logging: bool) -> std::io::Result<()> {
    if enable {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        *FILE.lock().unwrap() = Some(opts.open(path)?);
    }
    ENABLED.store(enable, Ordering::Relaxed);
    UNSAFE.store(unsafe_logging, Ordering::Relaxed);
    Ok(())
}

pub fn unsafe_logging() -> bool {
    UNSAFE.load(Ordering::Relaxed)
}

fn write(tag: &str, msg: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    // Go's log.LstdFlags: local date and time.
    let ts = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    if let Some(f) = FILE.lock().unwrap().as_mut() {
        let _ = writeln!(f, "{ts} [{tag}]: {msg}");
    }
}

/// Go's standard `log.Print*`, which lyrebird points at the same file: no
/// level tag, always written when logging is enabled. Transport libraries
/// (snowflake) log this way; addresses are scrubbed unless `-unsafeLogging`.
pub fn print(msg: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let msg = if unsafe_logging() {
        msg.to_string()
    } else {
        scrub(msg)
    };
    let ts = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    if let Some(f) = FILE.lock().unwrap().as_mut() {
        let nl = if msg.ends_with('\n') { "" } else { "\n" };
        let _ = write!(f, "{ts} {msg}{nl}");
    }
}

/// Replaces IP addresses (with or without port) in `s` (ptutil safelog).
pub fn scrub(s: &str) -> String {
    fn is_addr(token: &str) -> bool {
        let bare = token.trim_start_matches('[').trim_end_matches(']');
        token.parse::<std::net::SocketAddr>().is_ok()
            || bare.parse::<std::net::IpAddr>().is_ok()
            || token.parse::<std::net::Ipv4Addr>().is_ok()
    }
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        // Trailing ':' or '.' belong to the surrounding text.
        let core = token.trim_end_matches([':', '.']);
        if !core.is_empty() && core.contains(['.', ':']) && is_addr(core) {
            out.push_str(ELIDED_ADDR);
            out.push_str(&token[core.len()..]);
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in s.chars() {
        if c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '[' | ']') {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
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

/// `[scrubbed]:port` unless `-unsafeLogging`.
pub fn elide_addr(addr: &str) -> String {
    if unsafe_logging() {
        return addr.to_string();
    }
    match crate::pt::split_host_port(addr) {
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

    #[test]
    fn scrubs_addresses_in_text() {
        assert_eq!(scrub("dial 192.0.2.1:443 failed"), "dial [scrubbed] failed");
        assert_eq!(scrub("to [2001:db8::1]:80 x"), "to [scrubbed] x");
        assert_eq!(scrub("c=IN IP4 203.0.113.9\r\n"), "c=IN IP4 [scrubbed]\r\n");
        assert_eq!(scrub("at 10.0.0.1."), "at [scrubbed].");
        assert_eq!(
            scrub("no addr, code 404, v1.2, fe80::1"),
            "no addr, code 404, v1.2, [scrubbed]"
        );
        assert_eq!(
            scrub("a=fingerprint:sha-256 AB:CD:EF"),
            "a=fingerprint:sha-256 AB:CD:EF"
        );
    }
}
