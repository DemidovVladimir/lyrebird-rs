//! lyrebird-rs: a Rust port of lyrebird, the Tor Project's pluggable
//! transport suite
//! (<https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird>).
//!
//! Module map (upstream path in parentheses):
//! - `pt` — pluggable transport spec v1 (goptlib)
//! - `socks5` — tor-facing SOCKS server (common/socks5)
//! - `proxy` — `TOR_PT_PROXY` dialers (cmd/lyrebird/proxy_*.go)
//! - `transports` — transport interface and implementations (transports/)
//! - `common` — crypto and randomness primitives (common/, internal/)
//! - `log`, `termmon` — logging and shutdown (common/log, cmd/lyrebird/termmon*.go)

pub mod common;
pub mod log;
pub mod proxy;
pub mod pt;
pub mod socks5;
pub mod termmon;
pub mod transports;

/// This crate's version (reported to tor in the `STATUS TYPE=version` line).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
