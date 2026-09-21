//! lyrebird-rs: a Rust port of lyrebird, the Tor Project's pluggable
//! transport suite
//! (<https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird>).
//!
//! Hexagonal layout:
//! - `app` — use cases: client mode, server mode, relaying, shutdown. Talks
//!   to the outside only through ports.
//! - `shared::{domain, ports, adapters}` — what the application and every
//!   transport share: crypto, the pt-spec, logging, streams and dialers,
//!   and their implementations (TCP, proxies, SOCKS5, ExtORPort, stdout,
//!   files, signals, HTTP).
//! - `transports::{obfs4, snowflake, webtunnel}` — one hexagon per
//!   transport, each with its own `domain`, `ports` and `adapters`.
//! - `main.rs` — the composition root that wires adapters into ports.
//!
//! `tests/architecture.rs` checks the dependency rules.

pub mod app;
pub mod shared;
pub mod transports;

/// This crate's version (reported to tor in the `STATUS TYPE=version` line).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
