// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/webtunnel.

//! WebTunnel (HTTPT): Tor carried by a web server's HTTP upgrade. Client
//! only, as upstream; the bridge side is the separate `webtunnel` project.
//!
//! - `domain`: arguments, SNI rotation, TLS policy, the upgrade.
//! - `ports`: `TlsConnector`.
//! - `adapters`: that connector on rustls.

pub mod adapters;
pub mod domain;
pub mod ports;

pub use domain::transport::Transport;
