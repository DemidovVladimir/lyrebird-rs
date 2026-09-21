// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4.

//! obfs4 (The Obfourscator): ntor + Elligator2 handshake, secretbox frames,
//! per-bridge packet-length and inter-arrival-time obfuscation.
//!
//! - `domain`: the protocol and the client/server factories.
//! - `ports`: `BridgeStateStore`, where a bridge keeps its identity.
//! - `adapters`: that store as lyrebird's files in the state directory.

pub mod adapters;
pub mod domain;
pub mod ports;

pub use domain::transport::Transport;
