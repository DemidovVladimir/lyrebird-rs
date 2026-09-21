// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of lyrebird transports/snowflake and snowflake/v2 client/lib.

//! Snowflake: WebRTC data channels to volunteer proxies, rendezvous via a
//! broker, with KCP + smux (Turbo Tunnel) on top so sessions survive proxy
//! churn.
//!
//! - `domain`: the client logic and protocols.
//! - `ports`: `RendezvousFactory`/`Rendezvous` (reaching the broker),
//!   `WebRtc` (peer connections), `NatProbe` (NAT type detection).
//! - `adapters`: HTTP, AMP cache and SQS rendezvous; str0m; STUN.

pub mod adapters;
pub mod domain;
pub mod ports;

pub use domain::transport::{Ports, Transport};
