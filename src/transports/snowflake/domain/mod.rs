//! snowflake domain: catching snowflakes through the broker, the peer
//! pool, and the Turbo Tunnel stack (KCP + smux over encapsulated data
//! channel messages) that makes one session outlive any single proxy.

pub mod broker;
pub mod client;
pub mod config;
pub mod encapsulation;
pub mod events;
pub mod kcp;
pub mod kcp_session;
pub mod nat;
pub mod peer;
pub mod smux;
pub mod transport;
pub mod turbotunnel;
