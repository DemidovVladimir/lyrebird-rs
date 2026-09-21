// Port of goptlib (CC0) — the Tor pluggable transport spec, v1.

//! The pluggable transport spec: transport arguments, control lines to tor
//! and the managed-transport environment.

pub mod addr;
pub mod args;
pub mod control;
pub mod managed;

pub use addr::{resolve_addr, split_host_port};
pub use args::Args;
pub use control::{encode_cstring, LogSeverity, PtError, TorControl};
pub use managed::{Bindaddr, ClientInfo, ServerInfo};
