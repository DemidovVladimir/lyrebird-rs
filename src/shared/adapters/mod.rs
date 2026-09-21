//! Shared adapters: the shared ports implemented with real sockets, files,
//! processes and TLS.

pub mod cli;
pub mod extorport;
pub mod fs;
pub mod httpc;
pub mod process_env;
pub mod proxy;
pub mod signals;
pub mod socks5;
pub mod stdout;
pub mod tcp;
