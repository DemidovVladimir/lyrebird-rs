//! Shared ports: the interfaces between the core (application and
//! transport domains) and the outside world. Adapters implement them;
//! `main.rs` wires the two together.

pub mod control;
pub mod dialer;
pub mod env;
pub mod log;
pub mod net;
pub mod orport;
pub mod signals;
pub mod socks;
pub mod storage;
pub mod stream;
pub mod transport;

pub use stream::{BoxError, BoxFuture, BoxStream};
