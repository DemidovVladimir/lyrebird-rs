//! Shared domain logic: pure rules and protocols used by the application
//! and by every transport. Talks to the outside only through
//! `shared::ports`.

pub mod crypto;
pub mod http;
pub mod proxy;
pub mod pt;
pub mod scrub;
