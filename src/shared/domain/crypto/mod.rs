//! Crypto and randomness primitives, one module per lyrebird `common/` (or
//! `internal/`) package. Pure computation: no I/O beyond the OS CSPRNG.

pub mod csrand;
pub mod drbg;
pub mod field;
pub mod gorand;
pub mod ntor;
pub mod probdist;
pub mod replayfilter;
pub mod x25519ell2;
