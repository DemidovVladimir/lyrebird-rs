//! Code shared by the application and all transports, as one hexagon:
//! `domain` (logic), `ports` (interfaces to the outside world) and
//! `adapters` (implementations of those interfaces).

pub mod adapters;
pub mod domain;
pub mod ports;
