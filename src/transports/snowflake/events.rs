// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of the client events in snowflake/v2 common/event.

//! Snowflake status events; lyrebird relays them to tor as `LOG` lines.

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::log::scrub;

pub enum Event {
    OfferCreated(Option<String>),
    BrokerRendezvous(Option<String>),
    Connected,
    ConnectionFailed(String),
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::OfferCreated(None) => f.write_str("offer created"),
            Event::OfferCreated(Some(e)) => write!(f, "offer creation failure {}", scrub(e)),
            Event::BrokerRendezvous(None) => f.write_str("broker rendezvous peer received"),
            Event::BrokerRendezvous(Some(e)) => write!(f, "broker failure {}", scrub(e)),
            Event::Connected => f.write_str("connected"),
            Event::ConnectionFailed(e) => write!(f, "trying a new proxy: {}", scrub(e)),
        }
    }
}

type Callback = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Clone, Default)]
pub struct EventSink(Arc<Mutex<Option<Callback>>>);

impl EventSink {
    pub fn set(&self, f: Callback) {
        *self.0.lock().unwrap() = Some(f);
    }

    pub fn emit(&self, e: Event) {
        let cb = self.0.lock().unwrap().clone();
        if let Some(cb) = cb {
            cb(e.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_upstream() {
        assert_eq!(Event::OfferCreated(None).to_string(), "offer created");
        assert_eq!(
            Event::BrokerRendezvous(Some("dial tcp 192.0.2.1:443: timeout".into())).to_string(),
            "broker failure dial tcp [scrubbed]: timeout"
        );
        assert_eq!(
            Event::ConnectionFailed("timeout 10.0.0.1".into()).to_string(),
            "trying a new proxy: timeout [scrubbed]"
        );
    }
}
