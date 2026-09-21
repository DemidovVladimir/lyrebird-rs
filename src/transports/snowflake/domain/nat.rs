// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 NAT type detection and the client's NATPolicy.

//! Which NAT type to report to the broker.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::broker::BrokerChannel;
use crate::shared::ports::log;
use crate::transports::snowflake::ports::nat_probe::NatProbe;

pub const NAT_UNKNOWN: &str = "unknown";
pub const NAT_RESTRICTED: &str = "restricted";
pub const NAT_UNRESTRICTED: &str = "unrestricted";

/// Claims "unrestricted" while the NAT type is unknown, until that fails once.
#[derive(Default)]
pub struct NatPolicy {
    assumed_unrestricted_and_failed: AtomicBool,
}

impl NatPolicy {
    pub fn nat_type_to_send(&self, actual: &str) -> String {
        if !self.assumed_unrestricted_and_failed.load(Ordering::Relaxed) && actual == NAT_UNKNOWN {
            NAT_UNRESTRICTED.into()
        } else {
            actual.into()
        }
    }

    pub fn success(&self, actual: &str, sent: &str) {
        if actual != sent {
            log::print(&format!(
                "Connected to a proxy by using a spoofed NAT type \"{sent}\"! Our actual NAT type was \"{actual}\""
            ));
        }
    }

    pub fn failure(&self, actual: &str, sent: &str) {
        if actual == NAT_UNKNOWN && sent == NAT_UNRESTRICTED {
            log::print(&format!(
                "Tried to connect to a restricted proxy while our NAT type is \"{actual}\", and failed. Let's not do that again."
            ));
            self.assumed_unrestricted_and_failed
                .store(true, Ordering::Relaxed);
        }
    }
}

/// Tries each STUN server until one supports the RFC 5780 mapping test.
pub async fn update_nat_type(
    servers: Vec<String>,
    broker: Arc<BrokerChannel>,
    probe: Arc<dyn NatProbe>,
) {
    let mut last_err = None;
    for server in servers {
        let addr = server.strip_prefix("stun:").unwrap_or(&server).to_string();
        match probe.is_restricted_mapping(&addr).await {
            Ok(restricted) => {
                broker.set_nat_type(if restricted {
                    NAT_RESTRICTED
                } else {
                    NAT_UNRESTRICTED
                });
                return;
            }
            Err(e) => {
                log::print(&format!(
                    "Warning: NAT checking failed for server at {}: {}",
                    log::elide_addr(&addr),
                    e
                ));
                last_err = Some(e);
            }
        }
    }
    if last_err.is_some() {
        broker.set_nat_type(NAT_UNKNOWN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_spoofs_until_failure() {
        let p = NatPolicy::default();
        assert_eq!(p.nat_type_to_send(NAT_UNKNOWN), NAT_UNRESTRICTED);
        assert_eq!(p.nat_type_to_send(NAT_RESTRICTED), NAT_RESTRICTED);
        p.failure(NAT_UNKNOWN, NAT_UNRESTRICTED);
        assert_eq!(p.nat_type_to_send(NAT_UNKNOWN), NAT_UNKNOWN);
    }
}
