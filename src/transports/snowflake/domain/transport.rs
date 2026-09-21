// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of lyrebird transports/snowflake.

//! The snowflake transport as the application sees it (client only, as
//! upstream).

use std::sync::Arc;
use std::time::Duration;

use super::client::SnowflakeClient;
use super::config::{parse_client_args, ClientConfig};
use super::events::EventSink;
use crate::shared::domain::pt::{Args, TorControl};
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::transport::{self, ClientArgs, Conn, DialError};
use crate::shared::ports::{BoxError, BoxFuture};
use crate::transports::snowflake::ports::nat_probe::NatProbe;
use crate::transports::snowflake::ports::rendezvous::RendezvousFactory;
use crate::transports::snowflake::ports::webrtc::WebRtc;

const TRANSPORT_NAME: &str = "snowflake";
/// pion's server-reflexive gathering timeout.
pub const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const WINDOW_SIZE: i32 = 65535;
pub const STREAM_SIZE: usize = 1024 * 1024;

/// What snowflake needs from the outside world.
#[derive(Clone)]
pub struct Ports {
    pub rendezvous: Arc<dyn RendezvousFactory>,
    pub webrtc: Arc<dyn WebRtc>,
    pub nat_probe: Arc<dyn NatProbe>,
}

pub struct Transport {
    ports: Ports,
    tor: TorControl,
}

impl Transport {
    /// Status events go to tor through `tor`.
    pub fn new(ports: Ports, tor: TorControl) -> Transport {
        Transport { ports, tor }
    }
}

impl transport::Transport for Transport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn client_factory(&self) -> Result<Arc<dyn transport::ClientFactory>, BoxError> {
        Ok(Arc::new(ClientFactory {
            ports: self.ports.clone(),
            events: EventSink::new(self.tor.clone()),
        }))
    }

    fn server_factory(&self, _args: &Args) -> Result<Arc<dyn transport::ServerFactory>, BoxError> {
        Err("ServerFactory not implemented for the snowflake transport".into())
    }
}

pub struct ClientFactory {
    ports: Ports,
    events: EventSink,
}

impl transport::ClientFactory for ClientFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn parse_args(&self, args: &Args) -> Result<ClientArgs, BoxError> {
        Ok(Box::new(parse_client_args(args)?))
    }

    fn dial<'a>(
        &'a self,
        _target: &'a str,
        dialer: &'a dyn Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>> {
        Box::pin(async move {
            let config = args
                .downcast::<ClientConfig>()
                .map_err(|_| DialError::Other("invalid type for args".into()))?;
            if !dialer.is_direct() {
                // Upstream silently bypasses TOR_PT_PROXY here; refuse instead.
                return Err(DialError::Other(
                    "snowflake: TOR_PT_PROXY is not supported yet (needs SOCKS5 UDP relaying)"
                        .into(),
                ));
            }
            let client = SnowflakeClient::new(&config, &self.ports, self.events.clone())
                .map_err(|e| DialError::Other(e.into()))?;
            Ok(client.dial().await?)
        })
    }
}
