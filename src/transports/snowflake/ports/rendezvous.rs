// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of the RendezvousMethod interface in snowflake/v2 client/lib.

//! Reaching the broker: some channel that carries an encoded poll request
//! there and the broker's reply back.

use std::io;

use crate::shared::ports::BoxFuture;

/// A way of carrying an encoded poll request to the broker and back.
pub trait Rendezvous: Send + Sync {
    fn exchange<'a>(&'a self, req: &'a [u8]) -> BoxFuture<'a, io::Result<Vec<u8>>>;
}

/// Builds the rendezvous channel a bridge line asks for. Errors are
/// configuration errors (bad URL, credentials, region).
pub trait RendezvousFactory: Send + Sync {
    /// POST to `broker_url`, domain-fronted through one of `fronts` if any.
    fn http(
        &self,
        broker_url: &str,
        fronts: &[String],
        send_sni: bool,
    ) -> Result<Box<dyn Rendezvous>, String>;

    /// GET through the AMP cache at `cache_url`, domain-fronted likewise.
    fn amp_cache(
        &self,
        broker_url: &str,
        cache_url: &str,
        fronts: &[String],
        send_sni: bool,
    ) -> Result<Box<dyn Rendezvous>, String>;

    /// Through an Amazon SQS queue; `creds` is base64 JSON.
    fn sqs(&self, queue_url: &str, creds: &str) -> Result<Box<dyn Rendezvous>, String>;
}
