// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/statefile.go (the storage side).

//! Where a bridge keeps its long-term identity between runs.

use crate::shared::ports::BoxError;

/// The bridge identity as saved: hex strings, as in lyrebird's
/// `obfs4_state.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredState {
    pub node_id: String,
    pub private_key: String,
    pub public_key: String,
    pub drbg_seed: String,
    pub iat_mode: i64,
}

pub trait BridgeStateStore: Send + Sync {
    /// The saved identity, or `None` on first run.
    fn load(&self) -> Result<Option<StoredState>, BoxError>;
    fn save(&self, state: &StoredState) -> Result<(), BoxError>;
    /// Publishes the client bridge line for the operator
    /// (`obfs4_bridgeline.txt`).
    fn save_bridge_line(&self, text: &str) -> Result<(), BoxError>;
}
