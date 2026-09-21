// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/transports.go (the registry).

//! The transports this process offers, looked up by method name.

use std::sync::Arc;

use crate::shared::ports::transport::Transport;

pub struct Registry(Vec<Arc<dyn Transport>>);

impl Registry {
    /// `transports` in registration order.
    pub fn new(transports: Vec<Arc<dyn Transport>>) -> Registry {
        Registry(transports)
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Transport>> {
        self.0.iter().find(|t| t.name() == name).cloned()
    }
}
