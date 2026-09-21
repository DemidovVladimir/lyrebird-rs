// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/statefile.go (the files).

//! The bridge identity as lyrebird keeps it: `obfs4_state.json` and
//! `obfs4_bridgeline.txt` in the PT state directory, both mode 0600.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::shared::ports::BoxError;
use crate::transports::obfs4::ports::state_store::{BridgeStateStore, StoredState};

const STATE_FILE: &str = "obfs4_state.json";
const BRIDGE_FILE: &str = "obfs4_bridgeline.txt";

#[derive(Serialize, Deserialize, Default)]
struct JsonServerState {
    #[serde(rename = "node-id", default)]
    node_id: String,
    #[serde(rename = "private-key", default)]
    private_key: String,
    #[serde(rename = "public-key", default)]
    public_key: String,
    #[serde(rename = "drbg-seed", default)]
    drbg_seed: String,
    #[serde(rename = "iat-mode", default)]
    iat_mode: i64,
}

pub struct FsBridgeStateStore {
    dir: PathBuf,
}

impl FsBridgeStateStore {
    /// Files in `state_dir` (`TOR_PT_STATE_LOCATION`).
    pub fn new(state_dir: &Path) -> FsBridgeStateStore {
        FsBridgeStateStore {
            dir: state_dir.to_path_buf(),
        }
    }
}

fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(data)
}

impl BridgeStateStore for FsBridgeStateStore {
    fn load(&self) -> Result<Option<StoredState>, BoxError> {
        let path = self.dir.join(STATE_FILE);
        match std::fs::read(&path) {
            Ok(data) => {
                let js: JsonServerState = serde_json::from_slice(&data)
                    .map_err(|e| format!("failed to load statefile '{}': {e}", path.display()))?;
                Ok(Some(StoredState {
                    node_id: js.node_id,
                    private_key: js.private_key,
                    public_key: js.public_key,
                    drbg_seed: js.drbg_seed,
                    iat_mode: js.iat_mode,
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, state: &StoredState) -> Result<(), BoxError> {
        let js = JsonServerState {
            node_id: state.node_id.clone(),
            private_key: state.private_key.clone(),
            public_key: state.public_key.clone(),
            drbg_seed: state.drbg_seed.clone(),
            iat_mode: state.iat_mode,
        };
        let encoded = serde_json::to_vec(&js)?;
        write_private_file(&self.dir.join(STATE_FILE), &encoded)?;
        Ok(())
    }

    fn save_bridge_line(&self, text: &str) -> Result<(), BoxError> {
        write_private_file(&self.dir.join(BRIDGE_FILE), text.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::domain::pt::Args;
    use crate::transports::obfs4::domain::state::server_state_from_args;

    #[test]
    fn state_file_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBridgeStateStore::new(dir.path());
        assert_eq!(store.load().unwrap(), None);
        let first = server_state_from_args(&store, &Args::new()).unwrap();
        let bridge = std::fs::read_to_string(dir.path().join(BRIDGE_FILE)).unwrap();
        assert!(bridge.ends_with(&format!("cert={} iat-mode=0\n", first.cert())));
        let json = std::fs::read_to_string(dir.path().join(STATE_FILE)).unwrap();
        assert!(json.starts_with("{\"node-id\":\""), "{json}");
        assert!(json.ends_with("\"iat-mode\":0}"), "{json}");
        let mut args = Args::new();
        args.add("iat-mode", "2");
        let second = server_state_from_args(&FsBridgeStateStore::new(dir.path()), &args).unwrap();
        assert_eq!(second.cert(), first.cert());
        std::fs::write(dir.path().join(STATE_FILE), "not json").unwrap();
        let err = store.load().unwrap_err().to_string();
        assert!(err.starts_with("failed to load statefile '"), "{err}");
    }
}
