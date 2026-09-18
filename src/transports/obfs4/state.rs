// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/statefile.go.

//! Bridge identity: `obfs4_state.json`, `obfs4_bridgeline.txt`, and the
//! `cert=` argument (base64 of NODEID | PUBKEY without padding).

use std::io::Write;
use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::common::csrand;
use crate::common::drbg::Seed;
use crate::common::ntor::{Keypair, NodeId, PublicKey, NODE_ID_LENGTH, PUBLIC_KEY_LENGTH};
use crate::pt::Args;
use crate::transports::BoxError;

use super::{IatMode, CERT_ARG, IAT_ARG, NODE_ID_ARG, PRIVATE_KEY_ARG, SEED_ARG};

const STATE_FILE: &str = "obfs4_state.json";
const BRIDGE_FILE: &str = "obfs4_bridgeline.txt";
const CERT_SUFFIX: &str = "==";
const CERT_LENGTH: usize = NODE_ID_LENGTH + PUBLIC_KEY_LENGTH;

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

pub fn cert_to_string(node_id: &NodeId, public: &PublicKey) -> String {
    let raw = [&node_id.0[..], &public.0[..]].concat();
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    encoded
        .strip_suffix(CERT_SUFFIX)
        .unwrap_or(&encoded)
        .to_string()
}

pub fn cert_from_string(encoded: &str) -> Result<(NodeId, PublicKey), String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(format!("{encoded}{CERT_SUFFIX}"))
        .map_err(|e| format!("failed to decode cert: {e}"))?;
    if decoded.len() != CERT_LENGTH {
        return Err(format!("cert length {} is invalid", decoded.len()));
    }
    Ok((
        NodeId::new(&decoded[..NODE_ID_LENGTH]).unwrap(),
        PublicKey::new(&decoded[NODE_ID_LENGTH..]).unwrap(),
    ))
}

pub struct ServerState {
    pub node_id: NodeId,
    pub identity_key: Keypair,
    pub drbg_seed: Seed,
    pub iat_mode: IatMode,
}

impl ServerState {
    pub fn cert(&self) -> String {
        cert_to_string(&self.node_id, self.identity_key.public())
    }

    fn client_string(&self) -> String {
        format!(
            "{CERT_ARG}={} {IAT_ARG}={}",
            self.cert(),
            self.iat_mode as u8
        )
    }
}

/// Keys come either all from args or all from the state file (created on
/// first run); `iat-mode` may override either.
pub fn server_state_from_args(state_dir: &Path, args: &Args) -> Result<ServerState, BoxError> {
    let mut js = JsonServerState::default();
    let node_id = args.get(NODE_ID_ARG);
    let private_key = args.get(PRIVATE_KEY_ARG);
    let seed = args.get(SEED_ARG);
    match (private_key, node_id, seed) {
        (None, None, None) => json_state_from_file(state_dir, &mut js)?,
        (None, _, _) => return Err(format!("missing argument '{PRIVATE_KEY_ARG}'").into()),
        (_, None, _) => return Err(format!("missing argument '{NODE_ID_ARG}'").into()),
        (_, _, None) => return Err(format!("missing argument '{SEED_ARG}'").into()),
        (Some(k), Some(n), Some(s)) => {
            js.private_key = k.to_string();
            js.node_id = n.to_string();
            js.drbg_seed = s.to_string();
        }
    }
    if let Some(iat) = args.get(IAT_ARG) {
        js.iat_mode = iat
            .parse()
            .map_err(|_| format!("malformed iat-mode '{iat}'"))?;
    }
    state_from_json(state_dir, &js)
}

fn state_from_json(state_dir: &Path, js: &JsonServerState) -> Result<ServerState, BoxError> {
    let st = ServerState {
        node_id: NodeId::from_hex(&js.node_id)?,
        identity_key: Keypair::from_hex(&js.private_key)?,
        drbg_seed: Seed::from_hex(&js.drbg_seed)?,
        iat_mode: IatMode::from_int(js.iat_mode)
            .ok_or_else(|| format!("invalid iat-mode '{}'", js.iat_mode))?,
    };
    write_bridge_file(state_dir, &st)?;
    write_json_state(state_dir, js)?;
    Ok(st)
}

fn json_state_from_file(state_dir: &Path, js: &mut JsonServerState) -> Result<(), BoxError> {
    let path = state_dir.join(STATE_FILE);
    match std::fs::read(&path) {
        Ok(data) => {
            *js = serde_json::from_slice(&data)
                .map_err(|e| format!("failed to load statefile '{}': {e}", path.display()))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => new_json_state(state_dir, js),
        Err(e) => Err(e.into()),
    }
}

fn new_json_state(state_dir: &Path, js: &mut JsonServerState) -> Result<(), BoxError> {
    let mut raw_id = [0u8; NODE_ID_LENGTH];
    csrand::bytes(&mut raw_id);
    let identity = Keypair::new(false);
    js.node_id = hex::encode(raw_id);
    js.private_key = identity.private_hex();
    js.public_key = identity.public().hex();
    js.drbg_seed = Seed::random().hex();
    js.iat_mode = IatMode::None as i64;
    write_json_state(state_dir, js)
}

fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(data)
}

fn write_json_state(state_dir: &Path, js: &JsonServerState) -> Result<(), BoxError> {
    let encoded = serde_json::to_vec(js)?;
    write_private_file(&state_dir.join(STATE_FILE), &encoded)?;
    Ok(())
}

fn write_bridge_file(state_dir: &Path, st: &ServerState) -> Result<(), BoxError> {
    const PREFIX: &str = "# obfs4 torrc client bridge line\n\
        #\n\
        # This file is an automatically generated bridge line based on\n\
        # the current lyrebird configuration.  EDITING IT WILL HAVE NO\n\
        # EFFECT.\n\
        #\n\
        # Before distributing this Bridge, edit the placeholder fields\n\
        # to contain the actual values:\n\
        #  <IP ADDRESS>  - The public IP address of your obfs4 bridge.\n\
        #  <PORT>        - The TCP/IP port of your obfs4 bridge.\n\
        #  <FINGERPRINT> - The bridge's fingerprint.\n\n";
    let line = format!(
        "Bridge obfs4 <IP ADDRESS>:<PORT> <FINGERPRINT> {}\n",
        st.client_string()
    );
    write_private_file(
        &state_dir.join(BRIDGE_FILE),
        format!("{PREFIX}{line}").as_bytes(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_roundtrip_and_go_vectors() {
        #[derive(serde::Deserialize)]
        struct V {
            node_id: String,
            identity_private: String,
            cert: String,
        }
        let vs: Vec<V> =
            serde_json::from_str(include_str!("../../../tests/vectors/obfs4_handshake.json"))
                .unwrap();
        for v in vs {
            let id = NodeId::from_hex(&v.node_id).unwrap();
            let kp = Keypair::from_hex(&v.identity_private).unwrap();
            assert_eq!(cert_to_string(&id, kp.public()), v.cert);
            assert_eq!(cert_from_string(&v.cert).unwrap(), (id, *kp.public()));
        }
        assert!(cert_from_string("AAAA").is_err());
    }

    #[test]
    fn state_file_lifecycle() {
        let dir = std::env::temp_dir().join(format!("lyrebird-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = server_state_from_args(&dir, &Args::new()).unwrap();
        let bridge = std::fs::read_to_string(dir.join(BRIDGE_FILE)).unwrap();
        assert!(bridge.ends_with(&format!("cert={} iat-mode=0\n", first.cert())));
        let mut args = Args::new();
        args.add(IAT_ARG, "2");
        let second = server_state_from_args(&dir, &args).unwrap();
        assert_eq!(second.cert(), first.cert());
        assert_eq!(second.iat_mode, IatMode::Paranoid);
        let mut partial = Args::new();
        partial.add(NODE_ID_ARG, "00");
        assert!(server_state_from_args(&dir, &partial).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
