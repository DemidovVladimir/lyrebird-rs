// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/statefile.go.

//! Bridge identity: where it comes from (args, or the stored state created
//! on first run), the bridge line, and the `cert=` argument (base64 of
//! NODEID | PUBKEY without padding).

use base64::Engine;

use super::transport::{IatMode, CERT_ARG, IAT_ARG, NODE_ID_ARG, PRIVATE_KEY_ARG, SEED_ARG};
use crate::shared::domain::crypto::csrand;
use crate::shared::domain::crypto::drbg::Seed;
use crate::shared::domain::crypto::ntor::{
    Keypair, NodeId, PublicKey, NODE_ID_LENGTH, PUBLIC_KEY_LENGTH,
};
use crate::shared::domain::pt::Args;
use crate::shared::ports::BoxError;
use crate::transports::obfs4::ports::state_store::{BridgeStateStore, StoredState};

const CERT_SUFFIX: &str = "==";
const CERT_LENGTH: usize = NODE_ID_LENGTH + PUBLIC_KEY_LENGTH;

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

    /// The contents of `obfs4_bridgeline.txt`.
    pub fn bridge_line_file(&self) -> String {
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
        format!(
            "{PREFIX}Bridge obfs4 <IP ADDRESS>:<PORT> <FINGERPRINT> {}\n",
            self.client_string()
        )
    }
}

/// Keys come either all from args or all from the store (created on first
/// run); `iat-mode` may override either.
pub fn server_state_from_args(
    store: &dyn BridgeStateStore,
    args: &Args,
) -> Result<ServerState, BoxError> {
    let mut js = StoredState::default();
    let node_id = args.get(NODE_ID_ARG);
    let private_key = args.get(PRIVATE_KEY_ARG);
    let seed = args.get(SEED_ARG);
    match (private_key, node_id, seed) {
        (None, None, None) => {
            js = match store.load()? {
                Some(stored) => stored,
                None => new_state(store)?,
            }
        }
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
    state_from_stored(store, &js)
}

fn state_from_stored(
    store: &dyn BridgeStateStore,
    js: &StoredState,
) -> Result<ServerState, BoxError> {
    let st = ServerState {
        node_id: NodeId::from_hex(&js.node_id)?,
        identity_key: Keypair::from_hex(&js.private_key)?,
        drbg_seed: Seed::from_hex(&js.drbg_seed)?,
        iat_mode: IatMode::from_int(js.iat_mode)
            .ok_or_else(|| format!("invalid iat-mode '{}'", js.iat_mode))?,
    };
    store.save_bridge_line(&st.bridge_line_file())?;
    store.save(js)?;
    Ok(st)
}

/// A fresh identity, saved right away.
fn new_state(store: &dyn BridgeStateStore) -> Result<StoredState, BoxError> {
    let mut raw_id = [0u8; NODE_ID_LENGTH];
    csrand::bytes(&mut raw_id);
    let identity = Keypair::new(false);
    let js = StoredState {
        node_id: hex::encode(raw_id),
        private_key: identity.private_hex(),
        public_key: identity.public().hex(),
        drbg_seed: Seed::random().hex(),
        iat_mode: IatMode::None as i64,
    };
    store.save(&js)?;
    Ok(js)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Keeps the state in memory.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        pub state: Mutex<Option<StoredState>>,
        pub bridge_line: Mutex<String>,
    }

    impl BridgeStateStore for MemoryStore {
        fn load(&self) -> Result<Option<StoredState>, BoxError> {
            Ok(self.state.lock().unwrap().clone())
        }

        fn save(&self, state: &StoredState) -> Result<(), BoxError> {
            *self.state.lock().unwrap() = Some(state.clone());
            Ok(())
        }

        fn save_bridge_line(&self, text: &str) -> Result<(), BoxError> {
            *self.bridge_line.lock().unwrap() = text.to_string();
            Ok(())
        }
    }

    #[test]
    fn cert_roundtrip_and_go_vectors() {
        #[derive(serde::Deserialize)]
        struct V {
            node_id: String,
            identity_private: String,
            cert: String,
        }
        let vs: Vec<V> = serde_json::from_str(include_str!(
            "../../../../tests/vectors/obfs4_handshake.json"
        ))
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
    fn state_lifecycle() {
        let store = MemoryStore::default();
        let first = server_state_from_args(&store, &Args::new()).unwrap();
        let saved = store.state.lock().unwrap().clone().unwrap();
        assert_eq!(saved.public_key, first.identity_key.public().hex());
        assert!(store
            .bridge_line
            .lock()
            .unwrap()
            .ends_with(&format!("cert={} iat-mode=0\n", first.cert())));
        let mut args = Args::new();
        args.add(IAT_ARG, "2");
        let second = server_state_from_args(&store, &args).unwrap();
        assert_eq!(second.cert(), first.cert());
        assert_eq!(second.iat_mode, IatMode::Paranoid);
        assert_eq!(store.state.lock().unwrap().as_ref().unwrap().iat_mode, 2);
        let mut partial = Args::new();
        partial.add(NODE_ID_ARG, "00");
        assert!(server_state_from_args(&store, &partial).is_err());
    }
}
