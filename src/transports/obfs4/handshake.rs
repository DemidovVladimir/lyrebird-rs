// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/handshake_ntor.go.

//! obfs4 handshake messages.
//!
//! Client: `X' | P_C | M_C | MAC(X' | P_C | M_C | E)`
//! Server: `Y' | AUTH | P_S | M_S | MAC(Y' | AUTH | P_S | M_S | E)`
//! where M = HMAC(B | NODEID, representative)[:16] and E is the epoch hour.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::common::csrand;
use crate::common::ntor::{
    self, Auth, KeySeed, Keypair, NodeId, PublicKey, Representative, AUTH_LENGTH,
    REPRESENTATIVE_LENGTH,
};
use crate::common::replayfilter::ReplayFilter;

use super::framing::FRAME_OVERHEAD;
use super::packet::{PACKET_OVERHEAD, SEED_PACKET_PAYLOAD_LENGTH};

pub const MAX_HANDSHAKE_LENGTH: usize = 8192;
const MARK_LENGTH: usize = 32 / 2;
const MAC_LENGTH: usize = 32 / 2;
const CLIENT_MIN_HANDSHAKE_LENGTH: usize = REPRESENTATIVE_LENGTH + MARK_LENGTH + MAC_LENGTH;
const SERVER_MIN_HANDSHAKE_LENGTH: usize =
    REPRESENTATIVE_LENGTH + AUTH_LENGTH + MARK_LENGTH + MAC_LENGTH;
pub const INLINE_SEED_FRAME_LENGTH: usize =
    FRAME_OVERHEAD + PACKET_OVERHEAD + SEED_PACKET_PAYLOAD_LENGTH;
const CLIENT_MIN_PAD_LENGTH: usize =
    (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH) - CLIENT_MIN_HANDSHAKE_LENGTH;
const CLIENT_MAX_PAD_LENGTH: usize = MAX_HANDSHAKE_LENGTH - CLIENT_MIN_HANDSHAKE_LENGTH;
const SERVER_MIN_PAD_LENGTH: usize = 0;
const SERVER_MAX_PAD_LENGTH: usize =
    MAX_HANDSHAKE_LENGTH - (SERVER_MIN_HANDSHAKE_LENGTH + INLINE_SEED_FRAME_LENGTH);

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("handshake: M_[C,S] not found yet")]
    MarkNotFoundYet,
    #[error("handshake: Failed to find M_[C,S]")]
    InvalidHandshake,
    #[error("handshake: Replay detected")]
    ReplayedHandshake,
    #[error("handshake: ntor handshake failure")]
    NtorFailed,
    #[error("handshake: MAC mismatch: Dervied: {derived} Received: {received}.")]
    InvalidMac { derived: String, received: String },
    #[error("handshake: ntor AUTH mismatch: Derived: {derived} Received:{received}.")]
    InvalidAuth { derived: String, received: String },
}

pub fn epoch_hour(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
        / 3600
}

fn hmac16(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}

fn make_pad(len: usize) -> Vec<u8> {
    let mut pad = vec![0u8; len];
    csrand::bytes(&mut pad);
    pad
}

fn mac_key(identity: &PublicKey, node_id: &NodeId) -> Vec<u8> {
    [&identity.0[..], &node_id.0[..]].concat()
}

pub struct ClientHandshake<'a> {
    keypair: &'a Keypair,
    node_id: NodeId,
    server_identity: PublicKey,
    epoch_hour: String,
    pad_len: usize,
    mac_key: Vec<u8>,
    server: Option<(Representative, Auth, [u8; MARK_LENGTH])>,
}

impl<'a> ClientHandshake<'a> {
    /// `session_key` must have an Elligator2 representative.
    pub fn new(node_id: NodeId, server_identity: PublicKey, session_key: &'a Keypair) -> Self {
        ClientHandshake {
            keypair: session_key,
            node_id,
            server_identity,
            epoch_hour: String::new(),
            pad_len: csrand::int_range(CLIENT_MIN_PAD_LENGTH as i64, CLIENT_MAX_PAD_LENGTH as i64)
                as usize,
            mac_key: mac_key(&server_identity, &node_id),
            server: None,
        }
    }

    pub fn generate(&mut self, now: SystemTime) -> Vec<u8> {
        let repr = self
            .keypair
            .representative()
            .expect("client session key has a representative");
        let mark = hmac16(&self.mac_key, &[&repr.0]);
        let mut buf = Vec::with_capacity(CLIENT_MIN_HANDSHAKE_LENGTH + self.pad_len);
        buf.extend_from_slice(&repr.0);
        buf.extend_from_slice(&make_pad(self.pad_len));
        buf.extend_from_slice(&mark);
        self.epoch_hour = epoch_hour(now).to_string();
        let mac = hmac16(&self.mac_key, &[&buf, self.epoch_hour.as_bytes()]);
        buf.extend_from_slice(&mac);
        buf
    }

    /// On success returns (bytes consumed, KEY_SEED).
    pub fn parse_server(&mut self, resp: &[u8]) -> Result<(usize, KeySeed), HandshakeError> {
        if resp.len() < SERVER_MIN_HANDSHAKE_LENGTH {
            return Err(HandshakeError::MarkNotFoundYet);
        }
        let (repr, auth, mark) = *self.server.get_or_insert_with(|| {
            let repr = Representative(resp[..REPRESENTATIVE_LENGTH].try_into().unwrap());
            let auth: Auth = resp[REPRESENTATIVE_LENGTH..REPRESENTATIVE_LENGTH + AUTH_LENGTH]
                .try_into()
                .unwrap();
            let mark = hmac16(&self.mac_key, &[&repr.0]);
            (repr, auth, mark)
        });

        let Some(pos) = find_mark_mac(
            &mark,
            resp,
            REPRESENTATIVE_LENGTH + AUTH_LENGTH + SERVER_MIN_PAD_LENGTH,
            MAX_HANDSHAKE_LENGTH,
            false,
        ) else {
            return Err(if resp.len() >= MAX_HANDSHAKE_LENGTH {
                HandshakeError::InvalidHandshake
            } else {
                HandshakeError::MarkNotFoundYet
            });
        };

        let derived = hmac16(
            &self.mac_key,
            &[&resp[..pos + MARK_LENGTH], self.epoch_hour.as_bytes()],
        );
        let received = &resp[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
        if !bool::from(derived.ct_eq(received)) {
            return Err(HandshakeError::InvalidMac {
                derived: hex::encode(derived),
                received: hex::encode(received),
            });
        }

        let server_public = repr.to_public();
        let (ok, seed, derived_auth) = ntor::client_handshake(
            self.keypair,
            &server_public,
            &self.server_identity,
            &self.node_id,
        );
        if !ok {
            return Err(HandshakeError::NtorFailed);
        }
        if !ntor::compare_auth(&derived_auth, &auth) {
            return Err(HandshakeError::InvalidAuth {
                derived: hex::encode(derived_auth),
                received: hex::encode(auth),
            });
        }
        Ok((pos + MARK_LENGTH + MAC_LENGTH, seed))
    }
}

pub struct ServerHandshake<'a> {
    keypair: &'a Keypair,
    node_id: NodeId,
    server_identity: &'a Keypair,
    epoch_hour: String,
    server_auth: Auth,
    pad_len: usize,
    mac_key: Vec<u8>,
    client: Option<[u8; MARK_LENGTH]>,
}

impl<'a> ServerHandshake<'a> {
    pub fn new(node_id: NodeId, server_identity: &'a Keypair, session_key: &'a Keypair) -> Self {
        ServerHandshake {
            keypair: session_key,
            node_id,
            server_identity,
            epoch_hour: String::new(),
            server_auth: [0; AUTH_LENGTH],
            pad_len: csrand::int_range(SERVER_MIN_PAD_LENGTH as i64, SERVER_MAX_PAD_LENGTH as i64)
                as usize,
            mac_key: mac_key(server_identity.public(), &node_id),
            client: None,
        }
    }

    /// On success returns KEY_SEED. `now` drives the epoch hour and replay filter.
    pub fn parse_client(
        &mut self,
        filter: &ReplayFilter,
        resp: &[u8],
        now: SystemTime,
    ) -> Result<KeySeed, HandshakeError> {
        if resp.len() < CLIENT_MIN_HANDSHAKE_LENGTH {
            return Err(HandshakeError::MarkNotFoundYet);
        }
        let mac_key = &self.mac_key;
        let mark = *self
            .client
            .get_or_insert_with(|| hmac16(mac_key, &[&resp[..REPRESENTATIVE_LENGTH]]));

        let Some(pos) = find_mark_mac(
            &mark,
            resp,
            REPRESENTATIVE_LENGTH + CLIENT_MIN_PAD_LENGTH,
            MAX_HANDSHAKE_LENGTH,
            true,
        ) else {
            return Err(if resp.len() >= MAX_HANDSHAKE_LENGTH {
                HandshakeError::InvalidHandshake
            } else {
                HandshakeError::MarkNotFoundYet
            });
        };

        let hour = epoch_hour(now);
        let received = &resp[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
        let mut mac_found = false;
        for off in [0i64, -1, 1] {
            let candidate = (hour + off).to_string();
            let derived = hmac16(
                &self.mac_key,
                &[&resp[..pos + MARK_LENGTH], candidate.as_bytes()],
            );
            if bool::from(derived.ct_eq(received)) {
                if filter.test_and_set(now, received) {
                    return Err(HandshakeError::ReplayedHandshake);
                }
                mac_found = true;
                self.epoch_hour = candidate;
            }
        }
        if !mac_found {
            return Err(HandshakeError::InvalidHandshake);
        }
        // The client must not send anything after its MAC.
        if resp.len() != pos + MARK_LENGTH + MAC_LENGTH {
            return Err(HandshakeError::InvalidHandshake);
        }

        let client_repr = Representative(resp[..REPRESENTATIVE_LENGTH].try_into().unwrap());
        let client_public = client_repr.to_public();
        let (ok, seed, auth) = ntor::server_handshake(
            &client_public,
            self.keypair,
            self.server_identity,
            &self.node_id,
        );
        if !ok {
            return Err(HandshakeError::NtorFailed);
        }
        self.server_auth = auth;
        Ok(seed)
    }

    /// Call after a successful `parse_client`.
    pub fn generate(&self) -> Vec<u8> {
        let repr = self
            .keypair
            .representative()
            .expect("server session key has a representative");
        let mark = hmac16(&self.mac_key, &[&repr.0]);
        let mut buf = Vec::with_capacity(SERVER_MIN_HANDSHAKE_LENGTH + self.pad_len);
        buf.extend_from_slice(&repr.0);
        buf.extend_from_slice(&self.server_auth);
        buf.extend_from_slice(&make_pad(self.pad_len));
        buf.extend_from_slice(&mark);
        let mac = hmac16(&self.mac_key, &[&buf, self.epoch_hour.as_bytes()]);
        buf.extend_from_slice(&mac);
        buf
    }
}

fn find_mark_mac(
    mark: &[u8; MARK_LENGTH],
    buf: &[u8],
    start_pos: usize,
    max_pos: usize,
    from_tail: bool,
) -> Option<usize> {
    if start_pos > buf.len() {
        return None;
    }
    let end_pos = buf.len().min(max_pos);
    if end_pos < start_pos || end_pos - start_pos < MARK_LENGTH + MAC_LENGTH {
        return None;
    }
    if from_tail {
        // The server can assume the mark is at the tail: the client stops
        // sending after its MAC until the server responds.
        let pos = end_pos - (MARK_LENGTH + MAC_LENGTH);
        return bool::from(buf[pos..pos + MARK_LENGTH].ct_eq(mark)).then_some(pos);
    }
    let pos = buf[start_pos..end_pos]
        .windows(MARK_LENGTH)
        .position(|w| w == mark)?;
    if start_pos + pos + MARK_LENGTH + MAC_LENGTH > end_pos {
        return None;
    }
    Some(start_pos + pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::time::Duration;

    #[derive(Deserialize)]
    struct HsVec {
        node_id: String,
        identity_private: String,
        client_private: String,
        client_public: String,
        server_private: String,
        server_public: String,
        epoch_hour: String,
        client_blob: String,
        server_blob: String,
        server_wire: String,
        seed: String,
    }

    fn vectors() -> Vec<HsVec> {
        serde_json::from_str(include_str!("../../../tests/vectors/obfs4_handshake.json")).unwrap()
    }

    fn at_hour(hour: &str) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(hour.parse::<u64>().unwrap() * 3600 + 1234)
    }

    fn filter() -> ReplayFilter {
        ReplayFilter::new(Duration::from_secs(3 * 3600))
    }

    #[test]
    fn server_derives_go_seed_from_go_client() {
        let filter = filter();
        for v in vectors() {
            let identity = Keypair::from_hex(&v.identity_private).unwrap();
            let node_id = NodeId::from_hex(&v.node_id).unwrap();
            let session = Keypair::from_parts(&v.server_private, &v.server_public, None);
            let mut hs = ServerHandshake::new(node_id, &identity, &session);
            let blob = hex::decode(&v.client_blob).unwrap();
            let now = at_hour(&v.epoch_hour);
            for n in [1, 31, 64, blob.len() - 1] {
                assert!(matches!(
                    hs.parse_client(&filter, &blob[..n], now),
                    Err(HandshakeError::MarkNotFoundYet)
                ));
            }
            let seed = hs.parse_client(&filter, &blob, now).unwrap();
            assert_eq!(hex::encode(seed), v.seed);
            // Same MAC again is a replay.
            let mut again = ServerHandshake::new(node_id, &identity, &session);
            assert!(matches!(
                again.parse_client(&filter, &blob, now),
                Err(HandshakeError::ReplayedHandshake)
            ));
        }
    }

    #[test]
    fn client_derives_go_seed_from_go_server() {
        for v in vectors() {
            let identity = Keypair::from_hex(&v.identity_private).unwrap();
            let node_id = NodeId::from_hex(&v.node_id).unwrap();
            let blob = hex::decode(&v.client_blob).unwrap();
            let session =
                Keypair::from_parts(&v.client_private, &v.client_public, Some(&blob[..32]));
            let mut hs = ClientHandshake::new(node_id, *identity.public(), &session);
            hs.epoch_hour = v.epoch_hour.clone();
            let wire = hex::decode(&v.server_wire).unwrap();
            let server_len = hex::decode(&v.server_blob).unwrap().len();
            assert!(matches!(
                hs.parse_server(&wire[..95]),
                Err(HandshakeError::MarkNotFoundYet)
            ));
            let (n, seed) = hs.parse_server(&wire).unwrap();
            assert_eq!(n, server_len);
            assert_eq!(hex::encode(seed), v.seed);
        }
    }

    #[test]
    fn server_rejects_wrong_epoch() {
        let v = &vectors()[0];
        let identity = Keypair::from_hex(&v.identity_private).unwrap();
        let node_id = NodeId::from_hex(&v.node_id).unwrap();
        let session = Keypair::new(true);
        let mut hs = ServerHandshake::new(node_id, &identity, &session);
        let far = at_hour(&v.epoch_hour) + Duration::from_secs(5 * 3600);
        let blob = hex::decode(&v.client_blob).unwrap();
        assert!(matches!(
            hs.parse_client(&filter(), &blob, far),
            Err(HandshakeError::InvalidHandshake)
        ));
    }

    #[test]
    fn server_rejects_trailing_data() {
        let v = &vectors()[1];
        let identity = Keypair::from_hex(&v.identity_private).unwrap();
        let node_id = NodeId::from_hex(&v.node_id).unwrap();
        let session = Keypair::new(true);
        let mut hs = ServerHandshake::new(node_id, &identity, &session);
        let mut blob = hex::decode(&v.client_blob).unwrap();
        blob.push(0);
        assert!(hs
            .parse_client(&filter(), &blob, at_hour(&v.epoch_hour))
            .is_err());
    }

    #[test]
    fn rust_client_and_server_agree() {
        let filter = filter();
        let identity = Keypair::new(false);
        let node_id = NodeId([9; 20]);
        let client_key = Keypair::new(true);
        let server_key = Keypair::new(true);
        let now = SystemTime::now();
        let mut c = ClientHandshake::new(node_id, *identity.public(), &client_key);
        let blob = c.generate(now);
        assert!(blob.len() >= CLIENT_MIN_HANDSHAKE_LENGTH + CLIENT_MIN_PAD_LENGTH);
        let mut s = ServerHandshake::new(node_id, &identity, &server_key);
        let sseed = s.parse_client(&filter, &blob, now).unwrap();
        let mut resp = s.generate();
        let resp_len = resp.len();
        resp.extend_from_slice(&[0xaa; INLINE_SEED_FRAME_LENGTH]);
        let (n, cseed) = c.parse_server(&resp).unwrap();
        assert_eq!(n, resp_len);
        assert_eq!(cseed, sseed);
    }

    #[test]
    fn wrong_node_id_never_finds_mark() {
        let filter = filter();
        let identity = Keypair::new(false);
        let client_key = Keypair::new(true);
        let server_key = Keypair::new(true);
        let now = SystemTime::now();
        let mut c = ClientHandshake::new(NodeId([1; 20]), *identity.public(), &client_key);
        let blob = c.generate(now);
        let mut s = ServerHandshake::new(NodeId([2; 20]), &identity, &server_key);
        assert!(matches!(
            s.parse_client(&filter, &blob, now),
            Err(HandshakeError::MarkNotFoundYet)
        ));
    }
}
