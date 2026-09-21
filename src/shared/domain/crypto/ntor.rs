// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/ntor.

//! The obfs4 variant of Tor's ntor handshake (includes obfs4's duplicated
//! `B` in the transcript suffix) plus the Elligator2 keypair helpers.

use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::SimpleHkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{csrand, x25519ell2};

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const REPRESENTATIVE_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const NODE_ID_LENGTH: usize = 20;
pub const KEY_SEED_LENGTH: usize = 32;
pub const AUTH_LENGTH: usize = 32;

const PROTO_ID: &[u8] = b"ntor-curve25519-sha256-1";
const T_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
const T_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
const T_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:key_verify";
const M_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

pub type KeySeed = [u8; KEY_SEED_LENGTH];
pub type Auth = [u8; AUTH_LENGTH];

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("ntor: Invalid NodeID length: {0}")]
    NodeIdLength(usize),
    #[error("ntor: Invalid Curve25519 public key length: {0}")]
    PublicKeyLength(usize),
    #[error("ntor: Invalid Curve25519 private key length: {0}")]
    PrivateKeyLength(usize),
    #[error("{0}")]
    Hex(#[from] hex::FromHexError),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NodeId(pub [u8; NODE_ID_LENGTH]);

impl NodeId {
    pub fn new(raw: &[u8]) -> Result<NodeId, KeyError> {
        raw.try_into()
            .map(NodeId)
            .map_err(|_| KeyError::NodeIdLength(raw.len()))
    }

    pub fn from_hex(encoded: &str) -> Result<NodeId, KeyError> {
        NodeId::new(&hex::decode(encoded)?)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    pub fn new(raw: &[u8]) -> Result<PublicKey, KeyError> {
        raw.try_into()
            .map(PublicKey)
            .map_err(|_| KeyError::PublicKeyLength(raw.len()))
    }

    pub fn from_hex(encoded: &str) -> Result<PublicKey, KeyError> {
        PublicKey::new(&hex::decode(encoded)?)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Representative(pub [u8; REPRESENTATIVE_LENGTH]);

impl Representative {
    pub fn to_public(&self) -> PublicKey {
        PublicKey(x25519ell2::representative_to_public_key(&self.0))
    }
}

pub struct Keypair {
    public: PublicKey,
    private: Zeroizing<[u8; PRIVATE_KEY_LENGTH]>,
    representative: Option<Representative>,
}

impl Keypair {
    /// A fresh keypair; with `elligator`, retries until the key has a representative.
    pub fn new(elligator: bool) -> Keypair {
        loop {
            let mut raw = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
            csrand::bytes(&mut raw[..]);
            if let Some(kp) = Keypair::from_random(&raw, elligator) {
                return kp;
            }
        }
    }

    /// One iteration of `new`: private = SHA-512(raw)[..32], tweak = SHA-512(raw)[63].
    pub fn from_random(raw: &[u8; PRIVATE_KEY_LENGTH], elligator: bool) -> Option<Keypair> {
        let digest = Zeroizing::new(Sha512::digest(raw));
        let mut private = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
        private.copy_from_slice(&digest[..PRIVATE_KEY_LENGTH]);
        if elligator {
            let (public, repr) = x25519ell2::scalar_base_mult(&private, digest[63])?;
            Some(Keypair {
                public: PublicKey(public),
                private,
                representative: Some(Representative(repr)),
            })
        } else {
            let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();
            Some(Keypair {
                public: PublicKey(public),
                private,
                representative: None,
            })
        }
    }

    /// A keypair from a stored private key (no representative).
    pub fn from_private(raw: &[u8]) -> Result<Keypair, KeyError> {
        let private: [u8; PRIVATE_KEY_LENGTH] = raw
            .try_into()
            .map_err(|_| KeyError::PrivateKeyLength(raw.len()))?;
        let private = Zeroizing::new(private);
        let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();
        Ok(Keypair {
            public: PublicKey(public),
            private,
            representative: None,
        })
    }

    pub fn from_hex(encoded: &str) -> Result<Keypair, KeyError> {
        let raw = Zeroizing::new(hex::decode(encoded)?);
        Keypair::from_private(&raw)
    }

    /// Test vectors carry the (dirty) public key alongside the private key.
    #[cfg(test)]
    pub(crate) fn from_parts(private: &str, public: &str, repr: Option<&[u8]>) -> Keypair {
        Keypair {
            public: PublicKey::from_hex(public).unwrap(),
            private: Zeroizing::new(hex::decode(private).unwrap().try_into().unwrap()),
            representative: repr.map(|r| Representative(r.try_into().unwrap())),
        }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn private_bytes(&self) -> &[u8; PRIVATE_KEY_LENGTH] {
        &self.private
    }

    pub fn private_hex(&self) -> String {
        hex::encode(*self.private)
    }

    pub fn representative(&self) -> Option<&Representative> {
        self.representative.as_ref()
    }
}

fn x25519(scalar: &[u8; 32], point: &PublicKey) -> [u8; 32] {
    MontgomeryPoint(point.0).mul_clamped(*scalar).to_bytes()
}

fn is_zero(x: &[u8; 32]) -> bool {
    bool::from(x.ct_eq(&[0u8; 32]))
}

/// Server side: returns (ok, key_seed, auth).
pub fn server_handshake(
    client_public: &PublicKey,
    server_keypair: &Keypair,
    id_keypair: &Keypair,
    id: &NodeId,
) -> (bool, KeySeed, Auth) {
    let exp1 = Zeroizing::new(x25519(&server_keypair.private, client_public));
    let exp2 = Zeroizing::new(x25519(&id_keypair.private, client_public));
    let not_ok = is_zero(&exp1) | is_zero(&exp2);
    let (seed, auth) = ntor_common(
        &exp1,
        &exp2,
        id,
        &id_keypair.public,
        client_public,
        &server_keypair.public,
    );
    (!not_ok, seed, auth)
}

/// Client side: returns (ok, key_seed, auth).
pub fn client_handshake(
    client_keypair: &Keypair,
    server_public: &PublicKey,
    id_public: &PublicKey,
    id: &NodeId,
) -> (bool, KeySeed, Auth) {
    let exp1 = Zeroizing::new(x25519(&client_keypair.private, server_public));
    let exp2 = Zeroizing::new(x25519(&client_keypair.private, id_public));
    let not_ok = is_zero(&exp1) | is_zero(&exp2);
    let (seed, auth) = ntor_common(
        &exp1,
        &exp2,
        id,
        id_public,
        &client_keypair.public,
        server_public,
    );
    (!not_ok, seed, auth)
}

pub fn compare_auth(a: &Auth, b: &[u8]) -> bool {
    b.len() == AUTH_LENGTH && bool::from(a.ct_eq(b))
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

fn ntor_common(
    exp1: &[u8; 32],
    exp2: &[u8; 32],
    id: &NodeId,
    b: &PublicKey,
    x: &PublicKey,
    y: &PublicKey,
) -> (KeySeed, Auth) {
    // Upstream's suffix starts from a buffer already holding B, then writes B
    // again: B | B | X | Y | PROTOID | ID.
    let mut suffix = Vec::with_capacity(4 * 32 + PROTO_ID.len() + NODE_ID_LENGTH);
    suffix.extend_from_slice(&b.0);
    suffix.extend_from_slice(&b.0);
    suffix.extend_from_slice(&x.0);
    suffix.extend_from_slice(&y.0);
    suffix.extend_from_slice(PROTO_ID);
    suffix.extend_from_slice(&id.0);

    let key_seed = hmac_sha256(T_KEY, &[exp1, exp2, &suffix]);
    let verify = hmac_sha256(T_VERIFY, &[exp1, exp2, &suffix]);
    let auth = hmac_sha256(T_MAC, &[&verify, &suffix, b"Server"]);
    (key_seed, auth)
}

/// HKDF-SHA256(salt = t_key, info = m_expand).
pub fn kdf(key_seed: &[u8], okm_len: usize) -> Zeroizing<Vec<u8>> {
    let mut okm = Zeroizing::new(vec![0u8; okm_len]);
    SimpleHkdf::<Sha256>::new(Some(T_KEY), key_seed)
        .expand(M_EXPAND, &mut okm)
        .expect("HKDF output length within bounds");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct HsVec {
        client_raw: String,
        client_ok: bool,
        client_private: String,
        client_public: String,
        client_repr: String,
        server_raw: String,
        server_public: String,
        identity_private: String,
        identity_public: String,
        node_id: String,
        server_ok: bool,
        client_seed: String,
        server_seed: String,
        client_auth: String,
        server_auth: String,
        kdf144: String,
    }

    fn raw(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn handshake_matches_go() {
        let vectors: Vec<HsVec> =
            serde_json::from_str(include_str!("../../../../tests/vectors/ntor.json")).unwrap();
        let mut checked = 0;
        for v in vectors {
            let client = Keypair::from_random(&raw(&v.client_raw), true);
            assert_eq!(client.is_some(), v.client_ok);
            let Some(client) = client else { continue };
            assert_eq!(client.private_hex(), v.client_private);
            assert_eq!(client.public().hex(), v.client_public);
            assert_eq!(
                hex::encode(client.representative().unwrap().0),
                v.client_repr
            );
            assert_eq!(
                client.representative().unwrap().to_public(),
                *client.public()
            );

            let server = Keypair::from_random(&raw(&v.server_raw), true).unwrap();
            assert_eq!(server.public().hex(), v.server_public);
            let identity = Keypair::from_hex(&v.identity_private).unwrap();
            assert_eq!(identity.public().hex(), v.identity_public);
            let id = NodeId::from_hex(&v.node_id).unwrap();

            let (sok, sseed, sauth) = server_handshake(client.public(), &server, &identity, &id);
            let (cok, cseed, cauth) =
                client_handshake(&client, server.public(), identity.public(), &id);
            assert_eq!(sok && cok, v.server_ok);
            assert_eq!(hex::encode(sseed), v.server_seed);
            assert_eq!(hex::encode(cseed), v.client_seed);
            assert_eq!(hex::encode(sauth), v.server_auth);
            assert_eq!(hex::encode(cauth), v.client_auth);
            assert!(compare_auth(&sauth, &cauth));
            assert_eq!(hex::encode(&*kdf(&sseed, 144)), v.kdf144);
            checked += 1;
        }
        assert!(checked >= 4, "only {checked} usable vectors");
    }
}
