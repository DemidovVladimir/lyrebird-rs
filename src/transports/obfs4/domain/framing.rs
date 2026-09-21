// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/framing.

//! obfs4 frames: `uint16 obfuscated length | NaCl secretbox(payload)`.
//! The length is XORed with SipHash-DRBG output; the nonce is a
//! 16-byte prefix plus a big-endian 64-bit counter starting at 1.

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use zeroize::Zeroizing;

use crate::shared::domain::crypto::csrand;
use crate::shared::domain::crypto::drbg::{self, HashDrbg, Seed};

use super::buf::Buf;

/// Maximum wire length of a frame (1500 MTU - IPv6/TCP headers).
pub const MAXIMUM_SEGMENT_LENGTH: usize = 1500 - (40 + 12);
const LENGTH_LENGTH: usize = 2;
const SECRETBOX_OVERHEAD: usize = 16;
pub const FRAME_OVERHEAD: usize = LENGTH_LENGTH + SECRETBOX_OVERHEAD;
pub const MAXIMUM_FRAME_PAYLOAD_LENGTH: usize = MAXIMUM_SEGMENT_LENGTH - FRAME_OVERHEAD;

const KEY_LENGTH_SECRETBOX: usize = 32;
const NONCE_PREFIX_LENGTH: usize = 16;
const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + 8;
/// Key material per direction: secretbox key | nonce prefix | DRBG seed.
pub const KEY_LENGTH: usize = KEY_LENGTH_SECRETBOX + NONCE_PREFIX_LENGTH + drbg::SEED_LENGTH;

const MAX_FRAME_LENGTH: u16 = (MAXIMUM_SEGMENT_LENGTH - LENGTH_LENGTH) as u16;
const MIN_FRAME_LENGTH: u16 = (FRAME_OVERHEAD - LENGTH_LENGTH) as u16;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("framing: Poly1305 tag mismatch")]
    TagMismatch,
    #[error("framing: Nonce counter wrapped")]
    NonceCounterWrapped,
    #[error("framing: Invalid payload length: {0}")]
    InvalidPayloadLength(usize),
}

struct BoxNonce {
    prefix: [u8; NONCE_PREFIX_LENGTH],
    counter: u64,
}

impl BoxNonce {
    fn new(prefix: &[u8]) -> BoxNonce {
        BoxNonce {
            prefix: prefix.try_into().expect("nonce prefix length"),
            counter: 1,
        }
    }

    fn bytes(&self) -> Result<[u8; NONCE_LENGTH], FrameError> {
        if self.counter == 0 {
            return Err(FrameError::NonceCounterWrapped);
        }
        let mut out = [0u8; NONCE_LENGTH];
        out[..NONCE_PREFIX_LENGTH].copy_from_slice(&self.prefix);
        out[NONCE_PREFIX_LENGTH..].copy_from_slice(&self.counter.to_be_bytes());
        Ok(out)
    }
}

fn split_key(key: &[u8]) -> (XSalsa20Poly1305, BoxNonce, HashDrbg) {
    assert_eq!(key.len(), KEY_LENGTH, "BUG: Invalid framing key length");
    let secretbox_key = Zeroizing::new(Key::clone_from_slice(&key[..KEY_LENGTH_SECRETBOX]));
    let cipher = XSalsa20Poly1305::new(&secretbox_key);
    let nonce =
        BoxNonce::new(&key[KEY_LENGTH_SECRETBOX..KEY_LENGTH_SECRETBOX + NONCE_PREFIX_LENGTH]);
    let seed = Seed::from_bytes(&key[KEY_LENGTH_SECRETBOX + NONCE_PREFIX_LENGTH..])
        .expect("seed length is fixed");
    (cipher, nonce, HashDrbg::new(&seed))
}

pub struct Encoder {
    cipher: XSalsa20Poly1305,
    nonce: BoxNonce,
    drbg: HashDrbg,
}

impl Encoder {
    pub fn new(key: &[u8]) -> Encoder {
        let (cipher, nonce, drbg) = split_key(key);
        Encoder {
            cipher,
            nonce,
            drbg,
        }
    }

    /// Appends one frame carrying `payload` to `out`.
    pub fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
        if payload.len() > MAXIMUM_FRAME_PAYLOAD_LENGTH {
            return Err(FrameError::InvalidPayloadLength(payload.len()));
        }
        let nonce = self.nonce.bytes()?;
        self.nonce.counter = self.nonce.counter.wrapping_add(1);
        let sealed = self
            .cipher
            .encrypt(&Nonce::from(nonce), payload)
            .expect("secretbox seal cannot fail");
        let mask = self.drbg.next_block();
        let length = (sealed.len() as u16) ^ u16::from_be_bytes([mask[0], mask[1]]);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&sealed);
        Ok(())
    }
}

pub struct Decoder {
    cipher: XSalsa20Poly1305,
    nonce: BoxNonce,
    drbg: HashDrbg,
    next_nonce: [u8; NONCE_LENGTH],
    next_length: u16,
    next_length_invalid: bool,
}

impl Decoder {
    pub fn new(key: &[u8]) -> Decoder {
        let (cipher, nonce, drbg) = split_key(key);
        Decoder {
            cipher,
            nonce,
            drbg,
            next_nonce: [0; NONCE_LENGTH],
            next_length: 0,
            next_length_invalid: false,
        }
    }

    /// Decodes one frame from the front of `frames`. `Ok(None)` means more
    /// data is needed (upstream's `ErrAgain`); any error is fatal.
    pub fn decode(&mut self, frames: &mut Buf) -> Result<Option<Vec<u8>>, FrameError> {
        if self.next_length == 0 {
            if frames.len() < LENGTH_LENGTH {
                return Ok(None);
            }
            let obfs = frames.as_slice();
            let obfs_len = u16::from_be_bytes([obfs[0], obfs[1]]);
            frames.consume(LENGTH_LENGTH);
            self.next_nonce = self.nonce.bytes()?;
            let mask = self.drbg.next_block();
            let mut length = obfs_len ^ u16::from_be_bytes([mask[0], mask[1]]);
            if !(MIN_FRAME_LENGTH..=MAX_FRAME_LENGTH).contains(&length) {
                // Don't reveal the bad length: wait for a random amount of
                // data, then fail (the SSH plaintext-recovery countermeasure).
                self.next_length_invalid = true;
                length = csrand::int_range(MIN_FRAME_LENGTH as i64, MAX_FRAME_LENGTH as i64) as u16;
            }
            self.next_length = length;
        }

        let n = self.next_length as usize;
        if frames.len() < n {
            return Ok(None);
        }
        let opened = self
            .cipher
            .decrypt(&Nonce::from(self.next_nonce), &frames.as_slice()[..n]);
        frames.consume(n);
        let plaintext = match opened {
            Ok(p) if !self.next_length_invalid => p,
            _ => return Err(FrameError::TagMismatch),
        };
        self.next_length = 0;
        self.nonce.counter = self.nonce.counter.wrapping_add(1);
        Ok(Some(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct FrameVec {
        payload: String,
        frame: String,
    }
    #[derive(Deserialize)]
    struct KeyVec {
        key: String,
        frames: Vec<FrameVec>,
    }

    fn vectors() -> Vec<KeyVec> {
        serde_json::from_str(include_str!("../../../../tests/vectors/framing.json")).unwrap()
    }

    #[test]
    fn encoder_matches_go() {
        for v in vectors() {
            let mut enc = Encoder::new(&hex::decode(&v.key).unwrap());
            for f in &v.frames {
                let mut out = Vec::new();
                enc.encode(&hex::decode(&f.payload).unwrap(), &mut out)
                    .unwrap();
                assert_eq!(hex::encode(out), f.frame);
            }
        }
    }

    #[test]
    fn decoder_reads_go_frames_in_pieces() {
        for v in vectors() {
            let mut dec = Decoder::new(&hex::decode(&v.key).unwrap());
            let mut buf = Buf::default();
            let wire: Vec<u8> = v
                .frames
                .iter()
                .flat_map(|f| hex::decode(&f.frame).unwrap())
                .collect();
            let mut got = Vec::new();
            // Feed in awkward chunk sizes to exercise partial frames.
            for chunk in wire.chunks(7) {
                buf.extend(chunk);
                while let Some(p) = dec.decode(&mut buf).unwrap() {
                    got.push(hex::encode(p));
                }
            }
            let want: Vec<String> = v.frames.iter().map(|f| f.payload.clone()).collect();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let v = &vectors()[0];
        let mut dec = Decoder::new(&hex::decode(&v.key).unwrap());
        let mut buf = Buf::default();
        // Frame 0 first so the nonce/DRBG line up, then corrupt frame 1.
        buf.extend(&hex::decode(&v.frames[0].frame).unwrap());
        dec.decode(&mut buf).unwrap().unwrap();
        let mut second = hex::decode(&v.frames[1].frame).unwrap();
        let last = second.len() - 1;
        second[last] ^= 1;
        buf.extend(&second);
        assert!(matches!(dec.decode(&mut buf), Err(FrameError::TagMismatch)));
    }

    #[test]
    fn oversize_payload_is_rejected() {
        let mut enc = Encoder::new(&[1u8; KEY_LENGTH]);
        let mut out = Vec::new();
        let err = enc.encode(&[0u8; MAXIMUM_FRAME_PAYLOAD_LENGTH + 1], &mut out);
        assert!(matches!(err, Err(FrameError::InvalidPayloadLength(_))));
        assert!(enc
            .encode(&[0u8; MAXIMUM_FRAME_PAYLOAD_LENGTH], &mut out)
            .is_ok());
        assert_eq!(out.len(), MAXIMUM_SEGMENT_LENGTH);
    }
}
