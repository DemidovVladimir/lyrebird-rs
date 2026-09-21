// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/packet.go.

//! obfs4 packets inside frames: `uint8 type | uint16 length | payload | zero padding`.

use crate::shared::domain::crypto::drbg;

use super::framing::{Encoder, FrameError, MAXIMUM_FRAME_PAYLOAD_LENGTH, MAXIMUM_SEGMENT_LENGTH};

pub const PACKET_OVERHEAD: usize = 2 + 1;
pub const MAX_PACKET_PAYLOAD_LENGTH: usize = MAXIMUM_FRAME_PAYLOAD_LENGTH - PACKET_OVERHEAD;
pub const SEED_PACKET_PAYLOAD_LENGTH: usize = drbg::SEED_LENGTH;
/// Upstream reads the socket in chunks this large.
pub const CONSUME_READ_SIZE: usize = MAXIMUM_SEGMENT_LENGTH * 16;

pub const PACKET_TYPE_PAYLOAD: u8 = 0;
pub const PACKET_TYPE_PRNG_SEED: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet: Invalid packet length: {0}")]
    InvalidPacketLength(usize),
    #[error("packet: Invalid payload length: {0}")]
    InvalidPayloadLength(usize),
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Encodes one packet as one frame appended to `out`.
pub fn make_packet(
    encoder: &mut Encoder,
    out: &mut Vec<u8>,
    pkt_type: u8,
    data: &[u8],
    pad_len: usize,
) -> Result<(), FrameError> {
    assert!(
        data.len() + pad_len <= MAX_PACKET_PAYLOAD_LENGTH,
        "BUG: make_packet() len(data) + padLen > maxPacketPayloadLength: {} + {} > {}",
        data.len(),
        pad_len,
        MAX_PACKET_PAYLOAD_LENGTH
    );
    let mut pkt = Vec::with_capacity(PACKET_OVERHEAD + data.len() + pad_len);
    pkt.push(pkt_type);
    pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
    pkt.extend_from_slice(data);
    pkt.resize(PACKET_OVERHEAD + data.len() + pad_len, 0);
    encoder.encode(&pkt, out)
}

/// A decoded packet: (type, payload). Padding is dropped.
pub fn parse_packet(pkt: &[u8]) -> Result<(u8, &[u8]), PacketError> {
    if pkt.len() < PACKET_OVERHEAD {
        return Err(PacketError::InvalidPacketLength(pkt.len()));
    }
    let payload_len = u16::from_be_bytes([pkt[1], pkt[2]]) as usize;
    if payload_len > pkt.len() - PACKET_OVERHEAD {
        return Err(PacketError::InvalidPayloadLength(payload_len));
    }
    Ok((pkt[0], &pkt[PACKET_OVERHEAD..PACKET_OVERHEAD + payload_len]))
}

#[cfg(test)]
mod tests {
    use super::super::buf::Buf;
    use super::super::framing::{Decoder, KEY_LENGTH};
    use super::*;

    #[test]
    fn roundtrip_with_padding() {
        let key = [3u8; KEY_LENGTH];
        let mut enc = Encoder::new(&key);
        let mut dec = Decoder::new(&key);
        let mut wire = Vec::new();
        make_packet(&mut enc, &mut wire, PACKET_TYPE_PAYLOAD, b"hi", 100).unwrap();
        make_packet(&mut enc, &mut wire, PACKET_TYPE_PRNG_SEED, &[7; 24], 0).unwrap();
        make_packet(
            &mut enc,
            &mut wire,
            PACKET_TYPE_PAYLOAD,
            &[],
            MAX_PACKET_PAYLOAD_LENGTH,
        )
        .unwrap();
        let mut buf = Buf::default();
        buf.extend(&wire);
        let p = dec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(p.len(), PACKET_OVERHEAD + 2 + 100);
        assert_eq!(parse_packet(&p).unwrap(), (PACKET_TYPE_PAYLOAD, &b"hi"[..]));
        let p = dec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            parse_packet(&p).unwrap(),
            (PACKET_TYPE_PRNG_SEED, &[7u8; 24][..])
        );
        let p = dec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(parse_packet(&p).unwrap(), (PACKET_TYPE_PAYLOAD, &[][..]));
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(parse_packet(&[0, 0]).is_err());
        assert!(parse_packet(&[0, 0, 5, 1, 2]).is_err());
    }
}
