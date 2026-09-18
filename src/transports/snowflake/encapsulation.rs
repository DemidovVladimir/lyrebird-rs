// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 common/encapsulation.

//! Packets over a byte stream. Each chunk starts with a prefix byte:
//! bit 7 = data (else padding), bit 6 = more length bytes follow; 6 + 7 + 7
//! bits of length at most.

use std::io;

use crate::transports::BoxFuture;

pub trait ByteRead: Send {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
}

async fn read_byte(r: &mut dyn ByteRead) -> io::Result<Option<u8>> {
    let mut b = [0u8; 1];
    match r.read(&mut b).await? {
        0 => Ok(None),
        _ => Ok(Some(b[0])),
    }
}

async fn read_exact(r: &mut dyn ByteRead, buf: &mut [u8]) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        let k = r.read(&mut buf[n..]).await?;
        if k == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        n += k;
    }
    Ok(())
}

async fn discard(r: &mut dyn ByteRead, mut n: usize) -> io::Result<()> {
    let mut sink = [0u8; 1024];
    while n > 0 {
        let k = n.min(sink.len());
        read_exact(r, &mut sink[..k]).await?;
        n -= k;
    }
    Ok(())
}

/// Reads the next data chunk into `p`, skipping padding. Returns the bytes
/// stored; a chunk larger than `p` is truncated (the rest is discarded).
/// `Ok(None)` is a clean EOF between chunks.
pub async fn read_data(r: &mut dyn ByteRead, p: &mut [u8]) -> io::Result<Option<usize>> {
    loop {
        let Some(b) = read_byte(r).await? else {
            return Ok(None);
        };
        let is_data = b & 0x80 != 0;
        let mut more = b & 0x40 != 0;
        let mut n = (b & 0x3f) as usize;
        let mut i = 0;
        while more {
            if i >= 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length prefix is too long",
                ));
            }
            let b = read_byte(r).await?.ok_or(io::ErrorKind::UnexpectedEof)?;
            more = b & 0x80 != 0;
            n = (n << 7) | (b & 0x7f) as usize;
            i += 1;
        }
        if is_data {
            let take = n.min(p.len());
            read_exact(r, &mut p[..take]).await?;
            discard(r, n - take).await?;
            return Ok(Some(take));
        }
        discard(r, n).await?;
    }
}

fn data_prefix(n: usize) -> io::Result<Vec<u8>> {
    if n >> 6 == 0 {
        Ok(vec![0x80 | n as u8])
    } else if n >> 13 == 0 {
        Ok(vec![0xc0 | (n >> 7) as u8, (n & 0x7f) as u8])
    } else if n >> 20 == 0 {
        Ok(vec![
            0xc0 | (n >> 14) as u8,
            0x80 | ((n >> 7) & 0x7f) as u8,
            (n & 0x7f) as u8,
        ])
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "length prefix is too long",
        ))
    }
}

/// One encapsulated data chunk (prefix + data) as a single buffer.
pub fn encode_data(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = data_prefix(data.len())?;
    out.extend_from_slice(data);
    Ok(out)
}

/// `n` bytes of padding chunks.
pub fn encode_padding(mut n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while n > 0 {
        let mut p = n.min(1024);
        n -= p;
        if (p - 1) >> 6 == 0 {
            p -= 1;
            out.push(p as u8);
        } else if (p - 2) >> 13 == 0 {
            p -= 2;
            out.extend_from_slice(&[0x40 | (p >> 7) as u8, (p & 0x7f) as u8]);
        } else {
            p -= 3;
            out.extend_from_slice(&[
                0x40 | (p >> 14) as u8,
                0x80 | ((p >> 7) & 0x3f) as u8,
                (p & 0x7f) as u8,
            ]);
        }
        out.resize(out.len() + p, 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Slice(Vec<u8>, usize);

    impl ByteRead for Slice {
        fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
            Box::pin(async move {
                // One byte at a time to exercise the parser.
                if self.1 >= self.0.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[self.1];
                self.1 += 1;
                Ok(1)
            })
        }
    }

    #[test]
    fn prefixes_match_upstream() {
        // Worked through upstream's prefix rules (n < 2^6, 2^13, 2^20).
        assert_eq!(data_prefix(0).unwrap(), [0x80]);
        assert_eq!(data_prefix(63).unwrap(), [0xbf]);
        assert_eq!(data_prefix(64).unwrap(), [0xc0, 0x40]);
        assert_eq!(data_prefix(8191).unwrap(), [0xff, 0x7f]);
        assert_eq!(data_prefix(8192).unwrap(), [0xc0, 0xc0, 0x00]);
        assert_eq!(data_prefix(1048575).unwrap(), [0xff, 0xff, 0x7f]);
        assert!(data_prefix(1048576).is_err());
        assert_eq!(encode_padding(1), [0x00]);
        assert_eq!(encode_padding(2), [0x01, 0x00]);
        assert_eq!(encode_padding(66)[..2], [0x40, 0x40]);
    }

    #[tokio::test]
    async fn roundtrip_with_padding_and_truncation() {
        let mut wire = Vec::new();
        wire.extend(encode_padding(1500));
        wire.extend(encode_data(b"hello").unwrap());
        wire.extend(encode_padding(3));
        let big: Vec<u8> = (0..9000u32).map(|i| i as u8).collect();
        wire.extend(encode_data(&big).unwrap());
        wire.extend(encode_data(b"").unwrap());
        let mut r = Slice(wire, 0);
        let mut buf = vec![0u8; 100];
        assert_eq!(read_data(&mut r, &mut buf).await.unwrap(), Some(5));
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(read_data(&mut r, &mut buf).await.unwrap(), Some(100));
        assert_eq!(&buf[..100], &big[..100]);
        assert_eq!(read_data(&mut r, &mut buf).await.unwrap(), Some(0));
        assert_eq!(read_data(&mut r, &mut buf).await.unwrap(), None);
    }

    #[tokio::test]
    async fn truncated_input_is_an_error() {
        // Cases from upstream's TestReadDataTruncated.
        let cases: [&[u8]; 16] = [
            &[0x40],
            &[0xc0],
            &[0x41, 0x80],
            &[0xc1, 0x80],
            &[0x02],
            &[0x82],
            &[0x02, b'X'],
            &[0x82, b'X'],
            &[0x41, 0x00],
            &[0xc1, 0x00],
            &[0x41, 0x00, b'X'],
            &[0xc1, 0x00, b'X'],
            &[0x41, 0x80, 0x00],
            &[0xc1, 0x80, 0x00],
            &[0x41, 0x80, 0x00, b'X'],
            &[0xc1, 0x80, 0x00, b'X'],
        ];
        for c in cases {
            let mut r = Slice(c.to_vec(), 0);
            let mut buf = [0u8; 8];
            let err = read_data(&mut r, &mut buf).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{c:?}");
        }
    }

    #[tokio::test]
    async fn rejects_long_prefix() {
        let mut r = Slice(vec![0xc0, 0x80, 0x80, 0x00], 0);
        let mut buf = [0u8; 4];
        assert!(read_data(&mut r, &mut buf).await.is_err());
    }
}
