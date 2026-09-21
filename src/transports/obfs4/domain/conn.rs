// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/obfs4.go (obfs4Conn Read/Write).

//! An established obfs4 connection: secretbox frames over any byte
//! stream, with per-bridge packet-length and inter-arrival-time
//! obfuscation.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::buf::Buf;
use super::framing::{self, Decoder, Encoder, FRAME_OVERHEAD, MAXIMUM_SEGMENT_LENGTH};
use super::packet::{
    make_packet, parse_packet, CONSUME_READ_SIZE, MAX_PACKET_PAYLOAD_LENGTH, PACKET_OVERHEAD,
    PACKET_TYPE_PAYLOAD, PACKET_TYPE_PRNG_SEED, SEED_PACKET_PAYLOAD_LENGTH,
};
use super::transport::IatMode;
use crate::shared::domain::crypto::drbg::Seed;
use crate::shared::domain::crypto::probdist::WeightedDist;
use crate::shared::ports::stream::{BoxRead, BoxStream, BoxWrite};
use crate::shared::ports::transport::{Conn, ReadHalf, WriteHalf};
use crate::shared::ports::BoxFuture;

const HEADER_LENGTH: usize = FRAME_OVERHEAD + PACKET_OVERHEAD;
const MAX_IAT_DELAY: usize = 100;

pub fn iat_seed_from(seed: &Seed) -> Seed {
    Seed::from_bytes(&Sha256::digest(seed.0)).expect("sha256 output is long enough")
}

/// Length and IAT distributions shared by a connection's two halves: the
/// reader re-seeds them when the server's PRNG seed packet arrives.
struct Dists {
    len: WeightedDist,
    iat: Option<WeightedDist>,
}

pub struct SharedDists(Arc<Mutex<Dists>>);

impl SharedDists {
    pub fn new(len_seed: &Seed, iat_seed: Option<Seed>, biased: bool) -> SharedDists {
        SharedDists(Arc::new(Mutex::new(Dists {
            len: WeightedDist::new(len_seed, 0, MAXIMUM_SEGMENT_LENGTH, biased),
            iat: iat_seed.map(|s| WeightedDist::new(&s, 0, MAX_IAT_DELAY, biased)),
        })))
    }
}

pub fn split_conn(
    stream: BoxStream,
    encoder_key: &[u8],
    decoder_key: &[u8],
    is_server: bool,
    receive: Buf,
    dists: SharedDists,
    iat_mode: IatMode,
) -> Conn {
    let (rd, wr) = stream.split();
    assemble(
        rd,
        wr,
        Encoder::new(encoder_key),
        Decoder::new(decoder_key),
        is_server,
        receive,
        dists,
        iat_mode,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn assemble(
    rd: BoxRead,
    wr: BoxWrite,
    encoder: Encoder,
    decoder: Decoder,
    is_server: bool,
    receive: Buf,
    dists: SharedDists,
    iat_mode: IatMode,
) -> Conn {
    Conn {
        reader: Box::new(Obfs4Reader {
            rd,
            decoder,
            receive,
            decoded: Buf::default(),
            read_buf: vec![0u8; CONSUME_READ_SIZE],
            is_server,
            dists: dists.0.clone(),
            eof: false,
            error: None,
        }),
        writer: Box::new(Obfs4Writer {
            wr,
            encoder,
            iat_mode,
            dists: dists.0,
        }),
    }
}

struct Obfs4Reader {
    rd: BoxRead,
    decoder: Decoder,
    receive: Buf,
    decoded: Buf,
    read_buf: Vec<u8>,
    is_server: bool,
    dists: Arc<Mutex<Dists>>,
    eof: bool,
    error: Option<io::Error>,
}

impl Obfs4Reader {
    /// Decodes every complete frame already buffered.
    fn process_buffered(&mut self) -> io::Result<()> {
        while !self.receive.is_empty() {
            let pkt = match self.decoder.decode(&mut self.receive) {
                Ok(Some(pkt)) => pkt,
                Ok(None) => break,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };
            let (pkt_type, payload) =
                parse_packet(&pkt).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            match pkt_type {
                PACKET_TYPE_PAYLOAD => self.decoded.extend(payload),
                PACKET_TYPE_PRNG_SEED
                    if payload.len() == SEED_PACKET_PAYLOAD_LENGTH && !self.is_server =>
                {
                    let seed = Seed::from_bytes(payload).expect("length checked");
                    let mut d = self.dists.lock().unwrap();
                    d.len.reset(&seed);
                    if let Some(iat) = d.iat.as_mut() {
                        iat.reset(&iat_seed_from(&seed));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn read_impl(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.decoded.is_empty() {
                return Ok(self.decoded.read_into(out));
            }
            if let Some(e) = self.error.take() {
                return Err(e);
            }
            if self.eof {
                return Ok(0);
            }
            // Upstream reads the socket before decoding what is already
            // buffered; decode first so no complete frame waits on the network.
            if let Err(e) = self.process_buffered() {
                self.error = Some(e);
                continue;
            }
            if !self.decoded.is_empty() {
                continue;
            }
            match self.rd.read(&mut self.read_buf).await {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    let (receive, read_buf) = (&mut self.receive, &self.read_buf);
                    receive.extend(&read_buf[..n]);
                }
                Err(e) => self.error = Some(e),
            }
            if let Err(e) = self.process_buffered() {
                self.error = Some(e);
            }
        }
    }
}

impl ReadHalf for Obfs4Reader {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(self.read_impl(buf))
    }
}

struct Obfs4Writer {
    wr: BoxWrite,
    encoder: Encoder,
    iat_mode: IatMode,
    dists: Arc<Mutex<Dists>>,
}

/// Paranoid mode resamples zero lengths (lyrebird 0.8.1 panics on them); a
/// table that keeps producing zeros falls back to MTU-sized writes.
const MAX_ZERO_LENGTH_SAMPLES: usize = 64;

fn frame_err(e: framing::FrameError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl Obfs4Writer {
    /// Pads `burst` so its last segment is `to_pad_to` bytes long.
    fn pad_burst(
        &mut self,
        burst: &mut Vec<u8>,
        pending: usize,
        to_pad_to: usize,
    ) -> io::Result<()> {
        let tail_len = pending % MAXIMUM_SEGMENT_LENGTH;
        let pad_len = if to_pad_to >= tail_len {
            to_pad_to - tail_len
        } else {
            (MAXIMUM_SEGMENT_LENGTH - tail_len) + to_pad_to
        };
        if pad_len > HEADER_LENGTH {
            make_packet(
                &mut self.encoder,
                burst,
                PACKET_TYPE_PAYLOAD,
                &[],
                pad_len - HEADER_LENGTH,
            )
            .map_err(frame_err)?;
        } else if pad_len > 0 {
            make_packet(
                &mut self.encoder,
                burst,
                PACKET_TYPE_PAYLOAD,
                &[],
                MAX_PACKET_PAYLOAD_LENGTH,
            )
            .map_err(frame_err)?;
            make_packet(&mut self.encoder, burst, PACKET_TYPE_PAYLOAD, &[], pad_len)
                .map_err(frame_err)?;
        }
        Ok(())
    }

    fn sample_len(&self) -> usize {
        self.dists.lock().unwrap().len.sample()
    }

    fn sample_iat(&self) -> Duration {
        let d = self.dists.lock().unwrap();
        let units = d.iat.as_ref().map_or(0, WeightedDist::sample) as u64;
        // Delay resolution is 100 µs, so at most 10 ms.
        Duration::from_micros(units * 100)
    }

    async fn write_impl(&mut self, b: &[u8]) -> io::Result<()> {
        let mut frames = Vec::with_capacity(b.len() + b.len() / 8 + 2 * MAXIMUM_SEGMENT_LENGTH);
        for chunk in b.chunks(MAX_PACKET_PAYLOAD_LENGTH) {
            make_packet(
                &mut self.encoder,
                &mut frames,
                PACKET_TYPE_PAYLOAD,
                chunk,
                0,
            )
            .map_err(frame_err)?;
        }
        if self.iat_mode != IatMode::Paranoid {
            let target = self.sample_len();
            let pending = frames.len();
            self.pad_burst(&mut frames, pending, target)?;
        }

        if self.iat_mode == IatMode::None {
            return self.wr.write_all(&frames).await;
        }

        let mut burst = Buf::default();
        burst.extend(&frames);
        let mut zero_samples = 0;
        while !burst.is_empty() {
            let wr_len = match self.iat_mode {
                IatMode::Paranoid => {
                    let target = self.sample_len();
                    if target == 0 && zero_samples < MAX_ZERO_LENGTH_SAMPLES {
                        zero_samples += 1;
                        continue;
                    }
                    if target == 0 {
                        burst.len().min(MAXIMUM_SEGMENT_LENGTH)
                    } else {
                        if burst.len() < target {
                            let mut pad = Vec::new();
                            let pending = burst.len();
                            self.pad_burst(&mut pad, pending, target)?;
                            burst.extend(&pad);
                            if burst.len() != target {
                                // Padding spilled into another frame; resample.
                                continue;
                            }
                        }
                        target
                    }
                }
                _ => burst.len().min(MAXIMUM_SEGMENT_LENGTH),
            };
            zero_samples = 0;
            let delay = self.sample_iat();
            self.wr.write_all(&burst.as_slice()[..wr_len]).await?;
            burst.consume(wr_len);
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }
}

impl WriteHalf for Obfs4Writer {
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(self.write_impl(buf))
    }

    fn shutdown(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(self.wr.shutdown())
    }
}
