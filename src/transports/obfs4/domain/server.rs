// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/obfs4.go (server side).

//! obfs4 server: the bridge's handshake, with probe-resistant closing.

use std::io;
use std::time::{Duration, Instant, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::buf::Buf;
use super::conn::{assemble, iat_seed_from, SharedDists};
use super::framing::{Decoder, Encoder, KEY_LENGTH};
use super::handshake::{HandshakeError, ServerHandshake, MAX_HANDSHAKE_LENGTH};
use super::packet::{make_packet, PACKET_TYPE_PRNG_SEED};
use super::state::ServerState;
use super::transport::{IatMode, TRANSPORT_NAME};
use crate::shared::domain::crypto::drbg::Seed;
use crate::shared::domain::crypto::ntor::{self, Keypair, NodeId};
use crate::shared::domain::crypto::replayfilter::ReplayFilter;
use crate::shared::domain::pt::Args;
use crate::shared::ports::stream::BoxStream;
use crate::shared::ports::transport::{self, Conn};
use crate::shared::ports::{BoxError, BoxFuture};

const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const REPLAY_TTL: Duration = Duration::from_secs(3 * 3600);

pub struct ServerFactory {
    args: Args,
    node_id: NodeId,
    identity_key: Keypair,
    len_seed: Seed,
    iat_seed: Option<Seed>,
    iat_mode: IatMode,
    replay_filter: ReplayFilter,
    close_delay: Duration,
    biased: bool,
}

impl ServerFactory {
    /// `args` go on the SMETHOD line; a failed handshake is held open until
    /// `close_delay` after the handshake timeout.
    pub fn new(st: ServerState, args: Args, close_delay: Duration, biased: bool) -> ServerFactory {
        let iat_seed = (st.iat_mode != IatMode::None).then(|| iat_seed_from(&st.drbg_seed));
        ServerFactory {
            args,
            node_id: st.node_id,
            identity_key: st.identity_key,
            len_seed: st.drbg_seed,
            iat_seed,
            iat_mode: st.iat_mode,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            close_delay,
            biased,
        }
    }
}

impl transport::ServerFactory for ServerFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn args(&self) -> Option<Args> {
        Some(self.args.clone())
    }

    fn wrap(&self, conn: BoxStream) -> BoxFuture<'_, Result<Conn, BoxError>> {
        Box::pin(self.wrap_conn(conn))
    }
}

impl ServerFactory {
    async fn wrap_conn(&self, mut stream: BoxStream) -> Result<Conn, BoxError> {
        let session_key = Keypair::new(true);
        let dists = SharedDists::new(&self.len_seed, self.iat_seed, self.biased);
        let start = Instant::now();
        let mut hs = ServerHandshake::new(self.node_id, &self.identity_key, &session_key);

        let parsed = tokio::time::timeout(SERVER_HANDSHAKE_TIMEOUT, async {
            let mut receive = Buf::default();
            let mut hs_buf = [0u8; MAX_HANDSHAKE_LENGTH];
            loop {
                let n = stream.read(&mut hs_buf).await?;
                if n == 0 {
                    return Err::<_, BoxError>(Box::new(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )));
                }
                receive.extend(&hs_buf[..n]);
                match hs.parse_client(&self.replay_filter, receive.as_slice(), SystemTime::now()) {
                    Err(HandshakeError::MarkNotFoundYet) => continue,
                    Err(e) => return Err(e.into()),
                    Ok(seed) => return Ok(seed),
                }
            }
        })
        .await
        .unwrap_or_else(|_| Err(Box::new(io::Error::from(io::ErrorKind::TimedOut)) as BoxError));

        let seed = match parsed {
            Ok(seed) => seed,
            Err(e) => {
                self.close_after_delay(stream, start).await;
                return Err(e);
            }
        };
        let okm = ntor::kdf(&seed, KEY_LENGTH * 2);
        let mut encoder = Encoder::new(&okm[KEY_LENGTH..]);

        let mut frame_buf = hs.generate();
        make_packet(
            &mut encoder,
            &mut frame_buf,
            PACKET_TYPE_PRNG_SEED,
            &self.len_seed.0,
            0,
        )?;
        stream.write_all(&frame_buf).await?;

        let (rd, wr) = stream.split();
        Ok(assemble(
            rd,
            wr,
            encoder,
            Decoder::new(&okm[..KEY_LENGTH]),
            true,
            Buf::default(),
            dists,
            self.iat_mode,
        ))
    }

    /// Probe resistance: keep reading (and discarding) until a per-bridge
    /// fixed delay after the connection started, then close.
    async fn close_after_delay(&self, mut stream: BoxStream, start: Instant) {
        let deadline = start + self.close_delay + SERVER_HANDSHAKE_TIMEOUT;
        if Instant::now() > deadline {
            return;
        }
        let drain = async {
            let mut sink = [0u8; 4096];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        };
        let _ = tokio::time::timeout_at(deadline.into(), drain).await;
    }
}
