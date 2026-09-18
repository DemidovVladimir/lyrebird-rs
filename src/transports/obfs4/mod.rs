// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/obfs4.go.

//! obfs4 (The Obfourscator): ntor + Elligator2 handshake, secretbox frames,
//! per-bridge packet-length and inter-arrival-time obfuscation.

mod buf;
pub mod framing;
pub mod handshake;
pub mod packet;
pub mod state;

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::common::drbg::{HashDrbg, Seed};
use crate::common::gorand::Rand;
use crate::common::ntor::{self, Keypair, NodeId, PublicKey};
use crate::common::probdist::WeightedDist;
use crate::common::replayfilter::ReplayFilter;
use crate::proxy::Dialer;
use crate::pt::Args;
use crate::transports::{
    self, BoxError, BoxFuture, ClientArgs, Conn, DialError, ReadHalf, WriteHalf,
};

use buf::Buf;
use framing::{Decoder, Encoder, FRAME_OVERHEAD, KEY_LENGTH, MAXIMUM_SEGMENT_LENGTH};
use handshake::{ClientHandshake, HandshakeError, ServerHandshake, MAX_HANDSHAKE_LENGTH};
use packet::{
    make_packet, parse_packet, CONSUME_READ_SIZE, MAX_PACKET_PAYLOAD_LENGTH, PACKET_OVERHEAD,
    PACKET_TYPE_PAYLOAD, PACKET_TYPE_PRNG_SEED, SEED_PACKET_PAYLOAD_LENGTH,
};

pub const TRANSPORT_NAME: &str = "obfs4";
const NODE_ID_ARG: &str = "node-id";
const PUBLIC_KEY_ARG: &str = "public-key";
const PRIVATE_KEY_ARG: &str = "private-key";
const SEED_ARG: &str = "drbg-seed";
const IAT_ARG: &str = "iat-mode";
const CERT_ARG: &str = "cert";

const HEADER_LENGTH: usize = FRAME_OVERHEAD + PACKET_OVERHEAD;
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const REPLAY_TTL: Duration = Duration::from_secs(3 * 3600);
const MAX_IAT_DELAY: usize = 100;
const MAX_CLOSE_DELAY: i64 = 60;

/// `-obfs4-distBias`: ScrambleSuit-style (biased) table generation.
pub static BIASED_DIST: AtomicBool = AtomicBool::new(false);

fn biased() -> bool {
    BIASED_DIST.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IatMode {
    None = 0,
    Enabled = 1,
    Paranoid = 2,
}

impl IatMode {
    pub fn from_int(v: i64) -> Option<IatMode> {
        match v {
            0 => Some(IatMode::None),
            1 => Some(IatMode::Enabled),
            2 => Some(IatMode::Paranoid),
            _ => None,
        }
    }
}

fn iat_seed_from(seed: &Seed) -> Seed {
    Seed::from_bytes(&Sha256::digest(seed.0)).expect("sha256 output is long enough")
}

/// Length and IAT distributions shared by a connection's two halves: the
/// reader re-seeds them when the server's PRNG seed packet arrives.
struct Dists {
    len: WeightedDist,
    iat: Option<WeightedDist>,
}

type SharedDists = Arc<Mutex<Dists>>;

fn new_dists(len_seed: &Seed, iat_seed: Option<Seed>) -> SharedDists {
    Arc::new(Mutex::new(Dists {
        len: WeightedDist::new(len_seed, 0, MAXIMUM_SEGMENT_LENGTH, biased()),
        iat: iat_seed.map(|s| WeightedDist::new(&s, 0, MAX_IAT_DELAY, biased())),
    }))
}

pub struct Transport;

impl transports::Transport for Transport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn client_factory(
        &self,
        _state_dir: &Path,
    ) -> Result<Arc<dyn transports::ClientFactory>, BoxError> {
        Ok(Arc::new(ClientFactory))
    }

    fn server_factory(
        &self,
        state_dir: &Path,
        args: &Args,
    ) -> Result<Arc<dyn transports::ServerFactory>, BoxError> {
        let st = state::server_state_from_args(state_dir, args)?;
        let iat_seed = (st.iat_mode != IatMode::None).then(|| iat_seed_from(&st.drbg_seed));
        let mut pt_args = Args::new();
        pt_args.add(CERT_ARG, &st.cert());
        pt_args.add(IAT_ARG, &(st.iat_mode as u8).to_string());
        let close_delay = Rand::new(HashDrbg::new(&st.drbg_seed)).intn(MAX_CLOSE_DELAY) as u64;
        Ok(Arc::new(ServerFactory {
            args: pt_args,
            node_id: st.node_id,
            identity_key: st.identity_key,
            len_seed: st.drbg_seed,
            iat_seed,
            iat_mode: st.iat_mode,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
            close_delay: Duration::from_secs(close_delay),
        }))
    }
}

struct ClientParams {
    node_id: NodeId,
    public_key: PublicKey,
    session_key: Keypair,
    iat_mode: IatMode,
}

pub struct ClientFactory;

impl transports::ClientFactory for ClientFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn parse_args(&self, args: &Args) -> Result<ClientArgs, BoxError> {
        let (node_id, public_key) = match args.get(CERT_ARG) {
            Some(cert) => state::cert_from_string(cert)?,
            None => {
                let node_id = args
                    .get(NODE_ID_ARG)
                    .ok_or_else(|| format!("missing argument '{NODE_ID_ARG}'"))?;
                let node_id = NodeId::from_hex(node_id)?;
                let public_key = args
                    .get(PUBLIC_KEY_ARG)
                    .ok_or_else(|| format!("missing argument '{PUBLIC_KEY_ARG}'"))?;
                (node_id, PublicKey::from_hex(public_key)?)
            }
        };
        let iat = args
            .get(IAT_ARG)
            .ok_or_else(|| format!("missing argument '{IAT_ARG}'"))?;
        let iat_mode = iat
            .parse::<i64>()
            .ok()
            .and_then(IatMode::from_int)
            .ok_or_else(|| format!("invalid iat-mode '{iat}'"))?;
        Ok(Box::new(ClientParams {
            node_id,
            public_key,
            session_key: Keypair::new(true),
            iat_mode,
        }))
    }

    fn dial<'a>(
        &'a self,
        target: &'a str,
        dialer: &'a Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>> {
        Box::pin(async move {
            let params = args
                .downcast::<ClientParams>()
                .map_err(|_| DialError::Other("invalid argument type for args".into()))?;
            let tcp = dialer.dial(target).await?;
            client_conn(tcp, *params).await
        })
    }
}

async fn client_conn(tcp: TcpStream, params: ClientParams) -> Result<Conn, DialError> {
    let seed = Seed::random();
    let iat_seed = (params.iat_mode != IatMode::None).then(|| iat_seed_from(&seed));
    let dists = new_dists(&seed, iat_seed);
    let mut tcp = tcp;
    let mut receive = Buf::default();
    let okm = tokio::time::timeout(
        CLIENT_HANDSHAKE_TIMEOUT,
        client_handshake(&mut tcp, &params, &mut receive),
    )
    .await
    // Upstream's deadline error maps to a general SOCKS failure, not TTL expired.
    .map_err(|_| DialError::Other("handshake: i/o timeout".into()))??;
    Ok(split_conn(
        tcp,
        &okm[..KEY_LENGTH],
        &okm[KEY_LENGTH..],
        false,
        receive,
        dists,
        params.iat_mode,
    ))
}

async fn client_handshake(
    tcp: &mut TcpStream,
    params: &ClientParams,
    receive: &mut Buf,
) -> Result<zeroize::Zeroizing<Vec<u8>>, DialError> {
    let mut hs = ClientHandshake::new(params.node_id, params.public_key, &params.session_key);
    let blob = hs.generate(SystemTime::now());
    tcp.write_all(&blob).await?;
    let mut hs_buf = [0u8; MAX_HANDSHAKE_LENGTH];
    loop {
        let n = tcp.read(&mut hs_buf).await?;
        if n == 0 {
            return Err(DialError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        receive.extend(&hs_buf[..n]);
        match hs.parse_server(receive.as_slice()) {
            Err(HandshakeError::MarkNotFoundYet) => continue,
            Err(e) => return Err(DialError::Other(e.into())),
            Ok((consumed, seed)) => {
                receive.consume(consumed);
                return Ok(ntor::kdf(&seed, KEY_LENGTH * 2));
            }
        }
    }
}

pub struct ServerFactory {
    args: Args,
    node_id: NodeId,
    identity_key: Keypair,
    len_seed: Seed,
    iat_seed: Option<Seed>,
    iat_mode: IatMode,
    replay_filter: ReplayFilter,
    close_delay: Duration,
}

impl transports::ServerFactory for ServerFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn args(&self) -> Option<Args> {
        Some(self.args.clone())
    }

    fn wrap(&self, conn: TcpStream) -> BoxFuture<'_, Result<Conn, BoxError>> {
        Box::pin(self.wrap_conn(conn))
    }
}

impl ServerFactory {
    async fn wrap_conn(&self, mut tcp: TcpStream) -> Result<Conn, BoxError> {
        let session_key = Keypair::new(true);
        let dists = new_dists(&self.len_seed, self.iat_seed);
        let start = Instant::now();
        let mut hs = ServerHandshake::new(self.node_id, &self.identity_key, &session_key);

        let parsed = tokio::time::timeout(SERVER_HANDSHAKE_TIMEOUT, async {
            let mut receive = Buf::default();
            let mut hs_buf = [0u8; MAX_HANDSHAKE_LENGTH];
            loop {
                let n = tcp.read(&mut hs_buf).await?;
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
                self.close_after_delay(tcp, start).await;
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
        tcp.write_all(&frame_buf).await?;

        let (rd, wr) = tcp.into_split();
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
    async fn close_after_delay(&self, mut tcp: TcpStream, start: Instant) {
        let deadline = start + self.close_delay + SERVER_HANDSHAKE_TIMEOUT;
        if Instant::now() > deadline {
            return;
        }
        let drain = async {
            let mut sink = [0u8; 4096];
            while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
        };
        let _ = tokio::time::timeout_at(deadline.into(), drain).await;
    }
}

fn split_conn(
    tcp: TcpStream,
    encoder_key: &[u8],
    decoder_key: &[u8],
    is_server: bool,
    receive: Buf,
    dists: SharedDists,
    iat_mode: IatMode,
) -> Conn {
    let (rd, wr) = tcp.into_split();
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
fn assemble(
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
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
            dists: dists.clone(),
            eof: false,
            error: None,
        }),
        writer: Box::new(Obfs4Writer {
            wr,
            encoder,
            iat_mode,
            dists,
        }),
    }
}

struct Obfs4Reader {
    rd: OwnedReadHalf,
    decoder: Decoder,
    receive: Buf,
    decoded: Buf,
    read_buf: Vec<u8>,
    is_server: bool,
    dists: SharedDists,
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
    wr: OwnedWriteHalf,
    encoder: Encoder,
    iat_mode: IatMode,
    dists: SharedDists,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::{ClientFactory as _, Transport as _};
    use tokio::net::TcpListener;

    async fn pair(iat: IatMode) -> (Conn, Conn) {
        let dir = std::env::temp_dir().join(format!(
            "lyrebird-obfs4-{}-{:?}-{}",
            std::process::id(),
            iat,
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut args = Args::new();
        args.add(IAT_ARG, &(iat as u8).to_string());
        let sf = Transport.server_factory(&dir, &args).unwrap();
        let cert = sf.args().unwrap();
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (tcp, _) = ln.accept().await.unwrap();
            sf.wrap(tcp).await.unwrap()
        });
        let cf = Transport.client_factory(&dir).unwrap();
        let mut cargs = Args::new();
        cargs.add(CERT_ARG, cert.get(CERT_ARG).unwrap());
        cargs.add(IAT_ARG, cert.get(IAT_ARG).unwrap());
        let parsed = cf.parse_args(&cargs).unwrap();
        let client = cf.dial(&addr, &Dialer::Direct, parsed).await.unwrap();
        let server = server.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
        (client, server)
    }

    fn rand_suffix() -> u64 {
        let mut b = [0u8; 8];
        crate::common::csrand::bytes(&mut b);
        u64::from_le_bytes(b)
    }

    async fn transfer(mut from: Conn, mut to: Conn, data: Vec<u8>, read_size: usize) -> Vec<u8> {
        let len = data.len();
        let writer = tokio::spawn(async move {
            for chunk in data.chunks(7919) {
                from.writer.write_all(chunk).await.unwrap();
            }
            from
        });
        let mut got = Vec::with_capacity(len);
        let mut buf = vec![0u8; read_size];
        while got.len() < len {
            let n = to.reader.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF");
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        got
    }

    #[tokio::test]
    async fn rust_to_rust_all_iat_modes() {
        for iat in [IatMode::None, IatMode::Enabled, IatMode::Paranoid] {
            let (client, server) = pair(iat).await;
            let data: Vec<u8> = (0..60_000u32).map(|i| (i * 7 % 251) as u8).collect();
            let size = if iat == IatMode::None { 65536 } else { 16 };
            assert_eq!(
                transfer(client, server, data.clone(), size).await,
                data,
                "{iat:?}"
            );
        }
    }

    #[tokio::test]
    async fn server_to_client_and_eof() {
        let (mut client, mut server) = pair(IatMode::None).await;
        server.writer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(client.reader.read(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf, b"hel");
        assert_eq!(client.reader.read(&mut buf).await.unwrap(), 2);
        drop(server);
        assert_eq!(client.reader.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn wrong_cert_is_rejected_by_server() {
        let dir = std::env::temp_dir().join(format!("lyrebird-obfs4-bad-{}", rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let sf = Transport.server_factory(&dir, &Args::new()).unwrap();
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (tcp, _) = ln.accept().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), sf.wrap(tcp)).await
        });
        let cf = ClientFactory;
        let mut cargs = Args::new();
        cargs.add(
            CERT_ARG,
            &state::cert_to_string(&NodeId([7; 20]), Keypair::new(false).public()),
        );
        cargs.add(IAT_ARG, "0");
        let parsed = cf.parse_args(&cargs).unwrap();
        let dial = tokio::time::timeout(
            Duration::from_secs(2),
            cf.dial(&addr, &Dialer::Direct, parsed),
        )
        .await;
        assert!(dial.is_err(), "client must still be waiting");
        // Either still inside its close delay or ended by our EOF; never a session.
        assert!(!matches!(server.await.unwrap(), Ok(Ok(_))));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_args_errors() {
        let cf = ClientFactory;
        assert!(cf.parse_args(&Args::new()).is_err());
        let mut a = Args::new();
        a.add(
            CERT_ARG,
            &state::cert_to_string(&NodeId([1; 20]), &PublicKey([2; 32])),
        );
        assert!(cf.parse_args(&a).is_err(), "iat-mode is required");
        a.add(IAT_ARG, "3");
        assert!(cf.parse_args(&a).is_err());
        let mut legacy = Args::new();
        legacy.add(NODE_ID_ARG, &"11".repeat(20));
        legacy.add(PUBLIC_KEY_ARG, &"22".repeat(32));
        legacy.add(IAT_ARG, "1");
        assert!(cf.parse_args(&legacy).is_ok());
    }
}
