// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/obfs4.go (client side).

//! obfs4 client: bridge-line arguments and the client handshake.

use std::io;
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::buf::Buf;
use super::conn::{iat_seed_from, split_conn, SharedDists};
use super::framing::KEY_LENGTH;
use super::handshake::{ClientHandshake, HandshakeError, MAX_HANDSHAKE_LENGTH};
use super::state;
use super::transport::{IatMode, CERT_ARG, IAT_ARG, NODE_ID_ARG, PUBLIC_KEY_ARG, TRANSPORT_NAME};
use crate::shared::domain::crypto::drbg::Seed;
use crate::shared::domain::crypto::ntor::{self, Keypair, NodeId, PublicKey};
use crate::shared::domain::pt::Args;
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::stream::BoxStream;
use crate::shared::ports::transport::{self, ClientArgs, Conn, DialError};
use crate::shared::ports::{BoxError, BoxFuture};

const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

struct ClientParams {
    node_id: NodeId,
    public_key: PublicKey,
    session_key: Keypair,
    iat_mode: IatMode,
}

pub struct ClientFactory {
    biased: bool,
}

impl ClientFactory {
    pub fn new(biased: bool) -> ClientFactory {
        ClientFactory { biased }
    }
}

impl transport::ClientFactory for ClientFactory {
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
        dialer: &'a dyn Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>> {
        Box::pin(async move {
            let params = args
                .downcast::<ClientParams>()
                .map_err(|_| DialError::Other("invalid argument type for args".into()))?;
            let stream = dialer.dial(target).await?;
            client_conn(stream, *params, self.biased).await
        })
    }
}

async fn client_conn(
    mut stream: BoxStream,
    params: ClientParams,
    biased: bool,
) -> Result<Conn, DialError> {
    let seed = Seed::random();
    let iat_seed = (params.iat_mode != IatMode::None).then(|| iat_seed_from(&seed));
    let dists = SharedDists::new(&seed, iat_seed, biased);
    let mut receive = Buf::default();
    let okm = tokio::time::timeout(
        CLIENT_HANDSHAKE_TIMEOUT,
        client_handshake(&mut stream, &params, &mut receive),
    )
    .await
    // Upstream's deadline error maps to a general SOCKS failure, not TTL expired.
    .map_err(|_| DialError::Other("handshake: i/o timeout".into()))??;
    Ok(split_conn(
        stream,
        &okm[..KEY_LENGTH],
        &okm[KEY_LENGTH..],
        false,
        receive,
        dists,
        params.iat_mode,
    ))
}

async fn client_handshake(
    stream: &mut BoxStream,
    params: &ClientParams,
    receive: &mut Buf,
) -> Result<zeroize::Zeroizing<Vec<u8>>, DialError> {
    let mut hs = ClientHandshake::new(params.node_id, params.public_key, &params.session_key);
    let blob = hs.generate(SystemTime::now());
    stream.write_all(&blob).await?;
    let mut hs_buf = [0u8; MAX_HANDSHAKE_LENGTH];
    loop {
        let n = stream.read(&mut hs_buf).await?;
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
