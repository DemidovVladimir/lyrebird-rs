// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/obfs4/obfs4.go (the transport and its args).

//! The obfs4 transport as the application sees it.

use std::sync::Arc;
use std::time::Duration;

use super::client::ClientFactory;
use super::server::ServerFactory;
use super::state;
use crate::shared::domain::crypto::drbg::HashDrbg;
use crate::shared::domain::crypto::gorand::Rand;
use crate::shared::domain::pt::Args;
use crate::shared::ports::transport;
use crate::shared::ports::BoxError;
use crate::transports::obfs4::ports::state_store::BridgeStateStore;

pub const TRANSPORT_NAME: &str = "obfs4";
pub const NODE_ID_ARG: &str = "node-id";
pub const PUBLIC_KEY_ARG: &str = "public-key";
pub const PRIVATE_KEY_ARG: &str = "private-key";
pub const SEED_ARG: &str = "drbg-seed";
pub const IAT_ARG: &str = "iat-mode";
pub const CERT_ARG: &str = "cert";

const MAX_CLOSE_DELAY: i64 = 60;

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

pub struct Transport {
    store: Arc<dyn BridgeStateStore>,
    biased: bool,
}

impl Transport {
    /// `store` holds the bridge identity (server side). `biased` is
    /// `-obfs4-distBias`: ScrambleSuit-style (biased) length and IAT tables.
    pub fn new(store: Arc<dyn BridgeStateStore>, biased: bool) -> Transport {
        Transport { store, biased }
    }
}

impl transport::Transport for Transport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn client_factory(&self) -> Result<Arc<dyn transport::ClientFactory>, BoxError> {
        Ok(Arc::new(ClientFactory::new(self.biased)))
    }

    fn server_factory(&self, args: &Args) -> Result<Arc<dyn transport::ServerFactory>, BoxError> {
        let st = state::server_state_from_args(&*self.store, args)?;
        let mut pt_args = Args::new();
        pt_args.add(CERT_ARG, &st.cert());
        pt_args.add(IAT_ARG, &(st.iat_mode as u8).to_string());
        let close_delay = Rand::new(HashDrbg::new(&st.drbg_seed)).intn(MAX_CLOSE_DELAY) as u64;
        Ok(Arc::new(ServerFactory::new(
            st,
            pt_args,
            Duration::from_secs(close_delay),
            self.biased,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::domain::crypto::ntor::{Keypair, NodeId, PublicKey};
    use crate::shared::ports::dialer::Dialer;
    use crate::shared::ports::stream::BoxStream;
    use crate::shared::ports::transport::{ClientFactory as _, Conn, Transport as _};
    use crate::shared::ports::BoxFuture;
    use crate::transports::obfs4::domain::state::{self, tests::MemoryStore};
    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;

    /// Dials in-memory pipes; the far ends come out of the receiver.
    struct PipeDialer(mpsc::UnboundedSender<DuplexStream>);

    impl Dialer for PipeDialer {
        fn dial<'a>(&'a self, _addr: &'a str) -> BoxFuture<'a, std::io::Result<BoxStream>> {
            Box::pin(async move {
                let (near, far) = tokio::io::duplex(64 * 1024);
                self.0
                    .send(far)
                    .map_err(|_| std::io::ErrorKind::ConnectionRefused)?;
                Ok(Box::new(near) as BoxStream)
            })
        }

        fn is_direct(&self) -> bool {
            true
        }
    }

    fn pipe() -> (PipeDialer, mpsc::UnboundedReceiver<DuplexStream>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (PipeDialer(tx), rx)
    }

    async fn pair(iat: IatMode) -> (Conn, Conn) {
        let t = Transport::new(Arc::new(MemoryStore::default()), false);
        let mut args = Args::new();
        args.add(IAT_ARG, &(iat as u8).to_string());
        let sf = t.server_factory(&args).unwrap();
        let cert = sf.args().unwrap();
        let (dialer, mut accepted) = pipe();
        let server = tokio::spawn(async move {
            let conn = accepted.recv().await.unwrap();
            sf.wrap(Box::new(conn)).await.unwrap()
        });
        let cf = t.client_factory().unwrap();
        let mut cargs = Args::new();
        cargs.add(CERT_ARG, cert.get(CERT_ARG).unwrap());
        cargs.add(IAT_ARG, cert.get(IAT_ARG).unwrap());
        let parsed = cf.parse_args(&cargs).unwrap();
        let client = cf.dial("bridge.test:443", &dialer, parsed).await.unwrap();
        let server = server.await.unwrap();
        (client, server)
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
        let t = Transport::new(Arc::new(MemoryStore::default()), false);
        let sf = t.server_factory(&Args::new()).unwrap();
        let (dialer, mut accepted) = pipe();
        let server = tokio::spawn(async move {
            let conn = accepted.recv().await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), sf.wrap(Box::new(conn))).await
        });
        let cf = ClientFactory::new(false);
        let mut cargs = Args::new();
        cargs.add(
            CERT_ARG,
            &state::cert_to_string(&NodeId([7; 20]), Keypair::new(false).public()),
        );
        cargs.add(IAT_ARG, "0");
        let parsed = cf.parse_args(&cargs).unwrap();
        let dial = tokio::time::timeout(
            Duration::from_secs(2),
            cf.dial("bridge.test:443", &dialer, parsed),
        )
        .await;
        assert!(dial.is_err(), "client must still be waiting");
        // Either still inside its close delay or ended by our EOF; never a session.
        assert!(!matches!(server.await.unwrap(), Ok(Ok(_))));
    }

    #[test]
    fn parse_args_errors() {
        let cf = ClientFactory::new(false);
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
