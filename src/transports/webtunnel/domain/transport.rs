// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/webtunnel/{webtunnel.go,client.go}.

//! The webtunnel transport as the application sees it (client only).
//!
//! A dial ignores the SOCKS target. It connects to the bridge URL's host
//! (or `addr=`), does TLS for `https` with the URL host (or `servername=`,
//! `sni-imitation=`) as SNI, sends `GET <path>` with the upgrade headers
//! and, after `101 Switching Protocols`, hands the raw stream to tor.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::config::{parse_client_args, tls_checks, ClientConfig};
use super::servername;
use super::upgrade;
use crate::shared::domain::http::Connection;
use crate::shared::domain::pt::{Args, LogSeverity, TorControl};
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::log;
use crate::shared::ports::transport::{self, ClientArgs, Conn, DialError, Plain, ReadHalf};
use crate::shared::ports::{BoxError, BoxFuture, BoxStream};
use crate::transports::webtunnel::ports::tls::TlsConnector;

pub const TRANSPORT_NAME: &str = "webtunnel";

pub struct Transport {
    tls: Arc<dyn TlsConnector>,
    tor: TorControl,
}

impl Transport {
    /// Errors and the SNI in use are reported to tor through `tor`.
    pub fn new(tls: Arc<dyn TlsConnector>, tor: TorControl) -> Transport {
        Transport { tls, tor }
    }
}

impl transport::Transport for Transport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn client_factory(&self) -> Result<Arc<dyn transport::ClientFactory>, BoxError> {
        Ok(Arc::new(ClientFactory::new(
            self.tls.clone(),
            self.tor.clone(),
        )))
    }

    fn server_factory(&self, _args: &Args) -> Result<Arc<dyn transport::ServerFactory>, BoxError> {
        Err("unimplemented".into())
    }
}

pub struct ClientFactory {
    generators: servername::Holder,
    tls: Arc<dyn TlsConnector>,
    tor: TorControl,
}

impl ClientFactory {
    pub fn new(tls: Arc<dyn TlsConnector>, tor: TorControl) -> ClientFactory {
        ClientFactory {
            generators: servername::Holder::default(),
            tls,
            tor,
        }
    }

    /// PT `LOG` line for tor; addresses scrubbed unless `-unsafeLogging`
    /// (upstream logs the bridge host and its resolved address as-is).
    fn pt_log(&self, severity: LogSeverity, msg: &str) {
        self.tor.log(severity, &log::scrubbed(msg));
    }

    async fn dial_impl(&self, config: ClientConfig, dialer: &dyn Dialer) -> Result<Conn, String> {
        let tcp = dialer.dial(&config.remote_address).await.map_err(|e| {
            format!(
                "error dialing {}: {}",
                log::elide_addr(&config.remote_address),
                log::elide_error(&e)
            )
        })?;

        let mut server_name = String::new();
        let mut generator = None;
        if !config.tls_server_name.is_empty() {
            let g = self
                .generators
                .get(config.tls_server_name.trim())
                .map_err(|e| format!("error getting server name generator: {e}"))?;
            server_name = g.generate();
            generator = Some(g);
        }
        self.pt_log(
            LogSeverity::Notice,
            &format!("Using TLS SNI: {server_name}"),
        );

        let tls = if config.tls_kind == "tls" {
            let (verify, sni) = tls_checks(&config, &server_name)?;
            Some(self.tls.prepare(verify, sni.as_deref())?)
        } else {
            None
        };
        // From here on a failure means the current server name did not
        // work (upstream: the TLS handshake runs inside the upgrade).
        let upgraded = async {
            let stream = match tls {
                Some(handshake) => handshake.connect(tcp).await?,
                None => tcp,
            };
            upgrade::client(stream, &config.path, &config.http_host).await
        }
        .await;
        match upgraded {
            Ok(conn) => Ok(assemble(conn)),
            Err(e) => {
                if let Some(g) = generator {
                    g.reroll_if_unchanged(&server_name);
                }
                Err(e)
            }
        }
    }
}

impl transport::ClientFactory for ClientFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn parse_args(&self, args: &Args) -> Result<ClientArgs, BoxError> {
        match parse_client_args(args) {
            Ok(c) => Ok(Box::new(c)),
            Err(e) => {
                self.pt_log(LogSeverity::Error, &format!("Error parsing args: {e}"));
                Err(log::scrubbed(&e).into())
            }
        }
    }

    fn dial<'a>(
        &'a self,
        _target: &'a str,
        dialer: &'a dyn Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>> {
        Box::pin(async move {
            let config = args
                .downcast::<ClientConfig>()
                .map_err(|_| DialError::Other("invalid argument type for args".into()))?;
            match self.dial_impl(*config, dialer).await {
                Ok(conn) => Ok(conn),
                Err(e) => {
                    self.pt_log(LogSeverity::Error, &format!("Error dialing: {e}"));
                    Err(DialError::Other(log::scrubbed(&e).into()))
                }
            }
        })
    }
}

/// The tunnel: the upgraded stream, preceded by whatever arrived with the
/// reply head.
fn assemble(conn: Connection) -> Conn {
    let prefix = conn.rbuf;
    let stream: BoxStream = conn.stream;
    let (r, w) = stream.split();
    Conn {
        reader: Box::new(Prefixed::new(prefix, r)),
        writer: Box::new(Plain(w)),
    }
}

struct Prefixed<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> Prefixed<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Prefixed<R> {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin + Send> ReadHalf for Prefixed<R> {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if self.pos < self.prefix.len() {
                let n = buf.len().min(self.prefix.len() - self.pos);
                buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            self.inner.read(buf).await
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::shared::adapters::tcp::DirectDialer;
    use crate::shared::ports::transport::ClientFactory as _;
    use crate::transports::webtunnel::adapters::rustls::RustlsConnector;
    use crate::transports::webtunnel::domain::config::{ERR_TLS_NO_NAME, ERR_UTLS_NO_NAME};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    pub(crate) fn args(pairs: &[(&str, &str)]) -> Args {
        let mut a = Args::new();
        for (k, v) in pairs {
            a.add(k, v);
        }
        a
    }

    pub(crate) fn factory(tls: RustlsConnector) -> ClientFactory {
        ClientFactory::new(Arc::new(tls), TorControl::capture().0)
    }

    pub(crate) const UPGRADE_OK: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";

    /// A plain upgrade server: answers `reply` to any request, then echoes.
    pub(crate) async fn upgrade_server(reply: &'static [u8]) -> String {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = ln.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    s.write_all(reply).await.unwrap();
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    pub(crate) async fn dial(
        f: &ClientFactory,
        url: &str,
        addr: &str,
        extra: &[(&str, &str)],
    ) -> Result<Conn, String> {
        let mut all = vec![("url", url), ("addr", addr)];
        all.extend_from_slice(extra);
        let parsed = f.parse_args(&args(&all)).unwrap();
        f.dial("192.0.2.3:1", &DirectDialer, parsed)
            .await
            .map_err(|e| e.to_string())
    }

    pub(crate) async fn echo_check(mut conn: Conn, expect_prefix: &[u8]) {
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 13 % 251) as u8).collect();
        conn.writer.write_all(&payload).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < expect_prefix.len() + payload.len() {
            let n = conn.reader.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, [expect_prefix, &payload].concat());
        conn.writer.shutdown().await.unwrap();
        assert_eq!(conn.reader.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn plain_upgrade_round_trip() {
        // Bytes after the head belong to the tunnel and must not be lost.
        let addr = upgrade_server(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\nearly",
        )
        .await;
        let f = factory(RustlsConnector::new());
        let conn = dial(&f, "http://bridge.test/secret", &addr, &[])
            .await
            .unwrap();
        echo_check(conn, b"early").await;
    }

    #[tokio::test]
    async fn failures_reroll_only_after_the_dial() {
        let bad = upgrade_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        let f = factory(RustlsConnector::new());
        let spec = "a.test,b.test,c.test";
        let before = f.generators.get(spec).unwrap().generate();
        let err = dial(
            &f,
            "http://bridge.test/secret",
            &bad,
            &[("servername", spec)],
        )
        .await
        .err()
        .expect("dial must fail");
        assert_eq!(err, "unrecognized reply");
        let after = f.generators.get(spec).unwrap().generate();
        assert_ne!(before, after, "the failed name is rotated out");
        // A refused TCP connection does not touch the generator.
        let err = dial(
            &f,
            "http://bridge.test/secret",
            "127.0.0.1:1",
            &[("servername", spec)],
        )
        .await
        .err()
        .expect("dial must fail");
        assert!(err.starts_with("error dialing "), "{err}");
        assert_eq!(f.generators.get(spec).unwrap().generate(), after);
    }

    #[tokio::test]
    async fn config_errors_happen_before_tls() {
        let addr = upgrade_server(UPGRADE_OK).await;
        let f = factory(RustlsConnector::new());
        let err = |extra: &'static [(&'static str, &'static str)]| {
            let (f, addr) = (&f, &addr);
            async move {
                dial(f, "https://bridge.test/secret", addr, extra)
                    .await
                    .err()
                    .expect("dial must fail")
            }
        };
        assert_eq!(
            err(&[("utls", "nonsense")]).await,
            "invalid ClientHelloID: 'nonsense'"
        );
        assert!(err(&[("cert", "not base64!")])
            .await
            .starts_with("failed to decode approved certificate chain hash : "));
        assert_eq!(err(&[("servername", "")]).await, ERR_UTLS_NO_NAME);
        assert_eq!(
            err(&[("servername", ""), ("utls", "none")]).await,
            ERR_TLS_NO_NAME
        );
        assert_eq!(
            err(&[("servername", " , ")]).await,
            "error getting server name generator: invalid servername spec"
        );
    }

    #[tokio::test]
    async fn errors_and_sni_are_reported_to_tor() {
        let bad = upgrade_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        let (tor, lines) = TorControl::capture();
        let f = ClientFactory::new(Arc::new(RustlsConnector::new()), tor);
        assert!(f.parse_args(&args(&[("url", "ftp://x/")])).is_err());
        assert!(dial(&f, "http://bridge.test/secret", &bad, &[])
            .await
            .is_err());
        assert_eq!(
            *lines.lock().unwrap(),
            [
                "LOG SEVERITY=error MESSAGE=\"Error parsing args: url parse error: unknown scheme\"",
                "LOG SEVERITY=notice MESSAGE=\"Using TLS SNI: bridge.test\"",
                "LOG SEVERITY=error MESSAGE=\"Error dialing: unrecognized reply\"",
            ]
        );
    }
}
