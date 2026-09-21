// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Minimal HTTP/1.1 client (plain or rustls TLS) that writes requests the
//! way Go's `net/http` Transport does, for the transports that talk to
//! brokers and CDNs (snowflake rendezvous, meek_lite).
//!
//! Supported: one idle keep-alive connection per client, transparent gzip,
//! response-header timeout, domain fronting (dial/SNI one name, `Host:`
//! another), outbound proxy dialers. The message format itself lives in
//! `shared::domain::http`.

use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::shared::domain::http::{dial_addr, encode_request, Connection, Request, ResponseHead};
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::stream::{split_locked, BoxRead, BoxStream, BoxWrite, ByteStream};

impl ByteStream for TlsStream<BoxStream> {
    fn split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        split_locked(*self)
    }
}

/// TLS settings: webpki roots, TLS 1.2+, no ALPN (Go's HTTP/1.1-only
/// Transport sends none).
pub fn tls_config(send_sni: bool) -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("ring supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.enable_sni = send_sni;
    Arc::new(cfg)
}

/// Dials `url`'s host (TLS for https) through `dialer`.
pub async fn connect(
    url: &url::Url,
    dialer: &dyn Dialer,
    tls: &Arc<rustls::ClientConfig>,
) -> io::Result<Connection> {
    let addr = dial_addr(url)?;
    let tcp = tokio::time::timeout(Duration::from_secs(30), dialer.dial(&addr))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dial tcp {addr}: i/o timeout"),
            )
        })??;
    let stream: BoxStream = match url.scheme() {
        "http" => tcp,
        "https" => {
            let host = url.host_str().unwrap_or_default();
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let name = ServerName::try_from(host.to_string())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let tls = tokio::time::timeout(
                Duration::from_secs(10),
                TlsConnector::from(tls.clone()).connect(name, tcp),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "net/http: TLS handshake timeout")
            })??;
            Box::new(tls)
        }
        s => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported protocol scheme \"{s}\""),
            ))
        }
    };
    Ok(Connection::new(stream))
}

pub struct Response {
    pub head: ResponseHead,
    pub body: Vec<u8>,
    /// The body was cut at the read limit.
    pub truncated: bool,
}

/// A keep-alive client for one origin (one idle connection is pooled).
pub struct Client {
    dialer: Arc<dyn Dialer>,
    tls: Arc<rustls::ClientConfig>,
    header_timeout: Option<Duration>,
    idle: Mutex<Option<(String, Connection)>>,
}

impl Client {
    pub fn new(
        dialer: Arc<dyn Dialer>,
        tls: Arc<rustls::ClientConfig>,
        header_timeout: Option<Duration>,
    ) -> Client {
        Client {
            dialer,
            tls,
            header_timeout,
            idle: Mutex::new(None),
        }
    }

    /// Sends `req` to `url`'s host (the dial and SNI name) and reads the
    /// response, decoding at most `limit` body bytes (+1 to detect overflow).
    pub async fn round_trip(
        &self,
        url: &url::Url,
        req: &Request<'_>,
        limit: usize,
    ) -> io::Result<Response> {
        let key = format!("{}://{}", url.scheme(), dial_addr(url)?);
        let pooled = {
            let mut idle = self.idle.lock().unwrap();
            match idle.take() {
                Some((k, c)) if k == key => Some(c),
                _ => None,
            }
        };
        if let Some(mut conn) = pooled {
            if conn.still_open().await {
                match self.exchange(&mut conn, req, limit).await {
                    Ok((resp, reusable)) => {
                        self.put_idle(key, conn, reusable);
                        return Ok(resp);
                    }
                    // Server closed the idle connection: retry on a new one.
                    Err((false, _)) => {}
                    Err((true, e)) => return Err(e),
                }
            }
        }
        let mut conn = connect(url, &*self.dialer, &self.tls).await?;
        match self.exchange(&mut conn, req, limit).await {
            Ok((resp, reusable)) => {
                self.put_idle(key, conn, reusable);
                Ok(resp)
            }
            Err((_, e)) => Err(e),
        }
    }

    fn put_idle(&self, key: String, conn: Connection, reusable: bool) {
        if reusable && conn.rbuf.is_empty() {
            *self.idle.lock().unwrap() = Some((key, conn));
        }
    }

    /// Err((true, _)) once any response byte arrived.
    async fn exchange(
        &self,
        conn: &mut Connection,
        req: &Request<'_>,
        limit: usize,
    ) -> Result<(Response, bool), (bool, io::Error)> {
        let wire = encode_request(req);
        conn.stream.write_all(&wire).await.map_err(|e| (false, e))?;
        conn.stream.flush().await.map_err(|e| (false, e))?;
        let head = match self.header_timeout {
            Some(t) => match tokio::time::timeout(t, conn.read_head()).await {
                Ok(r) => r,
                Err(_) => {
                    return Err((
                        true,
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "net/http: timeout awaiting response headers",
                        ),
                    ))
                }
            },
            None => conn.read_head().await,
        };
        let head = head.map_err(|e| {
            (
                e.kind() != io::ErrorKind::UnexpectedEof || !conn.rbuf.is_empty(),
                e,
            )
        })?;
        let gz = req.gzip
            && head
                .header("Content-Encoding")
                .is_some_and(|v| v.eq_ignore_ascii_case("gzip"));
        let raw_limit = if gz { usize::MAX } else { limit + 1 };
        let (raw, reusable) = conn
            .read_body(&head, req.method, raw_limit)
            .await
            .map_err(|e| (true, e))?;
        let mut body = raw;
        if gz {
            let mut dec = flate2::read::GzDecoder::new(&body[..]).take(limit as u64 + 1);
            let mut out = Vec::new();
            dec.read_to_end(&mut out).map_err(|e| (true, e))?;
            body = out;
        }
        let truncated = body.len() > limit;
        body.truncate(limit);
        Ok((
            Response {
                head,
                body,
                truncated,
            },
            reusable && !truncated,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::adapters::tcp::DirectDialer;
    use crate::shared::domain::http::host_header;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Serves canned responses in order; `true` closes the connection after.
    async fn serve(responses: Vec<(Vec<u8>, bool)>) -> (url::Url, tokio::task::JoinHandle<usize>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = url::Url::parse(&format!("http://{}/", l.local_addr().unwrap())).unwrap();
        let h = tokio::spawn(async move {
            let mut accepted = 0;
            let mut responses = responses.into_iter().peekable();
            while responses.peek().is_some() {
                let (mut s, _) = l.accept().await.unwrap();
                accepted += 1;
                for (resp, close) in responses.by_ref() {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    assert!(buf[..n].ends_with(b"\r\n\r\n"));
                    s.write_all(&resp).await.unwrap();
                    if close {
                        break;
                    }
                }
            }
            accepted
        });
        (url, h)
    }

    fn get<'a>(host: &'a str) -> Request<'a> {
        Request {
            method: "GET",
            target: "/",
            host,
            headers: vec![],
            body: None,
            gzip: true,
        }
    }

    #[tokio::test]
    async fn keeps_alive_and_decodes_bodies() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, b"zipped").unwrap();
        let zipped = enc.finish().unwrap();
        let mut gz = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            zipped.len()
        )
        .into_bytes();
        gz.extend(zipped);
        let (url, server) = serve(vec![
            (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec(), false),
            (gz, true),
        ])
        .await;
        let c = Client::new(
            Arc::new(DirectDialer),
            tls_config(true),
            Some(Duration::from_secs(5)),
        );
        let host = host_header(&url);
        let r = c.round_trip(&url, &get(&host), 100).await.unwrap();
        assert_eq!(r.body, b"hello");
        let r = c.round_trip(&url, &get(&host), 100).await.unwrap();
        assert_eq!(r.body, b"abcde");
        let r = c.round_trip(&url, &get(&host), 100).await.unwrap();
        assert_eq!(r.body, b"zipped");
        assert_eq!(server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn limits_body_and_redials_after_close() {
        let (url, server) = serve(vec![
            (
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n0123456789".to_vec(),
                true,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
                true,
            ),
            (
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                true,
            ),
        ])
        .await;
        let c = Client::new(Arc::new(DirectDialer), tls_config(true), None);
        let host = host_header(&url);
        let r = c.round_trip(&url, &get(&host), 4).await.unwrap();
        assert_eq!((r.body.as_slice(), r.truncated), (&b"0123"[..], true));
        let r = c.round_trip(&url, &get(&host), 4).await.unwrap();
        assert_eq!(r.body, b"ok");
        // The pooled connection was closed by the server: redial silently.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let r = c.round_trip(&url, &get(&host), 4).await.unwrap();
        assert_eq!(r.head.status_text, "404 Not Found");
        assert_eq!(server.await.unwrap(), 3);
    }
}
