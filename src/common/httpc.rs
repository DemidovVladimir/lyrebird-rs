// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! Minimal HTTP/1.1 client (plain or rustls TLS) that writes requests the
//! way Go's `net/http` Transport does, for the transports that talk to
//! brokers and CDNs (snowflake rendezvous, meek_lite, webtunnel).
//!
//! Supported: one idle keep-alive connection per client, `Content-Length`
//! and chunked bodies, transparent gzip, response-header timeout, domain
//! fronting (dial/SNI one name, `Host:` another), outbound proxy dialers.

use std::io::{self, Read};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::proxy::Dialer;

pub const GO_USER_AGENT: &str = "Go-http-client/1.1";
const MAX_HEADER_BYTES: usize = 1 << 20;

pub enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A buffered connection; `rbuf` holds bytes read past the last message.
pub struct Connection {
    pub stream: Stream,
    pub rbuf: Vec<u8>,
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

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Host and port of `url` for dialing ("host:port", IPv6 bracketed).
pub fn dial_addr(url: &url::Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL has no port"))?;
    Ok(format!("{host}:{port}"))
}

/// `Host:` header value for `url` (Go keeps a non-default port).
pub fn host_header(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

/// Dials `url`'s host (TLS for https) through `dialer`.
pub async fn connect(
    url: &url::Url,
    dialer: &Dialer,
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
    let stream = match url.scheme() {
        "http" => Stream::Plain(tcp),
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
            Stream::Tls(Box::new(tls))
        }
        s => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported protocol scheme \"{s}\""),
            ))
        }
    };
    Ok(Connection {
        stream,
        rbuf: Vec::new(),
    })
}

pub struct Request<'a> {
    pub method: &'a str,
    /// Request target (path and query), e.g. `/client`.
    pub target: &'a str,
    pub host: &'a str,
    /// Extra headers, written in order after the standard ones.
    pub headers: Vec<(String, String)>,
    pub body: Option<&'a [u8]>,
    /// Advertise and transparently decode gzip.
    pub gzip: bool,
}

/// Serializes `req` like Go's `Request.write` (+ Transport extra headers).
pub fn encode_request(req: &Request<'_>) -> Vec<u8> {
    let ua = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map_or(GO_USER_AGENT, |(_, v)| v.as_str());
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        req.method, req.target, req.host
    );
    if !ua.is_empty() {
        head.push_str(&format!("User-Agent: {ua}\r\n"));
    }
    if let Some(body) = req.body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    let mut headers: Vec<_> = req
        .headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("user-agent"))
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if req.gzip {
        head.push_str("Accept-Encoding: gzip\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    if let Some(body) = req.body {
        out.extend_from_slice(body);
    }
    out
}

#[derive(Debug)]
pub struct ResponseHead {
    pub version_minor: u8,
    pub status: u16,
    /// `"200 OK"`, as Go's `Response.Status`.
    pub status_text: String,
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }
}

pub fn parse_head(raw: &[u8]) -> io::Result<ResponseHead> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid("malformed HTTP response"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let (proto, rest) = status_line
        .split_once(' ')
        .ok_or_else(|| invalid(format!("malformed HTTP response {status_line:?}")))?;
    let version_minor = match proto {
        "HTTP/1.1" => 1,
        "HTTP/1.0" => 0,
        _ => return Err(invalid(format!("malformed HTTP version {proto:?}"))),
    };
    let rest = rest.trim_start();
    let code = rest.split(' ').next().unwrap_or_default();
    let status: u16 = code
        .parse()
        .ok()
        .filter(|_| code.len() == 3)
        .ok_or_else(|| invalid(format!("malformed HTTP status code {code:?}")))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| invalid(format!("malformed MIME header line: {line}")))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok(ResponseHead {
        version_minor,
        status,
        status_text: rest.to_string(),
        headers,
    })
}

impl Connection {
    async fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 8192];
        let n = self.stream.read(&mut tmp).await?;
        self.rbuf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// Reads a response head, skipping 1xx interim responses (except 101).
    pub async fn read_head(&mut self) -> io::Result<ResponseHead> {
        loop {
            let end = loop {
                if let Some(i) = find(&self.rbuf, b"\r\n\r\n") {
                    break i + 4;
                }
                if self.rbuf.len() > MAX_HEADER_BYTES {
                    return Err(invalid("server response headers exceeded limit"));
                }
                if self.fill().await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ));
                }
            };
            let raw: Vec<u8> = self.rbuf.drain(..end).collect();
            let head = parse_head(&raw[..raw.len() - 4])?;
            if (100..200).contains(&head.status) && head.status != 101 {
                continue;
            }
            return Ok(head);
        }
    }

    async fn read_exact_buf(
        &mut self,
        n: usize,
        limit: usize,
        out: &mut Vec<u8>,
    ) -> io::Result<bool> {
        let mut need = n;
        while need > 0 {
            if self.rbuf.is_empty() && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
            let take = need.min(self.rbuf.len());
            let room = limit.saturating_sub(out.len());
            out.extend_from_slice(&self.rbuf[..take.min(room)]);
            self.rbuf.drain(..take);
            need -= take;
            if out.len() >= limit {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn read_line(&mut self) -> io::Result<String> {
        loop {
            if let Some(i) = find(&self.rbuf, b"\r\n") {
                let line: Vec<u8> = self.rbuf.drain(..i + 2).collect();
                return String::from_utf8(line[..i].to_vec())
                    .map_err(|_| invalid("malformed chunked encoding"));
            }
            if self.rbuf.len() > 4096 {
                return Err(invalid("malformed chunked encoding"));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
        }
    }

    /// Reads a response body of at most `limit` bytes (raw, before gzip).
    /// Returns the body and whether the connection may be reused.
    pub async fn read_body(
        &mut self,
        head: &ResponseHead,
        method: &str,
        limit: usize,
    ) -> io::Result<(Vec<u8>, bool)> {
        let mut body = Vec::new();
        let mut reusable = head.version_minor == 1 && !head.has_token("Connection", "close");
        if method == "HEAD" || head.status == 204 || head.status == 304 {
            return Ok((body, reusable));
        }
        if head.has_token("Transfer-Encoding", "chunked") {
            loop {
                let line = self.read_line().await?;
                let size = line.split(';').next().unwrap_or_default().trim();
                let size = usize::from_str_radix(size, 16)
                    .map_err(|_| invalid("invalid byte in chunk length"))?;
                if size == 0 {
                    while !self.read_line().await?.is_empty() {}
                    return Ok((body, reusable));
                }
                if !self.read_exact_buf(size, limit, &mut body).await? {
                    return Ok((body, false));
                }
                if !self.read_line().await?.is_empty() {
                    return Err(invalid("malformed chunked encoding"));
                }
            }
        }
        if let Some(cl) = head.header("Content-Length") {
            let n: usize = cl
                .parse()
                .map_err(|_| invalid(format!("bad Content-Length {cl:?}")))?;
            let complete = self.read_exact_buf(n, limit, &mut body).await?;
            return Ok((body, reusable && complete));
        }
        reusable = false;
        loop {
            let take = self.rbuf.len().min(limit - body.len());
            body.extend(self.rbuf.drain(..take));
            if body.len() >= limit || self.fill().await? == 0 {
                body.extend(self.rbuf.drain(..self.rbuf.len().min(limit - body.len())));
                return Ok((body, reusable));
            }
        }
    }

    /// True if the idle connection has not been closed by the peer.
    async fn still_open(&mut self) -> bool {
        let mut b = [0u8; 1];
        tokio::time::timeout(Duration::ZERO, self.stream.read(&mut b))
            .await
            .is_err()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub struct Response {
    pub head: ResponseHead,
    pub body: Vec<u8>,
    /// The body was cut at the read limit.
    pub truncated: bool,
}

/// A keep-alive client for one origin (one idle connection is pooled).
pub struct Client {
    dialer: Dialer,
    tls: Arc<rustls::ClientConfig>,
    header_timeout: Option<Duration>,
    idle: Mutex<Option<(String, Connection)>>,
}

impl Client {
    pub fn new(
        dialer: Dialer,
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
        let mut conn = connect(url, &self.dialer, &self.tls).await?;
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
    use tokio::net::TcpListener;

    #[test]
    fn encodes_like_go() {
        let req = Request {
            method: "POST",
            target: "/client",
            host: "broker.example",
            headers: vec![],
            body: Some(b"abc"),
            gzip: true,
        };
        assert_eq!(
            String::from_utf8(encode_request(&req)).unwrap(),
            "POST /client HTTP/1.1\r\nHost: broker.example\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 3\r\nAccept-Encoding: gzip\r\n\r\nabc"
        );
    }

    #[test]
    fn parses_head() {
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A:  b ").unwrap();
        assert_eq!((h.status, h.status_text.as_str()), (200, "200 OK"));
        assert_eq!(h.header("content-length"), Some("5"));
        assert_eq!(h.header("x-a"), Some("b"));
        assert!(parse_head(b"HTTP/2 200 OK").is_err());
    }

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
            Dialer::Direct,
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
        let c = Client::new(Dialer::Direct, tls_config(true), None);
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
