// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause

//! HTTP/1.1 messages the way Go's `net/http` writes and reads them:
//! request encoding, response heads and bodies over any byte stream. Used
//! by webtunnel's upgrade and by the HTTP client adapter.
//!
//! Supported: `Content-Length` and chunked bodies, 1xx interim responses,
//! a limit on header size.

use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::shared::ports::stream::BoxStream;

pub const GO_USER_AGENT: &str = "Go-http-client/1.1";
const MAX_HEADER_BYTES: usize = 1 << 20;

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

/// A buffered connection; `rbuf` holds bytes read past the last message.
pub struct Connection {
    pub stream: BoxStream,
    pub rbuf: Vec<u8>,
}

impl Connection {
    pub fn new(stream: BoxStream) -> Connection {
        Connection {
            stream,
            rbuf: Vec::new(),
        }
    }

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
    pub async fn still_open(&mut self) -> bool {
        let mut b = [0u8; 1];
        tokio::time::timeout(Duration::ZERO, self.stream.read(&mut b))
            .await
            .is_err()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn reads_bodies_over_any_stream() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::io::AsyncWriteExt::write_all(
            &mut server,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\nrest",
        )
        .await
        .unwrap();
        let mut conn = Connection::new(Box::new(client));
        let head = conn.read_head().await.unwrap();
        assert_eq!(head.status, 200);
        let (body, reusable) = conn.read_body(&head, "GET", 100).await.unwrap();
        assert_eq!((body.as_slice(), reusable), (&b"abcde"[..], true));
        assert_eq!(conn.rbuf, b"rest");
    }
}
