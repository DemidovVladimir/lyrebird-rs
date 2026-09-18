// Copyright (c) 2022 The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: MIT
//
// Port of webtunnel transport/httpupgrade/httpupgrade.go (client side).

//! The HTTP upgrade that turns a (TLS) connection into a raw tunnel: one
//! `GET` with `Connection: upgrade` and `Upgrade: websocket`, answered by
//! `101 Switching Protocols`. No WebSocket framing follows; the bytes after
//! the reply head are the tunnel.

use tokio::io::AsyncWriteExt;

use crate::common::httpc::{self, Connection, Request, Stream};
use crate::log;

/// Sends the upgrade request and checks the reply the way upstream does.
/// On success the connection is the tunnel; bytes read past the head stay
/// in its buffer (upstream drops them with its `bufio.Reader`).
pub async fn client(stream: Stream, path: &str, host: &str) -> Result<Connection, String> {
    let target = format!("/{path}");
    let req = Request {
        method: "GET",
        target: &target,
        host,
        headers: vec![
            ("Connection".into(), "upgrade".into()),
            ("Upgrade".into(), "websocket".into()),
        ],
        body: None,
        gzip: false,
    };
    let mut conn = Connection {
        stream,
        rbuf: Vec::new(),
    };
    let io = |e: std::io::Error| e.to_string();
    conn.stream
        .write_all(&httpc::encode_request(&req))
        .await
        .map_err(io)?;
    conn.stream.flush().await.map_err(io)?;
    let head = conn.read_head().await.map_err(io)?;
    let has = |name: &str, want: &str| {
        head.header(name)
            .is_some_and(|v| v.eq_ignore_ascii_case(want))
    };
    if head.status_text != "101 Switching Protocols"
        || !has("Upgrade", "websocket")
        || !has("Connection", "upgrade")
    {
        // Upstream says only "unrecognized reply"; the status line tells a
        // 502 from the bridge's reverse proxy apart from a blocked URL.
        let status = if log::unsafe_logging() {
            head.status_text.clone()
        } else {
            log::scrub(&head.status_text)
        };
        log::debug(&format!(
            "webtunnel: unrecognized upgrade reply: HTTP status {status:?}"
        ));
        return Err("unrecognized reply".into());
    }
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Serves one connection: checks the request head, writes `reply`.
    async fn serve(reply: &'static [u8]) -> String {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(
                &buf[..n],
                &b"GET /secret HTTP/1.1\r\nHost: bridge.test\r\nUser-Agent: Go-http-client/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"[..]
            );
            s.write_all(reply).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn upgrade_reply_check() {
        let addr = serve(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\ntunnel",
        )
        .await;
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let conn = client(Stream::Plain(tcp), "secret", "bridge.test")
            .await
            .unwrap();
        assert_eq!(conn.rbuf, b"tunnel");

        for reply in [
            &b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"[..],
            b"HTTP/1.1 101 Switching Protocol\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, upgrade\r\n\r\n",
        ] {
            let addr = serve(reply).await;
            let tcp = TcpStream::connect(&addr).await.unwrap();
            let err = client(Stream::Plain(tcp), "secret", "bridge.test")
                .await
                .err()
                .expect("must be refused");
            assert_eq!(err, "unrecognized reply");
        }
    }
}
