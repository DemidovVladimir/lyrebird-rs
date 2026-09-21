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

use crate::shared::domain::http::{encode_request, Connection, Request};
use crate::shared::ports::log;
use crate::shared::ports::BoxStream;

/// Sends the upgrade request and checks the reply the way upstream does.
/// On success the connection is the tunnel; bytes read past the head stay
/// in its buffer (upstream drops them with its `bufio.Reader`).
pub async fn client(stream: BoxStream, path: &str, host: &str) -> Result<Connection, String> {
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
    let mut conn = Connection::new(stream);
    let io = |e: std::io::Error| e.to_string();
    conn.stream
        .write_all(&encode_request(&req))
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
        let status = log::scrubbed(&head.status_text);
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

    /// Serves one in-memory connection: checks the request head, writes
    /// `reply`.
    fn serve(reply: &'static [u8]) -> BoxStream {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(
                &buf[..n],
                &b"GET /secret HTTP/1.1\r\nHost: bridge.test\r\nUser-Agent: Go-http-client/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"[..]
            );
            server.write_all(reply).await.unwrap();
            // Hold the pipe open until the client is done.
            let _ = server.read(&mut buf).await;
        });
        Box::new(client)
    }

    #[tokio::test]
    async fn upgrade_reply_check() {
        let stream = serve(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\ntunnel",
        );
        let conn = client(stream, "secret", "bridge.test").await.unwrap();
        assert_eq!(conn.rbuf, b"tunnel");

        for reply in [
            &b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"[..],
            b"HTTP/1.1 101 Switching Protocol\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, upgrade\r\n\r\n",
        ] {
            let err = client(serve(reply), "secret", "bridge.test")
                .await
                .err()
                .expect("must be refused");
            assert_eq!(err, "unrecognized reply");
        }
    }
}
