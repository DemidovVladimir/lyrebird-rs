// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of lyrebird cmd/lyrebird copyLoop.

//! Relaying bytes between tor and a transport connection.

use std::time::Duration;

use crate::shared::ports::transport::{Conn, ReadHalf, WriteHalf};

/// Upstream copies with io.Copy's 32 KiB buffer.
const COPY_BUFFER: usize = 32 * 1024;

async fn copy(from: &mut dyn ReadHalf, to: &mut dyn WriteHalf) -> std::io::Result<()> {
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
    }
}

/// Both directions run until they end on their own (no half-close is
/// propagated), then both connections close — as upstream's copyLoop and
/// the deferred Close() calls (for a TLS transport, the close_notify).
pub async fn copy_loop(a: Conn, b: Conn) -> std::io::Result<()> {
    let Conn {
        reader: mut ar,
        writer: mut aw,
    } = a;
    let Conn {
        reader: mut br,
        writer: mut bw,
    } = b;
    let (r1, r2) = tokio::join!(
        copy(ar.as_mut(), bw.as_mut()),
        copy(br.as_mut(), aw.as_mut())
    );
    for w in [aw.as_mut(), bw.as_mut()] {
        let _ = tokio::time::timeout(Duration::from_secs(1), w.shutdown()).await;
    }
    r1.and(r2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::ports::stream::BoxStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relays_both_ways_until_both_end() {
        let (a, mut tor) = tokio::io::duplex(1024);
        let (b, mut bridge) = tokio::io::duplex(1024);
        let relay = tokio::spawn(copy_loop(
            Conn::from_stream(Box::new(a) as BoxStream),
            Conn::from_stream(Box::new(b) as BoxStream),
        ));
        tor.write_all(b"to bridge").await.unwrap();
        bridge.write_all(b"to tor").await.unwrap();
        let mut buf = [0u8; 9];
        bridge.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"to bridge");
        tor.read_exact(&mut buf[..6]).await.unwrap();
        assert_eq!(&buf[..6], b"to tor");
        drop(tor);
        drop(bridge);
        relay.await.unwrap().unwrap();
    }
}
