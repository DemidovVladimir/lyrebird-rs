// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 common/turbotunnel (client side).

//! A packet connection that survives its carrier: packets queue across
//! redials, and a lost snowflake is replaced by dialing a new one.

use std::io;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, watch};

use crate::transports::BoxFuture;

/// Written by the client at the start of every snowflake so the server can
/// recognise Turbo Tunnel sessions.
pub const TOKEN: [u8; 8] = [0x12, 0x93, 0x60, 0x5d, 0x27, 0x81, 0x75, 0xf5];
const QUEUE_SIZE: usize = 512;

pub type ClientId = [u8; 8];

pub fn new_client_id() -> ClientId {
    let mut id = [0u8; 8];
    crate::common::csrand::bytes(&mut id);
    id
}

/// One carrier connection (a single snowflake) carrying whole packets.
pub trait PacketCarrier: Send + Sync + 'static {
    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
    fn send<'a>(&'a self, pkt: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
    fn close(&self);
}

pub type DialFn =
    Box<dyn Fn() -> BoxFuture<'static, io::Result<Arc<dyn PacketCarrier>>> + Send + Sync>;

pub struct RedialPacketConn {
    recv_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    send_tx: mpsc::Sender<Vec<u8>>,
    closed: watch::Sender<bool>,
    err: Mutex<Option<String>>,
}

impl RedialPacketConn {
    pub fn new(dial: DialFn) -> Arc<RedialPacketConn> {
        let (recv_tx, recv_rx) = mpsc::channel(QUEUE_SIZE);
        let (send_tx, send_rx) = mpsc::channel(QUEUE_SIZE);
        let conn = Arc::new(RedialPacketConn {
            recv_rx: tokio::sync::Mutex::new(recv_rx),
            send_tx,
            closed: watch::channel(false).0,
            err: Mutex::new(None),
        });
        tokio::spawn(dial_loop(conn.clone(), dial, recv_tx, send_rx));
        conn
    }

    fn close_with_error(&self, err: Option<String>) -> bool {
        let first = self
            .closed
            .send_if_modified(|c| !std::mem::replace(c, true));
        if first {
            *self.err.lock().unwrap() =
                Some(err.unwrap_or_else(|| "operation on closed connection".into()));
        }
        first
    }

    fn error(&self) -> io::Error {
        let msg = self
            .err
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "operation on closed connection".into());
        io::Error::new(io::ErrorKind::BrokenPipe, msg)
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    async fn wait_closed(&self) {
        let mut rx = self.closed.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_closed() {
            return Err(self.error());
        }
        let mut rx = self.recv_rx.lock().await;
        tokio::select! {
            _ = self.wait_closed() => Err(self.error()),
            p = rx.recv() => match p {
                Some(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    Ok(n)
                }
                None => Err(self.error()),
            },
        }
    }

    /// Queues a packet; drops it if the queue is full (KCP retransmits).
    pub fn send(&self, pkt: &[u8]) -> io::Result<()> {
        if self.is_closed() {
            return Err(self.error());
        }
        let _ = self.send_tx.try_send(pkt.to_vec());
        Ok(())
    }

    pub fn close(&self) {
        self.close_with_error(None);
    }
}

async fn dial_loop(
    conn: Arc<RedialPacketConn>,
    dial: DialFn,
    recv_tx: mpsc::Sender<Vec<u8>>,
    send_rx: mpsc::Receiver<Vec<u8>>,
) {
    let send_rx = Arc::new(tokio::sync::Mutex::new(send_rx));
    loop {
        if conn.is_closed() {
            return;
        }
        let carrier = tokio::select! {
            c = dial() => c,
            _ = conn.wait_closed() => return,
        };
        let carrier = match carrier {
            Ok(c) => c,
            Err(e) => {
                conn.close_with_error(Some(e.to_string()));
                return;
            }
        };
        exchange(&conn, carrier.clone(), &recv_tx, send_rx.clone()).await;
        carrier.close();
    }
}

/// Pumps packets until the carrier fails in either direction or the
/// connection closes.
async fn exchange(
    conn: &Arc<RedialPacketConn>,
    carrier: Arc<dyn PacketCarrier>,
    recv_tx: &mpsc::Sender<Vec<u8>>,
    send_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
) {
    let reader = async {
        let mut buf = vec![0u8; 1500];
        loop {
            match carrier.recv(&mut buf).await {
                Ok(n) => {
                    // OK to drop packets.
                    let _ = recv_tx.try_send(buf[..n].to_vec());
                }
                Err(_) => return,
            }
        }
    };
    let writer = async {
        let mut rx = send_rx.lock().await;
        while let Some(p) = rx.recv().await {
            if carrier.send(&p).await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
        _ = conn.wait_closed() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Loops packets back, failing after `life` packets.
    struct Loopback {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        life: AtomicUsize,
    }

    impl PacketCarrier for Loopback {
        fn recv<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
            Box::pin(async move {
                let p = self
                    .rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or(io::ErrorKind::BrokenPipe)?;
                buf[..p.len()].copy_from_slice(&p);
                Ok(p.len())
            })
        }
        fn send<'a>(&'a self, pkt: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async move {
                if self.life.fetch_sub(1, Ordering::SeqCst) == 0 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                self.tx
                    .send(pkt.to_vec())
                    .map_err(|_| io::ErrorKind::BrokenPipe.into())
            })
        }
        fn close(&self) {}
    }

    #[tokio::test]
    async fn redials_after_carrier_failure() {
        let dials = Arc::new(AtomicUsize::new(0));
        let d = dials.clone();
        let conn = RedialPacketConn::new(Box::new(move || {
            d.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                let (tx, rx) = mpsc::unbounded_channel();
                Ok(Arc::new(Loopback {
                    tx,
                    rx: tokio::sync::Mutex::new(rx),
                    life: AtomicUsize::new(3),
                }) as Arc<dyn PacketCarrier>)
            })
        }));
        let mut buf = [0u8; 16];
        let mut got = 0;
        for i in 0..10u8 {
            conn.send(&[i]).unwrap();
            if let Ok(Ok(n)) =
                tokio::time::timeout(std::time::Duration::from_millis(200), conn.recv(&mut buf))
                    .await
            {
                assert_eq!(n, 1);
                got += 1;
            }
        }
        assert!(got >= 6, "only {got} packets looped back");
        assert!(dials.load(Ordering::SeqCst) >= 3);
        conn.close();
        assert!(conn.recv(&mut buf).await.is_err());
        assert!(conn.send(&[1]).is_err());
    }
}
