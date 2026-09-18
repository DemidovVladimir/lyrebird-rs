// Copyright (c) 2015 xtaci (kcp-go, MIT)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: MIT
//
// Port of the client side of kcp-go/v5 sess.go (`UDPSession`) without FEC
// or encryption, as Snowflake uses it.

//! A KCP byte stream over a packet connection.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify};

use super::kcp::Kcp;
use super::smux::MuxConn;
use super::turbotunnel::RedialPacketConn;
use crate::transports::BoxFuture;

const MTU_LIMIT: usize = 1500;

struct State {
    kcp: Kcp,
    /// Unread tail of a message larger than the caller's buffer.
    pending: Vec<u8>,
    write_delay: bool,
    ack_no_delay: bool,
}

pub struct KcpSession {
    state: Mutex<State>,
    pconn: Arc<RedialPacketConn>,
    read_event: Notify,
    write_event: Notify,
    die: watch::Sender<bool>,
    read_error: Mutex<Option<String>>,
    read_failed: watch::Sender<bool>,
}

impl KcpSession {
    /// `NewConn2` with a random conversation id.
    pub fn new(pconn: Arc<RedialPacketConn>) -> Arc<KcpSession> {
        let mut conv = [0u8; 4];
        crate::common::csrand::bytes(&mut conv);
        KcpSession::with_conv(u32::from_le_bytes(conv), pconn)
    }

    pub fn with_conv(conv: u32, pconn: Arc<RedialPacketConn>) -> Arc<KcpSession> {
        let s = Arc::new(KcpSession {
            state: Mutex::new(State {
                kcp: Kcp::new(conv),
                pending: Vec::new(),
                write_delay: false,
                ack_no_delay: false,
            }),
            pconn,
            read_event: Notify::new(),
            write_event: Notify::new(),
            die: watch::channel(false).0,
            read_error: Mutex::new(None),
            read_failed: watch::channel(false).0,
        });
        tokio::spawn(read_loop(s.clone()));
        tokio::spawn(update_loop(s.clone()));
        s
    }

    pub fn configure(&self, f: impl FnOnce(&mut Kcp)) {
        f(&mut self.state.lock().unwrap().kcp);
    }

    fn is_dead(&self) -> bool {
        *self.die.borrow()
    }

    async fn wait_dead(&self) {
        let mut rx = self.die.subscribe();
        let _ = rx.wait_for(|d| *d).await;
    }

    async fn wait_read_failed(&self) {
        let mut rx = self.read_failed.subscribe();
        let _ = rx.wait_for(|d| *d).await;
    }

    fn read_error(&self) -> io::Error {
        let msg = self.read_error.lock().unwrap().clone().unwrap_or_default();
        io::Error::new(io::ErrorKind::BrokenPipe, msg)
    }

    /// Sends whatever the last KCP call produced.
    fn transmit(&self, packets: Vec<Vec<u8>>) {
        for p in packets {
            if p.len() >= super::kcp::IKCP_OVERHEAD {
                let _ = self.pconn.send(&p);
            }
        }
    }

    pub async fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut st = self.state.lock().unwrap();
                if !st.pending.is_empty() {
                    let n = st.pending.len().min(b.len());
                    b[..n].copy_from_slice(&st.pending[..n]);
                    st.pending.drain(..n);
                    return Ok(n);
                }
                let size = st.kcp.peek_size();
                if size > 0 {
                    let size = size as usize;
                    if b.len() >= size {
                        st.kcp.recv(b);
                        let out = st.kcp.take_output();
                        drop(st);
                        self.transmit(out);
                        return Ok(size);
                    }
                    let mut msg = vec![0u8; size];
                    st.kcp.recv(&mut msg);
                    let n = b.len();
                    b.copy_from_slice(&msg[..n]);
                    st.pending = msg.split_off(n);
                    let out = st.kcp.take_output();
                    drop(st);
                    self.transmit(out);
                    return Ok(n);
                }
            }
            tokio::select! {
                _ = self.read_event.notified() => {}
                _ = self.wait_read_failed() => return Err(self.read_error()),
                _ = self.wait_dead() => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }

    pub async fn write_buffers(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        loop {
            if self.is_dead() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            {
                let mut guard = self.state.lock().unwrap();
                let st = &mut *guard;
                let kcp = &mut st.kcp;
                let waitsnd = kcp.wait_snd();
                if waitsnd < kcp.snd_wnd as usize && waitsnd < kcp.rmt_wnd as usize {
                    let mss = kcp.mss as usize;
                    let mut n = 0;
                    for b in bufs {
                        n += b.len();
                        for chunk in b.chunks(mss) {
                            kcp.send(chunk);
                        }
                    }
                    let waitsnd = kcp.wait_snd();
                    let flush = waitsnd >= kcp.snd_wnd as usize
                        || waitsnd >= kcp.rmt_wnd as usize
                        || !st.write_delay;
                    if flush {
                        kcp.flush(false);
                    }
                    let out = kcp.take_output();
                    drop(guard);
                    self.transmit(out);
                    return Ok(n);
                }
            }
            tokio::select! {
                _ = self.write_event.notified() => {}
                _ = self.wait_dead() => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }

    pub fn close(&self) {
        if self.die.send_if_modified(|d| !std::mem::replace(d, true)) {
            let out = {
                let mut st = self.state.lock().unwrap();
                st.kcp.flush(false);
                let out = st.kcp.take_output();
                st.kcp.release_tx();
                out
            };
            self.transmit(out);
        }
    }

    fn input(&self, data: &[u8]) {
        let out = {
            let mut st = self.state.lock().unwrap();
            let ack_no_delay = st.ack_no_delay;
            st.kcp.input(data, true, ack_no_delay);
            if st.kcp.peek_size() > 0 {
                self.read_event.notify_one();
            }
            let waitsnd = st.kcp.wait_snd();
            if waitsnd < st.kcp.snd_wnd as usize && waitsnd < st.kcp.rmt_wnd as usize {
                self.write_event.notify_one();
            }
            st.kcp.take_output()
        };
        self.transmit(out);
    }
}

async fn read_loop(s: Arc<KcpSession>) {
    let mut buf = vec![0u8; MTU_LIMIT];
    loop {
        let r = tokio::select! {
            r = s.pconn.recv(&mut buf) => r,
            _ = s.wait_dead() => return,
        };
        match r {
            Ok(n) if n >= super::kcp::IKCP_OVERHEAD => s.input(&buf[..n]),
            Ok(_) => {}
            Err(e) => {
                *s.read_error.lock().unwrap() = Some(e.to_string());
                s.read_failed.send_replace(true);
                return;
            }
        }
    }
}

async fn update_loop(s: Arc<KcpSession>) {
    loop {
        if s.is_dead() {
            return;
        }
        let (interval, out) = {
            let mut st = s.state.lock().unwrap();
            let interval = st.kcp.flush(false);
            let waitsnd = st.kcp.wait_snd();
            if waitsnd < st.kcp.snd_wnd as usize && waitsnd < st.kcp.rmt_wnd as usize {
                s.write_event.notify_one();
            }
            (interval, st.kcp.take_output())
        };
        s.transmit(out);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(interval as u64)) => {}
            _ = s.wait_dead() => return,
        }
    }
}

impl MuxConn for KcpSession {
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(KcpSession::read(self, buf))
    }

    fn write_all_vectored<'a>(&'a self, bufs: &'a [&'a [u8]]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move { self.write_buffers(bufs).await.map(|_| ()) })
    }

    fn close(&self) {
        KcpSession::close(self);
    }
}

#[cfg(test)]
mod tests {
    use super::super::smux::{Config, Session};
    use super::super::turbotunnel::PacketCarrier;
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::mpsc;

    /// One direction-pair of a lossy in-memory link.
    struct Lossy {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        counter: AtomicU64,
        drop_every: u64,
    }

    impl PacketCarrier for Lossy {
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
                let c = self.counter.fetch_add(1, Ordering::SeqCst);
                if self.drop_every == 0 || c % self.drop_every != 0 {
                    let _ = self.tx.send(pkt.to_vec());
                }
                Ok(())
            })
        }
        fn close(&self) {}
    }

    fn link(drop_every: u64) -> (Arc<RedialPacketConn>, Arc<RedialPacketConn>) {
        let (atx, arx) = mpsc::unbounded_channel();
        let (btx, brx) = mpsc::unbounded_channel();
        let a: Arc<dyn PacketCarrier> = Arc::new(Lossy {
            tx: atx,
            rx: tokio::sync::Mutex::new(brx),
            counter: AtomicU64::new(1),
            drop_every,
        });
        let b: Arc<dyn PacketCarrier> = Arc::new(Lossy {
            tx: btx,
            rx: tokio::sync::Mutex::new(arx),
            counter: AtomicU64::new(1),
            drop_every,
        });
        let once = |c: Arc<dyn PacketCarrier>| {
            let slot = Mutex::new(Some(c));
            RedialPacketConn::new(Box::new(move || {
                let c = slot.lock().unwrap().take();
                Box::pin(async move {
                    match c {
                        Some(c) => Ok(c),
                        None => std::future::pending().await,
                    }
                })
            }))
        };
        (once(a), once(b))
    }

    fn tune(s: &KcpSession) {
        s.configure(|k| {
            k.set_stream(true);
            k.wnd_size(65535, 65535);
            k.nodelay(0, 0, 0, 1);
        });
    }

    async fn run(drop_every: u64) {
        let (pa, pb) = link(drop_every);
        let a = KcpSession::with_conv(7, pa);
        let b = KcpSession::with_conv(7, pb);
        tune(&a);
        tune(&b);
        let cfg = Config {
            version: 2,
            max_stream_buffer: 1 << 20,
            keepalive_timeout: Duration::from_secs(600),
            ..Config::default()
        };
        let client = Session::client(a, cfg.clone()).unwrap();
        let server = Session::server(b, cfg).unwrap();
        let cs = client.open_stream().await.unwrap();
        let ss = server.accept_stream().await.unwrap();
        let data: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
        let expect = data.clone();
        tokio::spawn(async move {
            cs.write(&data).await.unwrap();
            cs.close().await.unwrap();
        });
        let mut got = Vec::new();
        let mut buf = vec![0u8; 16384];
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let n = ss.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("transfer timed out");
        assert!(got == expect, "got {} of {} bytes", got.len(), expect.len());
    }

    #[tokio::test]
    async fn smux_over_kcp_lossless() {
        run(0).await;
    }

    #[tokio::test]
    async fn smux_over_kcp_with_loss() {
        run(9).await;
    }
}
