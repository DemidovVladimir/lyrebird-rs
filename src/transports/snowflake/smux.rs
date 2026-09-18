// Copyright (c) 2016-2017 xtaci (smux, MIT)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: MIT
//
// Port of github.com/xtaci/smux v1.5.34 (protocol versions 1 and 2).

//! Stream multiplexing over a reliable byte stream.
//!
//! Frame: `ver:u8 | cmd:u8 | length:u16le | sid:u32le | data`. Version 2
//! adds per-stream flow control (`UPD`: consumed, window).

use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, Notify};

use crate::transports::BoxFuture;

const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;
const HEADER_SIZE: usize = 8;
const UPD_SIZE: usize = 8;
const INITIAL_PEER_WINDOW: u32 = 262144;
const ACCEPT_BACKLOG: usize = 1024;
const OPEN_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Config {
    pub version: u8,
    pub keepalive_disabled: bool,
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
    pub max_frame_size: usize,
    pub max_receive_buffer: usize,
    pub max_stream_buffer: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            version: 1,
            keepalive_disabled: false,
            keepalive_interval: Duration::from_secs(10),
            keepalive_timeout: Duration::from_secs(30),
            max_frame_size: 32768,
            max_receive_buffer: 4194304,
            max_stream_buffer: 65536,
        }
    }
}

impl Config {
    pub fn verify(&self) -> Result<(), String> {
        if !(self.version == 1 || self.version == 2) {
            return Err("unsupported protocol version".into());
        }
        if !self.keepalive_disabled {
            if self.keepalive_interval.is_zero() {
                return Err("keep-alive interval must be positive".into());
            }
            if self.keepalive_timeout < self.keepalive_interval {
                return Err("keep-alive timeout must be larger than keep-alive interval".into());
            }
        }
        if self.max_frame_size == 0 || self.max_frame_size > 65535 {
            return Err("max frame size must be in 1..=65535".into());
        }
        if self.max_receive_buffer == 0 || self.max_stream_buffer == 0 {
            return Err("buffers must be positive".into());
        }
        if self.max_stream_buffer > self.max_receive_buffer {
            return Err("max stream buffer must not be larger than max receive buffer".into());
        }
        if self.max_stream_buffer > i32::MAX as usize {
            return Err("max stream buffer cannot be larger than 2147483647".into());
        }
        Ok(())
    }
}

/// The reliable byte stream a session runs on. Reads and writes may run
/// concurrently.
pub trait MuxConn: Send + Sync + 'static {
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
    /// Writes all buffers as one unit.
    fn write_all_vectored<'a>(&'a self, bufs: &'a [&'a [u8]]) -> BoxFuture<'a, io::Result<()>>;
    fn close(&self);
}

async fn read_full(conn: &dyn MuxConn, buf: &mut [u8]) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        let r = conn.read(&mut buf[n..]).await?;
        if r == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        n += r;
    }
    Ok(())
}

/// A latching flag that can be awaited.
struct Latch(watch::Sender<bool>);

impl Latch {
    fn new() -> Latch {
        Latch(watch::channel(false).0)
    }

    fn set(&self) -> bool {
        self.0.send_if_modified(|v| !std::mem::replace(v, true))
    }

    fn is_set(&self) -> bool {
        *self.0.borrow()
    }

    async fn wait(&self) {
        let mut rx = self.0.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }
}

/// A latch carrying the first error.
struct ErrLatch {
    latch: Latch,
    err: Mutex<Option<(io::ErrorKind, String)>>,
}

impl ErrLatch {
    fn new() -> ErrLatch {
        ErrLatch {
            latch: Latch::new(),
            err: Mutex::new(None),
        }
    }

    fn set(&self, e: &io::Error) {
        let mut slot = self.err.lock().unwrap();
        if slot.is_none() {
            *slot = Some((e.kind(), e.to_string()));
            drop(slot);
            self.latch.set();
        }
    }

    fn error(&self) -> io::Error {
        match &*self.err.lock().unwrap() {
            Some((kind, msg)) => io::Error::new(*kind, msg.clone()),
            None => io::ErrorKind::Other.into(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    Ctrl = 0,
    Data = 1,
}

struct WriteRequest {
    class: Class,
    seq: u32,
    ver: u8,
    cmd: u8,
    sid: u32,
    data: Vec<u8>,
    result: oneshot::Sender<io::Result<usize>>,
}

impl PartialEq for WriteRequest {
    fn eq(&self, o: &Self) -> bool {
        self.class == o.class && self.seq == o.seq
    }
}
impl Eq for WriteRequest {}
impl PartialOrd for WriteRequest {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for WriteRequest {
    /// Max-heap order: control before data, then lower sequence first.
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        o.class
            .cmp(&self.class)
            .then_with(|| (o.seq.wrapping_sub(self.seq) as i32).cmp(&0))
    }
}

struct SessionInner {
    config: Config,
    conn: Arc<dyn MuxConn>,
    next_stream_id: Mutex<(u32, bool)>,
    bucket: AtomicI32,
    bucket_notify: Notify,
    streams: Mutex<HashMap<u32, Arc<StreamInner>>>,
    die: Latch,
    read_error: ErrLatch,
    write_error: ErrLatch,
    proto_error: ErrLatch,
    accepts_tx: mpsc::Sender<Arc<StreamInner>>,
    accepts_rx: tokio::sync::Mutex<mpsc::Receiver<Arc<StreamInner>>>,
    data_ready: AtomicBool,
    request_id: AtomicU32,
    writes: mpsc::UnboundedSender<WriteRequest>,
}

#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

impl Session {
    pub fn client(conn: Arc<dyn MuxConn>, config: Config) -> Result<Session, String> {
        Session::new(conn, config, true)
    }

    pub fn server(conn: Arc<dyn MuxConn>, config: Config) -> Result<Session, String> {
        Session::new(conn, config, false)
    }

    fn new(conn: Arc<dyn MuxConn>, config: Config, client: bool) -> Result<Session, String> {
        config.verify()?;
        let (accepts_tx, accepts_rx) = mpsc::channel(ACCEPT_BACKLOG);
        let (writes_tx, writes_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(SessionInner {
            bucket: AtomicI32::new(config.max_receive_buffer as i32),
            config,
            conn,
            next_stream_id: Mutex::new((if client { 1 } else { 0 }, false)),
            bucket_notify: Notify::new(),
            streams: Mutex::new(HashMap::new()),
            die: Latch::new(),
            read_error: ErrLatch::new(),
            write_error: ErrLatch::new(),
            proto_error: ErrLatch::new(),
            accepts_tx,
            accepts_rx: tokio::sync::Mutex::new(accepts_rx),
            data_ready: AtomicBool::new(false),
            request_id: AtomicU32::new(0),
            writes: writes_tx,
        });
        tokio::spawn(send_loop(inner.clone(), writes_rx));
        tokio::spawn(recv_loop(inner.clone()));
        if !inner.config.keepalive_disabled {
            tokio::spawn(keepalive(inner.clone()));
        }
        Ok(Session { inner })
    }

    pub async fn open_stream(&self) -> io::Result<Stream> {
        let s = &self.inner;
        if s.die.is_set() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let sid = {
            let mut next = s.next_stream_id.lock().unwrap();
            if next.1 {
                return Err(io::Error::other(
                    "stream id overflows, should start a new connection",
                ));
            }
            next.0 = next.0.wrapping_add(2);
            if next.0 == next.0 % 2 {
                next.1 = true;
                return Err(io::Error::other(
                    "stream id overflows, should start a new connection",
                ));
            }
            next.0
        };
        let stream = StreamInner::new(sid, s.config.max_frame_size);
        write_frame(
            s,
            Class::Ctrl,
            CMD_SYN,
            sid,
            Vec::new(),
            Some(OPEN_CLOSE_TIMEOUT),
        )
        .await?;
        if s.read_error.latch.is_set() {
            return Err(s.read_error.error());
        }
        if s.write_error.latch.is_set() {
            return Err(s.write_error.error());
        }
        if s.die.is_set() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        s.streams.lock().unwrap().insert(sid, stream.clone());
        Ok(Stream {
            inner: stream,
            sess: s.clone(),
        })
    }

    pub async fn accept_stream(&self) -> io::Result<Stream> {
        let s = &self.inner;
        let mut rx = s.accepts_rx.lock().await;
        tokio::select! {
            st = rx.recv() => match st {
                Some(st) => Ok(Stream { inner: st, sess: s.clone() }),
                None => Err(io::ErrorKind::BrokenPipe.into()),
            },
            _ = s.read_error.latch.wait() => Err(s.read_error.error()),
            _ = s.proto_error.latch.wait() => Err(s.proto_error.error()),
            _ = s.die.wait() => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    pub fn close(&self) {
        close_session(&self.inner);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.die.is_set()
    }

    pub fn num_streams(&self) -> usize {
        if self.is_closed() {
            return 0;
        }
        self.inner.streams.lock().unwrap().len()
    }

    pub async fn closed(&self) {
        self.inner.die.wait().await
    }
}

fn close_session(s: &Arc<SessionInner>) {
    if s.die.set() {
        for st in s.streams.lock().unwrap().values() {
            st.die.set();
            st.read_event.notify_one();
        }
        s.conn.close();
    }
}

fn notify_bucket(s: &SessionInner) {
    s.bucket_notify.notify_one();
}

fn return_tokens(s: &SessionInner, n: usize) {
    if s.bucket.fetch_add(n as i32, Ordering::SeqCst) + n as i32 > 0 {
        notify_bucket(s);
    }
}

fn stream_closed(s: &SessionInner, sid: u32) {
    let mut streams = s.streams.lock().unwrap();
    if let Some(st) = streams.remove(&sid) {
        let n = st.recycle_tokens();
        if n > 0 {
            return_tokens(s, n);
        }
    }
}

async fn write_frame(
    s: &Arc<SessionInner>,
    class: Class,
    cmd: u8,
    sid: u32,
    data: Vec<u8>,
    timeout: Option<Duration>,
) -> io::Result<usize> {
    let (tx, rx) = oneshot::channel();
    let req = WriteRequest {
        class,
        seq: s.request_id.fetch_add(1, Ordering::SeqCst).wrapping_add(1),
        ver: s.config.version,
        cmd,
        sid,
        data,
        result: tx,
    };
    if s.die.is_set() {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    if s.write_error.latch.is_set() {
        return Err(s.write_error.error());
    }
    if s.writes.send(req).is_err() {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    let wait = async {
        tokio::select! {
            r = rx => r.unwrap_or_else(|_| Err(io::ErrorKind::BrokenPipe.into())),
            _ = s.die.wait() => Err(io::ErrorKind::BrokenPipe.into()),
            _ = s.write_error.latch.wait() => Err(s.write_error.error()),
        }
    };
    match timeout {
        Some(t) => tokio::time::timeout(t, wait)
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into())),
        None => wait.await,
    }
}

async fn send_loop(s: Arc<SessionInner>, mut rx: mpsc::UnboundedReceiver<WriteRequest>) {
    let mut heap: BinaryHeap<WriteRequest> = BinaryHeap::new();
    loop {
        if heap.is_empty() {
            tokio::select! {
                r = rx.recv() => match r {
                    Some(r) => heap.push(r),
                    None => return,
                },
                _ = s.die.wait() => return,
            }
        }
        // Gather everything queued so control frames can jump ahead.
        while let Ok(r) = rx.try_recv() {
            heap.push(r);
        }
        let req = heap.pop().unwrap();
        let mut header = [0u8; HEADER_SIZE];
        header[0] = req.ver;
        header[1] = req.cmd;
        header[2..4].copy_from_slice(&(req.data.len() as u16).to_le_bytes());
        header[4..8].copy_from_slice(&req.sid.to_le_bytes());
        let bufs: [&[u8]; 2] = [&header, &req.data];
        let res = tokio::select! {
            r = s.conn.write_all_vectored(&bufs) => r,
            _ = s.die.wait() => return,
        };
        match res {
            Ok(()) => {
                let _ = req.result.send(Ok(req.data.len()));
            }
            Err(e) => {
                s.write_error.set(&e);
                let _ = req.result.send(Err(e));
                return;
            }
        }
    }
}

async fn recv_loop(s: Arc<SessionInner>) {
    let conn = s.conn.clone();
    let mut hdr = [0u8; HEADER_SIZE];
    loop {
        while s.bucket.load(Ordering::SeqCst) <= 0 && !s.die.is_set() {
            tokio::select! {
                _ = s.bucket_notify.notified() => {}
                _ = s.die.wait() => return,
            }
        }
        let res = tokio::select! {
            r = read_full(conn.as_ref(), &mut hdr) => r,
            _ = s.die.wait() => return,
        };
        if let Err(e) = res {
            s.read_error.set(&e);
            return;
        }
        s.data_ready.store(true, Ordering::SeqCst);
        if hdr[0] != s.config.version {
            s.proto_error.set(&io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid protocol",
            ));
            return;
        }
        let length = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
        let sid = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        match hdr[1] {
            CMD_NOP => {}
            CMD_SYN => {
                let new = {
                    let mut streams = s.streams.lock().unwrap();
                    match streams.entry(sid) {
                        std::collections::hash_map::Entry::Occupied(_) => None,
                        std::collections::hash_map::Entry::Vacant(v) => {
                            let st = StreamInner::new(sid, s.config.max_frame_size);
                            v.insert(st.clone());
                            Some(st)
                        }
                    }
                };
                if let Some(st) = new {
                    tokio::select! {
                        _ = s.accepts_tx.send(st) => {}
                        _ = s.die.wait() => {}
                    }
                }
            }
            CMD_FIN => {
                if let Some(st) = s.streams.lock().unwrap().get(&sid) {
                    st.fin.set();
                    st.read_event.notify_one();
                }
            }
            CMD_PSH => {
                if length > 0 {
                    let mut buf = vec![0u8; length];
                    if let Err(e) = read_full(conn.as_ref(), &mut buf).await {
                        s.read_error.set(&e);
                        return;
                    }
                    if let Some(st) = s.streams.lock().unwrap().get(&sid) {
                        st.buffers.lock().unwrap().push_back(buf);
                        s.bucket.fetch_sub(length as i32, Ordering::SeqCst);
                        st.read_event.notify_one();
                    }
                }
            }
            CMD_UPD => {
                let mut upd = [0u8; UPD_SIZE];
                if let Err(e) = read_full(conn.as_ref(), &mut upd).await {
                    s.read_error.set(&e);
                    return;
                }
                if let Some(st) = s.streams.lock().unwrap().get(&sid) {
                    st.peer_consumed.store(
                        u32::from_le_bytes(upd[..4].try_into().unwrap()),
                        Ordering::SeqCst,
                    );
                    st.peer_window.store(
                        u32::from_le_bytes(upd[4..].try_into().unwrap()),
                        Ordering::SeqCst,
                    );
                    st.update.notify_one();
                }
            }
            _ => {
                s.proto_error.set(&io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid protocol",
                ));
                return;
            }
        }
    }
}

async fn keepalive(s: Arc<SessionInner>) {
    let mut ping = tokio::time::interval(s.config.keepalive_interval);
    let mut timeout = tokio::time::interval(s.config.keepalive_timeout);
    ping.tick().await;
    timeout.tick().await;
    loop {
        tokio::select! {
            _ = ping.tick() => {
                let s2 = s.clone();
                let interval = s.config.keepalive_interval;
                tokio::spawn(async move {
                    let _ = write_frame(&s2, Class::Ctrl, CMD_NOP, 0, Vec::new(), Some(interval)).await;
                });
                notify_bucket(&s);
            }
            _ = timeout.tick() => {
                if !s.data_ready.swap(false, Ordering::SeqCst) && s.bucket.load(Ordering::SeqCst) > 0 {
                    close_session(&s);
                    return;
                }
            }
            _ = s.die.wait() => return,
        }
    }
}

struct ReadState {
    num_read: u32,
    incr: u32,
}

struct StreamInner {
    id: u32,
    frame_size: usize,
    buffers: Mutex<VecDeque<Vec<u8>>>,
    read_state: Mutex<ReadState>,
    read_event: Notify,
    die: Latch,
    fin: Latch,
    num_written: AtomicU32,
    peer_consumed: AtomicU32,
    peer_window: AtomicU32,
    update: Notify,
}

impl StreamInner {
    fn new(id: u32, frame_size: usize) -> Arc<StreamInner> {
        Arc::new(StreamInner {
            id,
            frame_size,
            buffers: Mutex::new(VecDeque::new()),
            read_state: Mutex::new(ReadState {
                num_read: 0,
                incr: 0,
            }),
            read_event: Notify::new(),
            die: Latch::new(),
            fin: Latch::new(),
            num_written: AtomicU32::new(0),
            peer_consumed: AtomicU32::new(0),
            peer_window: AtomicU32::new(INITIAL_PEER_WINDOW),
            update: Notify::new(),
        })
    }

    fn recycle_tokens(&self) -> usize {
        let mut b = self.buffers.lock().unwrap();
        let n = b.iter().map(Vec::len).sum();
        b.clear();
        n
    }
}

pub struct Stream {
    inner: Arc<StreamInner>,
    sess: Arc<SessionInner>,
}

enum TryRead {
    Data(usize),
    WouldBlock,
    Eof,
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.inner.id
    }

    fn try_read(&self, buf: &mut [u8]) -> (TryRead, Option<u32>) {
        let st = &self.inner;
        let v2 = self.sess.config.version == 2;
        let mut n = 0;
        let mut notify_consumed = None;
        {
            let mut buffers = st.buffers.lock().unwrap();
            if let Some(front) = buffers.front_mut() {
                n = front.len().min(buf.len());
                buf[..n].copy_from_slice(&front[..n]);
                front.drain(..n);
                if front.is_empty() {
                    buffers.pop_front();
                }
            }
            if v2 {
                let mut rs = st.read_state.lock().unwrap();
                rs.num_read = rs.num_read.wrapping_add(n as u32);
                rs.incr = rs.incr.wrapping_add(n as u32);
                if rs.incr >= (self.sess.config.max_stream_buffer / 2) as u32
                    || rs.num_read == n as u32
                {
                    notify_consumed = Some(rs.num_read);
                    rs.incr = 0;
                }
            }
        }
        if n > 0 {
            return_tokens(&self.sess, n);
            return (TryRead::Data(n), notify_consumed.filter(|c| *c > 0));
        }
        if st.die.is_set() {
            return (TryRead::Eof, None);
        }
        (TryRead::WouldBlock, None)
    }

    async fn wait_read(&self) -> io::Result<()> {
        let st = &self.inner;
        let s = &self.sess;
        tokio::select! {
            _ = st.read_event.notified() => Ok(()),
            _ = st.fin.wait() => {
                if st.buffers.lock().unwrap().is_empty() {
                    Err(io::ErrorKind::UnexpectedEof.into())
                } else {
                    Ok(())
                }
            }
            _ = s.read_error.latch.wait() => Err(s.read_error.error()),
            _ = s.proto_error.latch.wait() => Err(s.proto_error.error()),
            _ = st.die.wait() => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    /// `Ok(0)` is EOF (the peer sent FIN and everything was read).
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.try_read(buf) {
                (TryRead::Data(n), consumed) => {
                    if let Some(c) = consumed {
                        self.send_window_update(c).await?;
                    }
                    return Ok(n);
                }
                (TryRead::Eof, _) => return Ok(0),
                (TryRead::WouldBlock, _) => match self.wait_read().await {
                    Ok(()) => continue,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                    Err(e) => return Err(e),
                },
            }
        }
    }

    async fn send_window_update(&self, consumed: u32) -> io::Result<()> {
        let mut data = Vec::with_capacity(UPD_SIZE);
        data.extend_from_slice(&consumed.to_le_bytes());
        data.extend_from_slice(&(self.sess.config.max_stream_buffer as u32).to_le_bytes());
        write_frame(&self.sess, Class::Ctrl, CMD_UPD, self.inner.id, data, None).await?;
        Ok(())
    }

    fn check_writable(&self) -> io::Result<()> {
        if self.inner.fin.is_set() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if self.inner.die.is_set() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }

    pub async fn write(&self, b: &[u8]) -> io::Result<usize> {
        if self.sess.config.version == 2 {
            return self.write_v2(b).await;
        }
        self.check_writable()?;
        let mut sent = 0;
        for chunk in b.chunks(self.inner.frame_size) {
            sent += write_frame(
                &self.sess,
                Class::Data,
                CMD_PSH,
                self.inner.id,
                chunk.to_vec(),
                None,
            )
            .await?;
        }
        Ok(sent)
    }

    async fn write_v2(&self, mut b: &[u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        self.check_writable()?;
        let st = &self.inner;
        let mut sent = 0;
        loop {
            let inflight =
                st.num_written
                    .load(Ordering::SeqCst)
                    .wrapping_sub(st.peer_consumed.load(Ordering::SeqCst)) as i32;
            if inflight < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer consumed more than sent",
                ));
            }
            let win = st.peer_window.load(Ordering::SeqCst) as i32 - inflight;
            if win > 0 {
                let take = (win as usize).min(b.len());
                let (now, rest) = b.split_at(take);
                b = rest;
                for chunk in now.chunks(st.frame_size) {
                    let n = write_frame(
                        &self.sess,
                        Class::Data,
                        CMD_PSH,
                        st.id,
                        chunk.to_vec(),
                        None,
                    )
                    .await;
                    st.num_written
                        .fetch_add(chunk.len() as u32, Ordering::SeqCst);
                    sent += n?;
                }
            }
            if b.is_empty() {
                return Ok(sent);
            }
            let s = &self.sess;
            tokio::select! {
                _ = st.update.notified() => continue,
                _ = st.fin.wait() => return Err(io::ErrorKind::UnexpectedEof.into()),
                _ = st.die.wait() => return Err(io::ErrorKind::BrokenPipe.into()),
                _ = s.write_error.latch.wait() => return Err(s.write_error.error()),
            }
        }
    }

    pub async fn close(&self) -> io::Result<()> {
        if !self.inner.die.set() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let res = write_frame(
            &self.sess,
            Class::Data,
            CMD_FIN,
            self.inner.id,
            Vec::new(),
            Some(OPEN_CLOSE_TIMEOUT),
        )
        .await;
        stream_closed(&self.sess, self.inner.id);
        res.map(|_| ())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

    /// In-memory MuxConn over a tokio duplex pipe.
    pub struct PipeConn {
        rd: tokio::sync::Mutex<ReadHalf<DuplexStream>>,
        wr: tokio::sync::Mutex<WriteHalf<DuplexStream>>,
    }

    impl PipeConn {
        pub fn pair() -> (Arc<dyn MuxConn>, Arc<dyn MuxConn>) {
            let (a, b) = tokio::io::duplex(1 << 16);
            let wrap = |d: DuplexStream| -> Arc<dyn MuxConn> {
                let (rd, wr) = tokio::io::split(d);
                Arc::new(PipeConn {
                    rd: tokio::sync::Mutex::new(rd),
                    wr: tokio::sync::Mutex::new(wr),
                })
            };
            (wrap(a), wrap(b))
        }
    }

    impl MuxConn for PipeConn {
        fn read<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
            Box::pin(async move { self.rd.lock().await.read(buf).await })
        }
        fn write_all_vectored<'a>(&'a self, bufs: &'a [&'a [u8]]) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async move {
                let mut w = self.wr.lock().await;
                for b in bufs {
                    w.write_all(b).await?;
                }
                Ok(())
            })
        }
        fn close(&self) {}
    }

    fn cfg(version: u8) -> Config {
        Config {
            version,
            max_stream_buffer: 1 << 20,
            keepalive_timeout: Duration::from_secs(600),
            ..Config::default()
        }
    }

    async fn roundtrip(version: u8) {
        let (a, b) = PipeConn::pair();
        let client = Session::client(a, cfg(version)).unwrap();
        let server = Session::server(b, cfg(version)).unwrap();
        let cs = client.open_stream().await.unwrap();
        assert_eq!(cs.id(), 3);
        let ss = server.accept_stream().await.unwrap();
        assert_eq!(ss.id(), 3);

        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 249) as u8).collect();
        let expect = data.clone();
        let writer = tokio::spawn(async move {
            cs.write(&data).await.unwrap();
            cs.close().await.unwrap();
        });
        let mut got = Vec::new();
        let mut buf = vec![0u8; 7000];
        loop {
            let n = ss.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.unwrap();
        assert_eq!(got.len(), expect.len());
        assert!(got == expect);
    }

    #[tokio::test]
    async fn v1_roundtrip_with_fin() {
        roundtrip(1).await;
    }

    #[tokio::test]
    async fn v2_roundtrip_flow_controlled() {
        roundtrip(2).await;
    }

    #[test]
    fn frame_order_prefers_control() {
        let mk = |class, seq| {
            let (tx, _rx) = oneshot::channel();
            WriteRequest {
                class,
                seq,
                ver: 2,
                cmd: 0,
                sid: 0,
                data: vec![],
                result: tx,
            }
        };
        let mut h = BinaryHeap::new();
        h.push(mk(Class::Data, 1));
        h.push(mk(Class::Ctrl, 3));
        h.push(mk(Class::Data, 2));
        h.push(mk(Class::Ctrl, 2));
        let order: Vec<(u8, u32)> = std::iter::from_fn(|| h.pop())
            .map(|r| (r.class as u8, r.seq))
            .collect();
        assert_eq!(order, vec![(0, 2), (0, 3), (1, 1), (1, 2)]);
    }
}
