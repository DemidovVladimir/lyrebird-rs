// Copyright (c) 2015 xtaci (kcp-go, MIT)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: MIT
//
// Port of github.com/xtaci/kcp-go/v5 v5.6.18 kcp.go (itself derived from
// skywind3000/kcp), which the Snowflake client and server both use.

//! KCP ARQ state machine (sans I/O). Segments leave through `output`, which
//! the session drains after every call.

use std::sync::OnceLock;
use std::time::Instant;

pub const IKCP_RTO_NDL: u32 = 30;
pub const IKCP_RTO_MIN: u32 = 100;
pub const IKCP_RTO_DEF: u32 = 200;
pub const IKCP_RTO_MAX: u32 = 60000;
pub const IKCP_CMD_PUSH: u8 = 81;
pub const IKCP_CMD_ACK: u8 = 82;
pub const IKCP_CMD_WASK: u8 = 83;
pub const IKCP_CMD_WINS: u8 = 84;
const IKCP_ASK_SEND: u32 = 1;
const IKCP_ASK_TELL: u32 = 2;
pub const IKCP_WND_SND: u32 = 32;
pub const IKCP_WND_RCV: u32 = 32;
pub const IKCP_MTU_DEF: u32 = 1400;
pub const IKCP_INTERVAL: u32 = 100;
pub const IKCP_OVERHEAD: usize = 24;
pub const IKCP_DEADLINK: u32 = 20;
const IKCP_THRESH_INIT: u32 = 2;
const IKCP_THRESH_MIN: u32 = 2;
const IKCP_PROBE_INIT: u32 = 7000;
const IKCP_PROBE_LIMIT: u32 = 120000;

/// Milliseconds since first use (Go's `currentMs`, relative to process start).
pub fn current_ms() -> u32 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u32
}

fn timediff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier) as i32
}

fn bound(lower: u32, middle: u32, upper: u32) -> u32 {
    middle.max(lower).min(upper)
}

#[derive(Clone, Default)]
struct Segment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    rto: u32,
    xmit: u32,
    resendts: u32,
    fastack: u32,
    acked: bool,
    data: Vec<u8>,
}

impl Segment {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.conv.to_le_bytes());
        out.push(self.cmd);
        out.push(self.frg);
        out.extend_from_slice(&self.wnd.to_le_bytes());
        out.extend_from_slice(&self.ts.to_le_bytes());
        out.extend_from_slice(&self.sn.to_le_bytes());
        out.extend_from_slice(&self.una.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
    }
}

pub struct Kcp {
    conv: u32,
    mtu: u32,
    pub mss: u32,
    pub state: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    ssthresh: u32,
    rx_rttvar: i32,
    rx_srtt: i32,
    rx_rto: u32,
    rx_minrto: u32,
    pub snd_wnd: u32,
    rcv_wnd: u32,
    pub rmt_wnd: u32,
    cwnd: u32,
    probe: u32,
    interval: u32,
    ts_flush: u32,
    nodelay: u32,
    updated: bool,
    ts_probe: u32,
    probe_wait: u32,
    dead_link: u32,
    incr: u32,
    fastresend: i32,
    nocwnd: bool,
    stream: bool,
    snd_queue: std::collections::VecDeque<Segment>,
    rcv_queue: std::collections::VecDeque<Segment>,
    snd_buf: std::collections::VecDeque<Segment>,
    rcv_buf: std::collections::VecDeque<Segment>,
    acklist: Vec<(u32, u32)>,
    /// Datagrams produced by `flush`, in order.
    output: Vec<Vec<u8>>,
}

impl Kcp {
    pub fn new(conv: u32) -> Kcp {
        Kcp {
            conv,
            mtu: IKCP_MTU_DEF,
            mss: IKCP_MTU_DEF - IKCP_OVERHEAD as u32,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: IKCP_THRESH_INIT,
            rx_rttvar: 0,
            rx_srtt: 0,
            rx_rto: IKCP_RTO_DEF,
            rx_minrto: IKCP_RTO_MIN,
            snd_wnd: IKCP_WND_SND,
            rcv_wnd: IKCP_WND_RCV,
            rmt_wnd: IKCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            interval: IKCP_INTERVAL,
            ts_flush: IKCP_INTERVAL,
            nodelay: 0,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: IKCP_DEADLINK,
            incr: 0,
            fastresend: 0,
            nocwnd: false,
            stream: false,
            snd_queue: Default::default(),
            rcv_queue: Default::default(),
            snd_buf: Default::default(),
            rcv_buf: Default::default(),
            acklist: Vec::new(),
            output: Vec::new(),
        }
    }

    pub fn take_output(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.output)
    }

    /// Size of the next message, or -1 if none is complete.
    pub fn peek_size(&self) -> i32 {
        let Some(seg) = self.rcv_queue.front() else {
            return -1;
        };
        if seg.frg == 0 {
            return seg.data.len() as i32;
        }
        if self.rcv_queue.len() < seg.frg as usize + 1 {
            return -1;
        }
        let mut length = 0;
        for seg in &self.rcv_queue {
            length += seg.data.len();
            if seg.frg == 0 {
                break;
            }
        }
        length as i32
    }

    /// Moves the next message into `buf`; -1 nothing ready, -2 buffer too small.
    pub fn recv(&mut self, buf: &mut [u8]) -> i32 {
        let peeksize = self.peek_size();
        if peeksize < 0 {
            return -1;
        }
        if peeksize as usize > buf.len() {
            return -2;
        }
        let fast_recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        let mut n = 0;
        while let Some(seg) = self.rcv_queue.pop_front() {
            buf[n..n + seg.data.len()].copy_from_slice(&seg.data);
            n += seg.data.len();
            if seg.frg == 0 {
                break;
            }
        }

        self.move_ready_segments();

        if self.rcv_queue.len() < self.rcv_wnd as usize && fast_recover {
            self.probe |= IKCP_ASK_TELL;
        }
        n as i32
    }

    fn move_ready_segments(&mut self) {
        while let Some(seg) = self.rcv_buf.front() {
            if seg.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                let seg = self.rcv_buf.pop_front().unwrap();
                self.rcv_queue.push_back(seg);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            } else {
                break;
            }
        }
    }

    pub fn send(&mut self, mut buf: &[u8]) -> i32 {
        if buf.is_empty() {
            return -1;
        }
        let mss = self.mss as usize;
        if self.stream {
            if let Some(seg) = self.snd_queue.back_mut() {
                if seg.data.len() < mss {
                    let extend = (mss - seg.data.len()).min(buf.len());
                    seg.data.extend_from_slice(&buf[..extend]);
                    buf = &buf[extend..];
                }
            }
            if buf.is_empty() {
                return 0;
            }
        }
        let count = if buf.len() <= mss {
            1
        } else {
            buf.len().div_ceil(mss)
        };
        if count > 255 {
            return -2;
        }
        for i in 0..count {
            let size = buf.len().min(mss);
            let seg = Segment {
                frg: if self.stream {
                    0
                } else {
                    (count - i - 1) as u8
                },
                data: buf[..size].to_vec(),
                ..Default::default()
            };
            self.snd_queue.push_back(seg);
            buf = &buf[size..];
        }
        0
    }

    fn update_ack(&mut self, rtt: i32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttvar = rtt >> 1;
        } else {
            let mut delta = rtt - self.rx_srtt;
            self.rx_srtt += delta >> 3;
            if delta < 0 {
                delta = -delta;
            }
            if rtt < self.rx_srtt - self.rx_rttvar {
                // Deviations below the mean only count for a sixteenth.
                self.rx_rttvar += (delta - self.rx_rttvar) >> 5;
            } else {
                self.rx_rttvar += (delta - self.rx_rttvar) >> 2;
            }
        }
        let rto =
            (self.rx_srtt as u32).wrapping_add(self.interval.max((self.rx_rttvar as u32) << 2));
        self.rx_rto = bound(self.rx_minrto, rto, IKCP_RTO_MAX);
    }

    fn shrink_buf(&mut self) {
        self.snd_una = match self.snd_buf.front() {
            Some(seg) => seg.sn,
            None => self.snd_nxt,
        };
    }

    fn parse_ack(&mut self, sn: u32) {
        if timediff(sn, self.snd_una) < 0 || timediff(sn, self.snd_nxt) >= 0 {
            return;
        }
        for seg in self.snd_buf.iter_mut() {
            if sn == seg.sn {
                // Freed now, removed once una passes it.
                seg.acked = true;
                seg.data = Vec::new();
                break;
            }
            if timediff(sn, seg.sn) < 0 {
                break;
            }
        }
    }

    fn parse_fastack(&mut self, sn: u32, ts: u32) {
        if timediff(sn, self.snd_una) < 0 || timediff(sn, self.snd_nxt) >= 0 {
            return;
        }
        for seg in self.snd_buf.iter_mut() {
            if timediff(sn, seg.sn) < 0 {
                break;
            } else if sn != seg.sn && timediff(seg.ts, ts) <= 0 {
                seg.fastack += 1;
            }
        }
    }

    fn parse_una(&mut self, una: u32) -> usize {
        let mut count = 0;
        while let Some(seg) = self.snd_buf.front() {
            if timediff(una, seg.sn) > 0 {
                self.snd_buf.pop_front();
                count += 1;
            } else {
                break;
            }
        }
        count
    }

    /// Returns whether `newseg` was a duplicate.
    fn parse_data(&mut self, newseg: Segment) -> bool {
        let sn = newseg.sn;
        if timediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) >= 0
            || timediff(sn, self.rcv_nxt) < 0
        {
            return true;
        }
        let mut insert_idx = 0;
        let mut repeat = false;
        for i in (0..self.rcv_buf.len()).rev() {
            let seg = &self.rcv_buf[i];
            if seg.sn == sn {
                repeat = true;
                break;
            }
            if timediff(sn, seg.sn) > 0 {
                insert_idx = i + 1;
                break;
            }
        }
        if !repeat {
            self.rcv_buf.insert(insert_idx, newseg);
        }
        self.move_ready_segments();
        repeat
    }

    /// Feeds one received datagram. `regular` is false for FEC-recovered data.
    pub fn input(&mut self, mut data: &[u8], regular: bool, ack_no_delay: bool) -> i32 {
        let snd_una = self.snd_una;
        if data.len() < IKCP_OVERHEAD {
            return -1;
        }
        let mut latest = 0u32;
        let mut flag = false;
        let mut window_slides = false;

        while data.len() >= IKCP_OVERHEAD {
            let conv = u32::from_le_bytes(data[0..4].try_into().unwrap());
            if conv != self.conv {
                return -1;
            }
            let cmd = data[4];
            let frg = data[5];
            let wnd = u16::from_le_bytes(data[6..8].try_into().unwrap());
            let ts = u32::from_le_bytes(data[8..12].try_into().unwrap());
            let sn = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let una = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let length = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
            data = &data[IKCP_OVERHEAD..];
            if data.len() < length {
                return -2;
            }
            if !matches!(
                cmd,
                IKCP_CMD_PUSH | IKCP_CMD_ACK | IKCP_CMD_WASK | IKCP_CMD_WINS
            ) {
                return -3;
            }

            if regular {
                self.rmt_wnd = wnd as u32;
            }
            if self.parse_una(una) > 0 {
                window_slides = true;
            }
            self.shrink_buf();

            match cmd {
                IKCP_CMD_ACK => {
                    self.parse_ack(sn);
                    self.parse_fastack(sn, ts);
                    flag = true;
                    latest = ts;
                }
                IKCP_CMD_PUSH => {
                    if timediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) < 0 {
                        self.acklist.push((sn, ts));
                        if timediff(sn, self.rcv_nxt) >= 0 {
                            self.parse_data(Segment {
                                conv,
                                cmd,
                                frg,
                                wnd,
                                ts,
                                sn,
                                una,
                                data: data[..length].to_vec(),
                                ..Default::default()
                            });
                        }
                    }
                }
                IKCP_CMD_WASK => self.probe |= IKCP_ASK_TELL,
                _ => {} // IKCP_CMD_WINS: nothing to do
            }
            data = &data[length..];
        }

        if flag && regular {
            let current = current_ms();
            if timediff(current, latest) >= 0 {
                self.update_ack(timediff(current, latest));
            }
        }

        if !self.nocwnd && timediff(self.snd_una, snd_una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr += (mss * mss) / self.incr + (mss / 16);
                if (self.cwnd + 1) * mss <= self.incr {
                    self.cwnd = if mss > 0 {
                        self.incr.div_ceil(mss)
                    } else {
                        self.incr + mss - 1
                    };
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd * mss;
            }
        }

        if window_slides {
            self.flush(false);
        } else if ack_no_delay && !self.acklist.is_empty() {
            self.flush(true);
        }
        0
    }

    fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            (self.rcv_wnd as usize - self.rcv_queue.len()) as u16
        } else {
            0
        }
    }

    /// Emits pending ACKs, probes and (re)transmissions. Returns the
    /// suggested delay (ms) before the next flush.
    pub fn flush(&mut self, ack_only: bool) -> u32 {
        let mtu = self.mtu as usize;
        let mut ctrl = Segment {
            conv: self.conv,
            cmd: IKCP_CMD_ACK,
            wnd: self.wnd_unused(),
            una: self.rcv_nxt,
            ..Default::default()
        };
        let mut buf: Vec<u8> = Vec::with_capacity(mtu);
        let output = &mut self.output;
        let mut make_space = |buf: &mut Vec<u8>, space: usize| {
            if buf.len() + space > mtu {
                output.push(std::mem::replace(buf, Vec::with_capacity(mtu)));
            }
        };

        let acks = std::mem::take(&mut self.acklist);
        let last = acks.len().wrapping_sub(1);
        for (i, &(sn, ts)) in acks.iter().enumerate() {
            make_space(&mut buf, IKCP_OVERHEAD);
            if timediff(sn, self.rcv_nxt) >= 0 || i == last {
                ctrl.sn = sn;
                ctrl.ts = ts;
                ctrl.encode(&mut buf);
            }
        }

        if ack_only {
            if !buf.is_empty() {
                self.output.push(buf);
            }
            return self.interval;
        }

        if self.rmt_wnd == 0 {
            let current = current_ms();
            if self.probe_wait == 0 {
                self.probe_wait = IKCP_PROBE_INIT;
                self.ts_probe = current.wrapping_add(self.probe_wait);
            } else if timediff(current, self.ts_probe) >= 0 {
                if self.probe_wait < IKCP_PROBE_INIT {
                    self.probe_wait = IKCP_PROBE_INIT;
                }
                self.probe_wait += self.probe_wait / 2;
                if self.probe_wait > IKCP_PROBE_LIMIT {
                    self.probe_wait = IKCP_PROBE_LIMIT;
                }
                self.ts_probe = current.wrapping_add(self.probe_wait);
                self.probe |= IKCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }

        let output = &mut self.output;
        let mut make_space = |buf: &mut Vec<u8>, space: usize| {
            if buf.len() + space > mtu {
                output.push(std::mem::replace(buf, Vec::with_capacity(mtu)));
            }
        };
        if self.probe & IKCP_ASK_SEND != 0 {
            ctrl.cmd = IKCP_CMD_WASK;
            make_space(&mut buf, IKCP_OVERHEAD);
            ctrl.encode(&mut buf);
        }
        if self.probe & IKCP_ASK_TELL != 0 {
            ctrl.cmd = IKCP_CMD_WINS;
            make_space(&mut buf, IKCP_OVERHEAD);
            ctrl.encode(&mut buf);
        }
        self.probe = 0;

        let mut cwnd = self.snd_wnd.min(self.rmt_wnd);
        if !self.nocwnd {
            cwnd = self.cwnd.min(cwnd);
        }

        let mut new_segs = 0;
        while !self.snd_queue.is_empty() {
            if timediff(self.snd_nxt, self.snd_una.wrapping_add(cwnd)) >= 0 {
                break;
            }
            let mut seg = self.snd_queue.pop_front().unwrap();
            seg.conv = self.conv;
            seg.cmd = IKCP_CMD_PUSH;
            seg.sn = self.snd_nxt;
            self.snd_buf.push_back(seg);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            new_segs += 1;
        }

        let resent = if self.fastresend <= 0 {
            u32::MAX
        } else {
            self.fastresend as u32
        };

        let mut current = current_ms();
        let mut change = 0u64;
        let mut lost = 0u64;
        let mut minrto = self.interval as i32;
        let rx_rto = self.rx_rto;
        let nodelay = self.nodelay;
        let dead_link = self.dead_link;
        let mut dead = false;

        let output = &mut self.output;
        for seg in self.snd_buf.iter_mut() {
            if seg.acked {
                continue;
            }
            let mut needsend = false;
            // Branches kept separate to mirror kcp-go's flush.
            #[allow(clippy::if_same_then_else)]
            if seg.xmit == 0 {
                needsend = true;
                seg.rto = rx_rto;
                seg.resendts = current.wrapping_add(seg.rto);
            } else if seg.fastack >= resent {
                needsend = true;
                seg.fastack = 0;
                seg.rto = rx_rto;
                seg.resendts = current.wrapping_add(seg.rto);
                change += 1;
            } else if seg.fastack > 0 && new_segs == 0 {
                needsend = true;
                seg.fastack = 0;
                seg.rto = rx_rto;
                seg.resendts = current.wrapping_add(seg.rto);
                change += 1;
            } else if timediff(current, seg.resendts) >= 0 {
                needsend = true;
                if nodelay == 0 {
                    seg.rto += rx_rto;
                } else {
                    seg.rto += rx_rto / 2;
                }
                seg.fastack = 0;
                seg.resendts = current.wrapping_add(seg.rto);
                lost += 1;
            }

            if needsend {
                current = current_ms();
                seg.xmit += 1;
                seg.ts = current;
                seg.wnd = ctrl.wnd;
                seg.una = ctrl.una;
                let need = IKCP_OVERHEAD + seg.data.len();
                if buf.len() + need > mtu {
                    output.push(std::mem::replace(&mut buf, Vec::with_capacity(mtu)));
                }
                seg.encode(&mut buf);
                buf.extend_from_slice(&seg.data);
                if seg.xmit >= dead_link {
                    dead = true;
                }
            }

            let rto = timediff(seg.resendts, current);
            if rto > 0 && rto < minrto {
                minrto = rto;
            }
        }
        if !buf.is_empty() {
            output.push(buf);
        }
        if dead {
            self.state = 0xFFFF_FFFF;
        }

        if !self.nocwnd {
            if change > 0 {
                let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.ssthresh = (inflight / 2).max(IKCP_THRESH_MIN);
                self.cwnd = self.ssthresh.wrapping_add(resent);
                self.incr = self.cwnd.wrapping_mul(self.mss);
            }
            if lost > 0 {
                self.ssthresh = (cwnd / 2).max(IKCP_THRESH_MIN);
                self.cwnd = 1;
                self.incr = self.mss;
            }
            if self.cwnd < 1 {
                self.cwnd = 1;
                self.incr = self.mss;
            }
        }
        minrto as u32
    }

    pub fn update(&mut self) {
        let current = current_ms();
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
        let mut slap = timediff(current, self.ts_flush);
        if !(-10000..10000).contains(&slap) {
            self.ts_flush = current;
            slap = 0;
        }
        if slap >= 0 {
            self.ts_flush = self.ts_flush.wrapping_add(self.interval);
            if timediff(current, self.ts_flush) >= 0 {
                self.ts_flush = current.wrapping_add(self.interval);
            }
            self.flush(false);
        }
    }

    pub fn set_mtu(&mut self, mtu: u32) -> i32 {
        if mtu < 50 || (mtu as usize) < IKCP_OVERHEAD {
            return -1;
        }
        self.mtu = mtu;
        self.mss = mtu - IKCP_OVERHEAD as u32;
        0
    }

    pub fn nodelay(&mut self, nodelay: i32, interval: i32, resend: i32, nc: i32) {
        if nodelay >= 0 {
            self.nodelay = nodelay as u32;
            self.rx_minrto = if nodelay != 0 {
                IKCP_RTO_NDL
            } else {
                IKCP_RTO_MIN
            };
        }
        if interval >= 0 {
            self.interval = interval.clamp(10, 5000) as u32;
        }
        if resend >= 0 {
            self.fastresend = resend;
        }
        if nc >= 0 {
            self.nocwnd = nc != 0;
        }
    }

    pub fn wnd_size(&mut self, sndwnd: i32, rcvwnd: i32) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd as u32;
        }
        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd as u32;
        }
    }

    pub fn set_stream(&mut self, stream: bool) {
        self.stream = stream;
    }

    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    pub fn release_tx(&mut self) {
        self.snd_queue.clear();
        self.snd_buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Kcp, Kcp) {
        let mut a = Kcp::new(0x11223344);
        let mut b = Kcp::new(0x11223344);
        for k in [&mut a, &mut b] {
            k.set_stream(true);
            k.wnd_size(65535, 65535);
            k.nodelay(0, 0, 0, 1);
        }
        (a, b)
    }

    /// Pumps datagrams between the two ends, dropping every `drop_every`-th.
    fn pump(a: &mut Kcp, b: &mut Kcp, drop_every: usize, counter: &mut usize) {
        for pkt in a.take_output() {
            *counter += 1;
            if drop_every == 0 || *counter % drop_every != 0 {
                b.input(&pkt, true, false);
            }
        }
        for pkt in b.take_output() {
            *counter += 1;
            if drop_every == 0 || *counter % drop_every != 0 {
                a.input(&pkt, true, false);
            }
        }
    }

    fn transfer(drop_every: usize) {
        let (mut a, mut b) = pair();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        for chunk in data.chunks(4096) {
            assert_eq!(a.send(chunk), 0);
        }
        let mut got = Vec::new();
        let mut buf = vec![0u8; 65536];
        let mut counter = 0;
        let start = Instant::now();
        while got.len() < data.len() {
            a.flush(false);
            b.flush(false);
            pump(&mut a, &mut b, drop_every, &mut counter);
            loop {
                let n = b.recv(&mut buf);
                if n < 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n as usize]);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
            assert!(start.elapsed().as_secs() < 30, "transfer stalled");
        }
        assert_eq!(got, data);
    }

    #[test]
    fn lossless_stream_transfer() {
        transfer(0);
    }

    #[test]
    fn lossy_stream_transfer() {
        transfer(7);
    }

    #[test]
    fn segment_wire_format() {
        let mut k = Kcp::new(0xa1b2c3d4);
        k.send(b"hello");
        // With congestion control on, cwnd starts at 0; the first flush only
        // opens it to 1 (as in kcp-go and ikcp).
        k.flush(false);
        assert!(k.take_output().is_empty());
        k.flush(false);
        let out = k.take_output();
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(&p[0..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(p[4], IKCP_CMD_PUSH);
        assert_eq!(p[5], 0); // frg
        assert_eq!(u16::from_le_bytes([p[6], p[7]]), IKCP_WND_RCV as u16);
        assert_eq!(u32::from_le_bytes(p[12..16].try_into().unwrap()), 0); // sn
        assert_eq!(u32::from_le_bytes(p[20..24].try_into().unwrap()), 5); // len
        assert_eq!(&p[24..], b"hello");
    }

    #[test]
    fn message_mode_fragments() {
        let mut a = Kcp::new(1);
        let mut b = Kcp::new(1);
        a.nodelay(-1, -1, -1, 1);
        let msg = vec![9u8; 5000];
        a.send(&msg);
        a.flush(false);
        for p in a.take_output() {
            b.input(&p, true, false);
        }
        let mut buf = vec![0u8; 4000];
        assert_eq!(b.recv(&mut buf), -2);
        let mut big = vec![0u8; 6000];
        assert_eq!(b.recv(&mut big), 5000);
        assert_eq!(&big[..5000], &msg[..]);
    }
}
