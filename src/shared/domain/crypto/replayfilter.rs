// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/replayfilter.

//! Time-bounded replay filter keyed by SipHash of the handshake MAC.

use std::collections::{HashMap, VecDeque};
use std::hash::Hasher;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use siphasher::sip::SipHasher24;

use super::csrand;

const MAX_FILTER_SIZE: usize = 100 * 1024;

pub struct ReplayFilter {
    key: [u8; 16],
    ttl: Duration,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    filter: HashMap<u64, SystemTime>,
    fifo: VecDeque<(u64, SystemTime)>,
}

impl ReplayFilter {
    pub fn new(ttl: Duration) -> ReplayFilter {
        let mut key = [0u8; 16];
        csrand::bytes(&mut key);
        ReplayFilter {
            key,
            ttl,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// True if `buf` was seen within the TTL; otherwise records it.
    pub fn test_and_set(&self, now: SystemTime, buf: &[u8]) -> bool {
        let mut h = SipHasher24::new_with_key(&self.key);
        h.write(buf);
        let digest = h.finish();

        let mut inner = self.inner.lock().unwrap();
        self.compact(&mut inner, now);
        if inner.filter.contains_key(&digest) {
            return true;
        }
        inner.filter.insert(digest, now);
        inner.fifo.push_back((digest, now));
        false
    }

    fn compact(&self, inner: &mut Inner, now: SystemTime) {
        while let Some(&(digest, first_seen)) = inner.fifo.front() {
            if inner.fifo.len() < MAX_FILTER_SIZE && !self.ttl.is_zero() {
                match now.duration_since(first_seen) {
                    // Clock went backwards: start over.
                    Err(_) => {
                        *inner = Inner::default();
                        return;
                    }
                    Ok(age) if age < self.ttl => return,
                    Ok(_) => {}
                }
            }
            inner.fifo.pop_front();
            inner.filter.remove(&digest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_replay_until_ttl() {
        let f = ReplayFilter::new(Duration::from_secs(10));
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(!f.test_and_set(t0, b"mac"));
        assert!(f.test_and_set(t0 + Duration::from_secs(5), b"mac"));
        assert!(!f.test_and_set(t0 + Duration::from_secs(5), b"other"));
        assert!(!f.test_and_set(t0 + Duration::from_secs(11), b"mac"));
    }

    #[test]
    fn clock_skew_resets() {
        let f = ReplayFilter::new(Duration::from_secs(10));
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(!f.test_and_set(t0, b"mac"));
        assert!(!f.test_and_set(t0 - Duration::from_secs(1), b"mac"));
    }
}
