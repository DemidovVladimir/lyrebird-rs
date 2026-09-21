//! Go `math/rand` (v1) algorithms over a pluggable 63-bit source.
//!
//! lyrebird seeds `rand.New(drbg)` with a SipHash DRBG and derives
//! wire-visible parameters from it (length tables, close delay), so these
//! must consume the source exactly like Go does.

pub trait Source {
    fn int63(&mut self) -> i64;
}

pub struct Rand<S: Source>(S);

impl<S: Source> Rand<S> {
    pub fn new(src: S) -> Self {
        Rand(src)
    }

    pub fn int63(&mut self) -> i64 {
        self.0.int63()
    }

    pub fn int31(&mut self) -> i32 {
        (self.int63() >> 32) as i32
    }

    pub fn int63n(&mut self, n: i64) -> i64 {
        assert!(n > 0, "invalid argument to int63n");
        if n & (n - 1) == 0 {
            return self.int63() & (n - 1);
        }
        let max = ((1u64 << 63) - 1 - (1u64 << 63) % n as u64) as i64;
        let mut v = self.int63();
        while v > max {
            v = self.int63();
        }
        v % n
    }

    pub fn int31n(&mut self, n: i32) -> i32 {
        assert!(n > 0, "invalid argument to int31n");
        if n & (n - 1) == 0 {
            return self.int31() & (n - 1);
        }
        let max = ((1u32 << 31) - 1 - (1u32 << 31) % n as u32) as i32;
        let mut v = self.int31();
        while v > max {
            v = self.int31();
        }
        v % n
    }

    /// Go `Intn` for a 64-bit `int`.
    pub fn intn(&mut self, n: i64) -> i64 {
        assert!(n > 0, "invalid argument to intn");
        if n <= i32::MAX as i64 {
            self.int31n(n as i32) as i64
        } else {
            self.int63n(n)
        }
    }

    pub fn float64(&mut self) -> f64 {
        loop {
            let f = self.int63() as f64 / (1u64 << 63) as f64;
            if f != 1.0 {
                return f;
            }
        }
    }

    pub fn perm(&mut self, n: usize) -> Vec<usize> {
        let mut m = vec![0usize; n];
        for i in 0..n {
            let j = self.intn(i as i64 + 1) as usize;
            m[i] = m[j];
            m[j] = i;
        }
        m
    }
}
