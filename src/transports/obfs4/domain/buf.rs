//! Growable FIFO byte buffer (the role `bytes.Buffer` plays upstream).

#[derive(Default)]
pub struct Buf {
    data: Vec<u8>,
    start: usize,
}

impl Buf {
    pub fn len(&self) -> usize {
        self.data.len() - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }

    pub fn extend(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start >= self.data.len() / 2 {
            self.data.drain(..self.start);
            self.start = 0;
        }
        self.data.extend_from_slice(bytes);
    }

    pub fn consume(&mut self, n: usize) {
        assert!(n <= self.len(), "Buf::consume past end");
        self.start += n;
        if self.start == self.data.len() {
            self.data.clear();
            self.start = 0;
        }
    }

    /// Moves up to `out.len()` bytes out of the front; returns the count.
    pub fn read_into(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len());
        out[..n].copy_from_slice(&self.as_slice()[..n]);
        self.consume(n);
        n
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.start = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_semantics() {
        let mut b = Buf::default();
        b.extend(b"hello");
        b.consume(2);
        b.extend(b" world");
        let mut out = [0u8; 4];
        assert_eq!(b.read_into(&mut out), 4);
        assert_eq!(&out, b"llo ");
        assert_eq!(b.as_slice(), b"world");
        b.consume(5);
        assert!(b.is_empty());
    }
}
