//! A writer that only ever hands the file whole blocks, so no write ends
//! part-way through a page.
//!
//! Writing a Parquet file straight to the CIFS share lost data in two runs
//! (run_20261122T205840, run_20261123T020456) with no error from write or
//! fsync, on soft and on hard mounts alike. Every loss was the tail of one
//! 4 KiB page read back as zeros: the page was sent half-filled at the end of
//! the file, the next write filled its tail, and the server kept the first
//! version. Writes of whole blocks from offset 0 never leave a page half
//! filled, so no page is sent twice; only the final page, written once at
//! `finish`, can be partial.

use std::io::{self, Write};

/// A multiple of every page size in use (4 KiB), and large enough that the
/// writes stay efficient over the network.
pub const BLOCK: usize = 1 << 20;

pub struct AlignedWriter<W: Write> {
    inner: Option<W>,
    buf: Vec<u8>,
}

impl<W: Write> AlignedWriter<W> {
    /// `inner` must be positioned at offset 0 (a new file), or alignment is
    /// relative to wherever it starts.
    pub fn new(inner: W) -> Self {
        Self {
            inner: Some(inner),
            buf: Vec::with_capacity(2 * BLOCK),
        }
    }

    /// Writes the buffered tail, flushes, and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.write_tail()?;
        Ok(self.inner.take().expect("inner is taken only by finish"))
    }

    fn write_tail(&mut self) -> io::Result<()> {
        if let Some(w) = self.inner.as_mut() {
            w.write_all(&self.buf)?;
            self.buf.clear();
            w.flush()?;
        }
        Ok(())
    }
}

impl<W: Write> Write for AlignedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        let whole = self.buf.len() / BLOCK * BLOCK;
        if whole > 0 {
            let w = self.inner.as_mut().expect("write after finish");
            w.write_all(&self.buf[..whole])?;
            self.buf.drain(..whole);
        }
        Ok(data.len())
    }

    /// Deliberately writes nothing: flushing the partial tail is exactly the
    /// half-filled page this writer exists to avoid. `finish` writes it.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer dropped without `finish` (e.g. on panic) still writes its tail,
/// so the file is no shorter than what was written to it.
impl<W: Write> Drop for AlignedWriter<W> {
    fn drop(&mut self) {
        let _ = self.write_tail();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records the length of every write it receives.
    #[derive(Default)]
    struct Recorder {
        data: Vec<u8>,
        writes: Vec<usize>,
    }

    impl Write for Recorder {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.data.extend_from_slice(b);
            self.writes.push(b.len());
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn only_the_last_write_is_partial() {
        let mut w = AlignedWriter::new(Recorder::default());
        let mut want = Vec::new();
        // Odd sizes, some far larger than a block, some tiny.
        for (i, n) in [1, 4095, 7, BLOCK + 3, 3 * BLOCK - 1, 12_345, 1].iter().enumerate() {
            let chunk: Vec<u8> = (0..*n).map(|j| (i * 31 + j) as u8).collect();
            w.write_all(&chunk).unwrap();
            w.flush().unwrap();
            want.extend_from_slice(&chunk);
        }
        let r = w.finish().unwrap();
        assert_eq!(r.data, want);
        let (last, rest) = r.writes.split_last().unwrap();
        assert!(rest.iter().all(|n| n % BLOCK == 0), "{:?}", r.writes);
        assert_eq!(*last, want.len() % BLOCK);
    }

    #[test]
    fn drop_writes_the_tail() {
        let mut out = Vec::new();
        {
            let mut w = AlignedWriter::new(&mut out);
            w.write_all(b"tail").unwrap();
        }
        assert_eq!(out, b"tail");
    }
}
