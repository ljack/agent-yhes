//! Forward one fixed readiness signal; discard all native approval progress.
use std::io::{self, Write};

const CORE_READY: &[u8] =
    b"yhes: realtime: waiting for ciphertext notifications; Git remains authoritative\n";
const SIM_READY: &[u8] = b"SIMULATION realtime: waiting for ciphertext notifications\n";

pub struct ReadyProgress<W> {
    output: W,
    matched: Option<usize>,
}

impl<W: Write> ReadyProgress<W> {
    pub fn new(output: W) -> Self {
        Self {
            output,
            matched: Some(0),
        }
    }
}

impl<W: Write> Write for ReadyProgress<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // write_fmt may split a line across writes. Match incrementally without
        // buffering arbitrary progress, and discard a mismatch until newline.
        for byte in bytes {
            self.matched = self
                .matched
                .and_then(|count| (CORE_READY.get(count) == Some(byte)).then_some(count + 1));
            if *byte == b'\n' {
                let ready = self.matched == Some(CORE_READY.len());
                self.matched = Some(0);
                if ready {
                    self.output.write_all(SIM_READY)?;
                    self.output.flush()?;
                }
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}
