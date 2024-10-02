//! MemZone mockup ffi interface
use crate::ffi::*;

pub struct MemZone(Vec<u8>);

impl MemZone {
    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        let size_b = bytes.len();
        let (start, end) = (ofst, ofst + size_b);

        bytes.copy_from_slice(&self.0[start..end])
    }

    pub fn paddr(&self) -> u64 {
        0
        // TODO find a way without unstable features...
        // self.0.as_ptr().addr() as u64
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        self.0.as_mut_slice()[ofst..].copy_from_slice(bytes)
    }

    pub fn mmap(&mut self) -> &mut [u64] {
        todo!("mmap not used anymore and interface seems wrong")
        // self.0.as_mut_slice()
    }

    pub fn sync(&mut self, _mode: SyncMode) {
        // Currently a NOP
    }
}
