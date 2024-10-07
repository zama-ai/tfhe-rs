//! MemZone mockup ffi interface
use std::sync::Arc;

use super::hpu_sim::HbmChunk;
use crate::ffi::*;

const HBM_BANK_SIZE_B: u64 = 512 * 1024 * 1024;

pub struct MemZone(Arc<HbmChunk>);

impl MemZone {
    pub(crate) fn new(chunk: Arc<HbmChunk>) -> Self {
        Self(chunk)
    }
    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        let size_b = bytes.len();
        let (start, end) = (ofst, ofst + size_b);

        let cpu_view = self.0.cpu_view();
        bytes.copy_from_slice(&cpu_view[start..end])
    }

    pub fn paddr(&self) -> u64 {
        self.0.paddr as u64
    }

    pub fn size(&self) -> usize {
        self.0.size_b
    }

    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        let (start, end) = (ofst, ofst + bytes.len());
        let mut cpu_view = self.0.cpu_view();
        cpu_view.as_mut_slice()[start..end].copy_from_slice(bytes)
    }

    pub fn mmap(&mut self) -> &mut [u64] {
        todo!("mmap not used anymore and interface seems wrong")
        // self.0.as_mut_slice()
    }

    pub fn sync(&mut self, mode: SyncMode) {
        self.0.sync(mode)
    }
}
