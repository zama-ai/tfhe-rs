use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::ffi::SyncMode;

pub const HBM_BANK_NB: usize = 32;
const HBM_BANK_SIZE_B: usize = 512 * 1024 * 1024;
const HBM_PAGE_SIZE_B: usize = 4096;

pub const HBM_BSK_PC_MAX: usize = 8;
pub const HBM_KSK_PC_MAX: usize = 8;
pub const HBM_CT_BANK_MAX: usize = 4;

pub struct HbmChunk {
    // Properties
    pub(crate) paddr: usize,
    pub(crate) size_b: usize,
    cpu_view: Mutex<Vec<u8>>,
    hw_view: Mutex<Vec<u8>>,
}

impl HbmChunk {
    pub fn new(paddr: usize, size_b: usize) -> Self {
        Self {
            paddr,
            size_b,
            cpu_view: Mutex::new(vec![0; size_b]),
            hw_view: Mutex::new(vec![0; size_b]),
        }
    }

    pub fn cpu_view(&self) -> MutexGuard<Vec<u8>> {
        self.cpu_view.lock().unwrap()
    }

    pub(crate) fn hw_view(&self) -> MutexGuard<Vec<u8>> {
        self.hw_view.lock().unwrap()
    }

    pub fn sync(&self, mode: SyncMode) {
        let Self {
            cpu_view, hw_view, ..
        } = self;
        match mode {
            SyncMode::Host2Device => {
                let cpu = cpu_view.lock().unwrap();
                let mut hw = hw_view.lock().unwrap();
                hw.copy_from_slice(&cpu);
            }
            SyncMode::Device2Host => {
                let hw = hw_view.lock().unwrap();
                let mut cpu = cpu_view.lock().unwrap();
                cpu.copy_from_slice(&hw);
            }
        }
    }
}

pub(crate) struct HbmBank {
    pc_id: usize,
    chunk: HashMap<usize, Arc<HbmChunk>>,
}

impl HbmBank {
    pub fn new(pc_id: usize) -> Self {
        Self {
            pc_id,
            chunk: HashMap::new(),
        }
    }

    pub(crate) fn alloc(&mut self, size_b: usize) -> Arc<HbmChunk> {
        // Compute next paddr
        let paddr = if let Some(key) = self.chunk.keys().max() {
            let chunk = &self.chunk[key];
            if (chunk.size_b % HBM_PAGE_SIZE_B) != 0 {
                chunk.paddr + ((chunk.size_b / HBM_PAGE_SIZE_B) + 1) * HBM_PAGE_SIZE_B
            } else {
                chunk.paddr + (chunk.size_b / HBM_PAGE_SIZE_B) * HBM_PAGE_SIZE_B
            }
        } else {
            0
        };

        // allocate chunk and register it in hashmap
        let chunk = Arc::new(HbmChunk::new(paddr, size_b));
        self.chunk.insert(paddr, chunk.clone());
        chunk
    }

    pub(crate) fn get_chunk(&self, addr: usize) -> Arc<HbmChunk> {
        self.chunk.get(&addr).unwrap().clone()
    }
}
