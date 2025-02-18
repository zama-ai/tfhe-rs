//! Hpu memory models
pub(crate) mod hbm;
pub(crate) use hbm::{HbmBank, HBM_BANK_NB};

pub(crate) mod ddr;
pub(crate) use ddr::DdrMem;

#[allow(unused)]
const MEM_PAGE_SIZE_B: usize = 4096;

// CT could use Ddr or Hbm memory.
// Its not the case for Keys, and thus PC_MAX for keys are defined in hbm
pub const MEM_CT_PC_MAX: usize = 2;

use ipc_channel::ipc;

/// Chunk of on-board memory
/// Could be synced in both direction through IPC
pub struct MemChunk {
    // Properties
    pub(crate) paddr: u64,
    pub(crate) size_b: usize,

    // Data
    pub(crate) data: Vec<u8>,
}

impl MemChunk {
    pub fn new(paddr: u64, size_b: usize) -> Self {
        Self {
            paddr,
            size_b,
            data: vec![0; size_b],
        }
    }

    /// Return reference on data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Return mutable reference on data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Generate Shm for syncing data through Ipc
    pub fn ipc_wrap(&self) -> ipc::IpcSharedMemory {
        ipc::IpcSharedMemory::from_bytes(self.data.as_slice())
    }

    /// Update internal data from Ipc shm
    pub fn ipc_update(&mut self, ipc_data: ipc::IpcSharedMemory) {
        self.data.copy_from_slice(&ipc_data);
    }
}
