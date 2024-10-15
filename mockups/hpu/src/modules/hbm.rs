use ipc_channel::ipc::{self, IpcSharedMemory};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tfhe::tfhe_hpu_backend::prelude::*;

pub const HBM_BANK_NB: usize = 32;
const HBM_BANK_SIZE_B: usize = 512 * 1024 * 1024;
const HBM_PAGE_SIZE_B: usize = 4096;

pub struct HbmChunk {
    // Properties
    pub(crate) paddr: u64,
    pub(crate) size_b: usize,

    data: Vec<u8>,
    hw_tx: ipc::IpcSender<ipc::IpcSharedMemory>,
    hw_rx: ipc::IpcReceiver<ipc::IpcSharedMemory>,
}

impl HbmChunk {
    pub fn new(
        paddr: u64,
        size_b: usize,
    ) -> (
        Self,
        (
            ipc::IpcSender<ipc::IpcSharedMemory>,
            ipc::IpcReceiver<ipc::IpcSharedMemory>,
        ),
    ) {
        // Create ipc sync channels
        let (hw_tx, cpu_rx) = ipc::channel().unwrap();
        let (cpu_tx, hw_rx) = ipc::channel().unwrap();

        (
            Self {
                paddr,
                size_b,
                data: vec![0; size_b],
                hw_tx,
                hw_rx,
            },
            (cpu_tx, cpu_rx),
        )
    }

    pub fn sync(&mut self, mode: SyncMode) {
        let Self {
            data,
            hw_tx: sync_tx,
            hw_rx: sync_rx,
            ..
        } = self;
        match mode {
            SyncMode::Host2Device => {
                let hw_data = sync_rx.recv().unwrap();
                data.copy_from_slice(&*hw_data);
            }
            SyncMode::Device2Host => {
                let cpu_data = IpcSharedMemory::from_bytes(data.as_slice());
                sync_tx.send(cpu_data);
            }
        }
    }
}

pub(crate) struct HbmBank {
    pc_id: usize,
    chunk: HashMap<u64, HbmChunk>,
}

impl HbmBank {
    pub fn new(pc_id: usize) -> Self {
        Self {
            pc_id,
            chunk: HashMap::new(),
        }
    }

    pub(crate) fn alloc(
        &mut self,
        size_b: usize,
    ) -> (
        u64,
        (
            ipc::IpcSender<ipc::IpcSharedMemory>,
            ipc::IpcReceiver<ipc::IpcSharedMemory>,
        ),
    ) {
        // Compute next paddr
        let paddr = if let Some(key) = self.chunk.keys().max() {
            let chunk = &self.chunk[key];
            if (chunk.size_b % HBM_PAGE_SIZE_B) != 0 {
                chunk.paddr + (((chunk.size_b / HBM_PAGE_SIZE_B) + 1) * HBM_PAGE_SIZE_B) as u64
            } else {
                chunk.paddr + ((chunk.size_b / HBM_PAGE_SIZE_B) * HBM_PAGE_SIZE_B) as u64
            }
        } else {
            0
        };

        // allocate chunk and register it in hashmap
        let (chunk, cpu) = HbmChunk::new(paddr, size_b);
        self.chunk.insert(paddr, chunk);

        (paddr, cpu)
    }

    pub(crate) fn get_chunk(&mut self, addr: u64) -> &mut HbmChunk {
        self.chunk.get_mut(&addr).unwrap()
    }

    pub(crate) fn rm_chunk(&mut self, addr: u64) -> Option<HbmChunk> {
        self.chunk.remove(&addr)
    }
}
