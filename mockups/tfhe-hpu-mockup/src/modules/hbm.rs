use ipc_channel::ipc;
use std::collections::HashMap;

#[allow(unused)]
pub const HBM_BANK_NB: usize = 32;
#[allow(unused)]
const HBM_BANK_SIZE_B: usize = 512 * 1024 * 1024;
#[allow(unused)]
const HBM_PAGE_SIZE_B: usize = 4096;

pub const HBM_BSK_PC_MAX: usize = 8;
pub const HBM_KSK_PC_MAX: usize = 8;
pub const HBM_CT_PC_MAX: usize = 2;

// WARN: XRT currently not suppor allocation greater than 16MiB
const HBM_CHUNK_SIZE_B: usize = 16 * 1024 * 1024;

pub struct HbmChunk {
    // Properties
    pub(crate) paddr: u64,
    pub(crate) size_b: usize,

    // Data
    pub(crate) data: Vec<u8>,
}

impl HbmChunk {
    pub fn new(paddr: u64, size_b: usize) -> Self {
        Self {
            paddr,
            size_b,
            data: vec![0; size_b],
        }
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
    #[allow(unused)]
    pub fn get_pc(&mut self) -> usize {
        self.pc_id
    }

    pub(crate) fn alloc(&mut self, size_b: usize) -> u64 {
        assert!(
            size_b <= HBM_CHUNK_SIZE_B,
            "XRT don't support allocation greater than {HBM_CHUNK_SIZE_B} Bytes."
        );

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
        let chunk = HbmChunk::new(paddr, size_b);
        self.chunk.insert(paddr, chunk);

        paddr
    }

    pub(crate) fn get_chunk(&self, addr: u64) -> &HbmChunk {
        self.chunk.get(&addr).unwrap()
    }

    pub(crate) fn get_mut_chunk(&mut self, addr: u64) -> &mut HbmChunk {
        self.chunk.get_mut(&addr).unwrap()
    }

    pub(crate) fn rm_chunk(&mut self, addr: u64) -> Option<HbmChunk> {
        self.chunk.remove(&addr)
    }

    /// Read data slice from mutiple chunk
    /// WARN: To circumvent an XRT limitation with huge buffer, Key's memory are allocated with
    /// multiple slot of MEM_CHUNK_SIZE_B (i.e. Currently 16MiB) This is abstracted by the
    /// HugeMemory in tfhe-hpu-backend Mimics the logic here to correctly read Huge object from
    /// Hbm model NB: User specify ofset in unit of data.
    pub(crate) fn read_across_chunk<T>(&self, ofst: usize, data: &mut [T])
    where
        T: bytemuck::Pod,
    {
        // Underlying memory is view as bytes memory
        // Extract byte ofst and byte length
        // NB: Don't use generic write method to prevent misunderstanding of ofst meaning
        // Indeed, we must used a bytes ofset to compute the sub-bfr id and thus keep a
        // byte approach everywhere to prevent mismatch
        let ofst_b = ofst * std::mem::size_of::<T>();
        let len_b = std::mem::size_of_val(data);

        let bid_start = ofst_b / HBM_CHUNK_SIZE_B;
        let bid_stop = (ofst_b + len_b) / HBM_CHUNK_SIZE_B;
        let mut bid_ofst = ofst_b % HBM_CHUNK_SIZE_B;

        let mut bid_addr = self.chunk.keys().collect::<Vec<_>>();
        bid_addr.sort();

        let mut rmn_data = len_b;
        let mut data_ofst = 0;

        let data_bytes = bytemuck::cast_slice_mut::<T, u8>(data);
        for addr in bid_addr[bid_start..=bid_stop].iter() {
            let size_b = std::cmp::min(rmn_data, HBM_CHUNK_SIZE_B - bid_ofst);
            let chunk = self.chunk.get(addr).unwrap();
            data_bytes[data_ofst..data_ofst + size_b].copy_from_slice(&chunk.data[0..size_b]);
            data_ofst += size_b;
            rmn_data -= size_b;
            bid_ofst = 0;
        }
    }
}
