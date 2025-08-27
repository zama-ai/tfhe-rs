use std::collections::HashMap;

use super::MemChunk;

#[allow(unused)]
const DDR_SIZE_B: usize = 4 * 1024 * 1024 * 1024;

pub(crate) struct DdrMem {
    chunk: HashMap<u64, MemChunk>,
}

impl DdrMem {
    pub fn new() -> Self {
        Self {
            chunk: HashMap::new(),
        }
    }
    pub(crate) fn alloc_at(&mut self, paddr: u64, size_b: usize) {
        // Check that required chunk is in the Ddr range
        assert!(
            (paddr as usize + size_b) < DDR_SIZE_B,
            "Error: Required chunk @0x{paddr:x}[0x{size_b}] is out of Ddr range [0x0, 0x{DDR_SIZE_B}]"
        );

        // Check collision with other chunk
        // It's not an hard error on real hardware, but handle it like this in the simulation
        // In any case multiple view of the same memory was not a good idea and could led to
        //  hard to debug issues
        let clash = self
            .chunk
            .iter()
            .filter(|(_addr, chunk)| paddr < (chunk.paddr + chunk.size_b as u64))
            .filter(|(_addr, chunk)| (paddr + size_b as u64) > chunk.paddr)
            .map(|(_addr, chunk)| chunk)
            .collect::<Vec<_>>();
        clash.iter().for_each(|chunk| {
            tracing::debug!(
                "Required Ddr allocation collide with chunk @0x{:x}[0x{:x}]",
                chunk.paddr,
                chunk.size_b
            )
        });
        assert!(
            clash.is_empty(),
            "Error: Ddr allocation @0x{paddr:x}[0x{size_b:x}] has {} collision. This is likely linked to the absence of a proper HpuDevice release in previous execution.",
            clash.len()
        );

        // allocate chunk and register it in hashmap
        let chunk = MemChunk::new(paddr, size_b);
        self.chunk.insert(paddr, chunk);
    }

    pub(crate) fn get_chunk(&self, addr: u64) -> &MemChunk {
        self.chunk.get(&addr).unwrap()
    }

    pub(crate) fn get_mut_chunk(&mut self, addr: u64) -> &mut MemChunk {
        self.chunk.get_mut(&addr).unwrap()
    }

    pub(crate) fn rm_chunk(&mut self, addr: u64) -> Option<MemChunk> {
        self.chunk.remove(&addr)
    }
}
