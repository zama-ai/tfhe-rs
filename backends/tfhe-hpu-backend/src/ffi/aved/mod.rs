//! Implement Aved driver abstraction
//!
//! Aved rely on 2 driver for communication
//! * Register access/Rpu interaction -> AMI
//! * Data xfer -> QDMA

use crate::ffi;

use std::sync::{Arc, Mutex};

mod ami;
use ami::AmiDriver;

mod mem_alloc;
use mem_alloc::{MemAlloc, MemChunk};

mod qdma;
use qdma::QdmaDriver;

pub struct HpuHw {
    pub(super) ami: AmiDriver,
    pub(super) qdma: Arc<Mutex<QdmaDriver>>,
    allocator: Option<MemAlloc>,
}

impl HpuHw {
    /// Handle ffi instantiation
    #[inline(always)]
    pub fn new_hpu_hw(
        ami_path: &str,
        ami_retry: std::time::Duration,
        h2c_path: &str,
        c2h_path: &str,
    ) -> HpuHw {
        Self {
            ami: AmiDriver::new(ami_path, ami_retry),
            qdma: Arc::new(Mutex::new(QdmaDriver::new(h2c_path, c2h_path))),
            allocator: None,
        }
    }

    pub fn init_mem(
        &mut self,
        config: &crate::interface::HpuConfig,
        params: &crate::entities::HpuParameters,
    ) {
        assert!(
            self.allocator.is_none(),
            "Error: Double request of HpuHw memory initialisation"
        );
        self.allocator = Some(MemAlloc::new(config, params));
    }

    /// Handle on-board memory allocation
    pub fn alloc(&mut self, props: ffi::MemZoneProperties) -> MemZone {
        let chunks = self
            .allocator
            .as_mut()
            .expect("Error: Aved backend memory must be explicitly init (c.f. init_mem)")
            .alloc(&props);
        MemZone::new(props.mem_kind, chunks[0].paddr, chunks, self.qdma.clone())
    }
    /// Handle on-board memory de-allocation
    pub fn release(&mut self, zone: &mut MemZone) {
        let MemZone { kind, chunks, .. } = zone;
        self.allocator
            .as_mut()
            .expect("Error: Aved backend memory must be explicitly init (c.f. init_mem)")
            .release(kind, chunks)
    }
}

pub struct MemZone {
    // Link properties
    kind: ffi::MemKind,
    addr: u64,
    chunks: Vec<MemChunk>,

    // Ref to Qdma driver
    qdma: Arc<Mutex<QdmaDriver>>,
}

impl MemZone {
    pub fn new(
        kind: ffi::MemKind,
        addr: u64,
        chunks: Vec<MemChunk>,
        qdma: Arc<Mutex<QdmaDriver>>,
    ) -> Self {
        Self {
            kind,
            addr,
            chunks,
            qdma,
        }
    }

    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        let qdma = self.qdma.lock().unwrap();
        qdma.read_bytes(ofst + self.addr as usize, bytes)
    }

    pub fn paddr(&self) -> u64 {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.size_b).sum()
    }

    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        let qdma = self.qdma.lock().unwrap();
        qdma.write_bytes(ofst + self.addr as usize, bytes)
    }
}
