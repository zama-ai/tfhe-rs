//! This ffi layer implement a wrapper around multiple ffi implementation
//! The aim is to completely hide underlying specificities and enable compile-time
//! swapping.
//!
//! Mainly replacing V80 by a simulation interface to ease CI

use crate::interface::FFIMode;

mod mem_alloc;
use mem_alloc::{MemAlloc, MemChunk};

/// Specify kind of the target memory
/// Used for target that has DDR and HBM
/// Hbm is targeted based on attach PC number, the DDR otherwise is targeted based on offset
/// For the sake of simplicity and prevent issue with large xfer, memory is always viewed as a chunk
/// of 16MiB
/// NB: This is inherited from XRT allocator limitation...
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum MemKind {
    Ddr { offset: usize },
    Hbm { pc: usize },
}

/// Define memory zone properties
#[derive(Debug, Clone, Copy)]
pub struct MemZoneProperties {
    pub mem_kind: MemKind,
    pub size_b: usize,
}

pub struct HpuHw(
    #[cfg(feature = "hw-v80")] v80::HpuHw,
    #[cfg(not(feature = "hw-v80"))] sim::HpuHw,
);

impl HpuHw {
    /// Function used to lazily load Hw
    /// It should probe the Hw state and reload it if required
    pub fn lazy_load(id: u8, mode: &FFIMode, force_reload: bool) -> bool {
        #[cfg(feature = "hw-v80")]
        {
            match mode {
                FFIMode::V80 {
                    hpu_path,
                    board_dev_sn,
                    ami_path,
                } => {
                    let (pcie_id, board_sn) = {
                        let (id, sn) = board_dev_sn
                            .get(id as usize)
                            .expect("Request invalid board id");
                        (id.expand(), sn.expand())
                    };
                    v80::HpuHw::lazy_load(
                        &pcie_id,
                        &board_sn,
                        &hpu_path.expand(),
                        &ami_path.expand(),
                        force_reload,
                    )
                }
                _ => panic!("Unsupported config type with ffi::v80"),
            }
        }
        #[cfg(not(feature = "hw-v80"))]
        {
            let _id = id;
            let _mode = mode;
            force_reload
        }
    }

    pub fn cfg_dma(id: u8, mode: &FFIMode) {
        #[cfg(feature = "hw-v80")]
        {
            match mode {
                FFIMode::V80 { board_dev_sn, .. } => {
                    let pcie_id = {
                        let (id, _sn) = board_dev_sn
                            .get(id as usize)
                            .expect("Request invalid board id");
                        id.expand()
                    };
                    v80::HpuHw::cfg_dma_queues(&pcie_id)
                }
                _ => panic!("Unsupported config type with ffi::v80"),
            }
        }
        #[cfg(not(feature = "hw-v80"))]
        {
            let _id = id;
            let _mode = mode;
        }
    }

    /// Read Hw register through ffi
    #[inline(always)]
    pub fn read_reg(&self, addr: u64) -> u32 {
        #[cfg(feature = "hw-v80")]
        {
            self.0.ami.read_reg(addr)
        }

        #[cfg(not(feature = "hw-v80"))]
        {
            self.0.read_reg(addr)
        }
    }

    /// Write Hw register through ffi
    #[inline(always)]
    pub fn write_reg(&mut self, addr: u64, value: u32) {
        #[cfg(feature = "hw-v80")]
        {
            self.0.ami.write_reg(addr, value)
        }

        #[cfg(not(feature = "hw-v80"))]
        {
            self.0.write_reg(addr, value)
        }
    }

    /// Handle on-board memory init through ffi
    #[inline(always)]
    #[allow(unused_variables)]
    pub fn init_mem(
        &mut self,
        config: &crate::interface::HpuConfig,
        params: &crate::entities::HpuParameters,
    ) {
        self.0.init_mem(config, params)
    }
    /// Handle on-board memory allocation through ffi
    #[inline(always)]
    pub fn alloc(&mut self, props: MemZoneProperties) -> MemZone {
        MemZone(self.0.alloc(props))
    }

    /// Handle on-board memory deallocation through ffi
    #[inline(always)]
    #[allow(unused_variables)]
    pub fn release(&mut self, zone: &mut MemZone) {
        self.0.release(&mut zone.0);
    }

    /// Handle ffi instantiation
    #[inline(always)]
    pub fn open_hpu_hw(
        id: u8,
        mode: &FFIMode,
        #[allow(unused)] retry_rate: std::time::Duration,
    ) -> HpuHw {
        #[cfg(feature = "hw-v80")]
        {
            match mode {
                FFIMode::V80 {
                    hpu_path,
                    board_dev_sn,
                    ..
                } => {
                    let pcie_id = {
                        let (id, _sn) = board_dev_sn
                            .get(id as usize)
                            .expect("Request invalid board id");
                        id.expand()
                    };
                    Self(
                        v80::HpuHw::open_hpu_hw(&pcie_id, &hpu_path.expand(), retry_rate)
                            .expect("Error with hpu_hw opening"),
                    )
                }
                _ => panic!("Unsupported config type with ffi::v80"),
            }
        }

        #[cfg(not(feature = "hw-v80"))]
        {
            match mode {
                FFIMode::Sim {
                    ipc_name,
                    iopq,
                    ackq,
                } => Self(sim::HpuHw::open_hpu_hw(id, &ipc_name.expand(), iopq, ackq)),
                _ => panic!("Unsupported config type with ffi::sim"),
            }
        }
    }

    /// Custom command only supported on V80 to push work
    pub fn iop_push(&mut self, stream: &[u32]) {
        #[cfg(feature = "hw-v80")]
        {
            self.0.ami.iop_push(stream)
        }

        #[cfg(not(feature = "hw-v80"))]
        {
            self.0.iop_push(stream).expect("Handle queue")
        }
    }

    /// Custom command only supported on V80 to push work
    #[cfg(feature = "hw-v80")]
    pub fn dop_push(&mut self, stream: &[u32]) {
        self.0.ami.dop_push(stream)
    }

    /// Custom command only supported on V80 to rd_ack
    pub fn iop_ack_rd(&mut self) -> u32 {
        #[cfg(feature = "hw-v80")]
        {
            self.0.ami.iop_ackq_rd()
        }

        #[cfg(not(feature = "hw-v80"))]
        {
            self.0.iop_ackq_rd()
        }
    }
}

pub struct MemZone(
    #[cfg(feature = "hw-v80")] v80::MemZone,
    #[cfg(not(feature = "hw-v80"))] sim::MemZone,
);

impl MemZone {
    /// Read a bytes slice in the associated MemZone
    #[inline(always)]
    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        self.0.read_bytes(ofst, bytes);
    }

    /// Get physical MemZone address
    #[inline(always)]
    pub fn paddr(&self) -> u64 {
        self.0.paddr()
    }

    /// Get MemZone size in byte
    #[inline(always)]
    #[allow(unused)]
    pub fn size(&self) -> usize {
        self.0.size()
    }

    /// Get write byte slice in MemZone at a given offset
    #[inline(always)]
    pub fn write_bytes(&mut self, ofst: usize, bytes: &[u8]) {
        self.0.write_bytes(ofst, bytes)
    }
}

/// Generic function to easily handle multiple word size
impl MemZone {
    pub fn read<T: Sized + bytemuck::Pod>(&self, ofst: usize, data: &mut [T]) {
        let data_bytes = bytemuck::cast_slice_mut::<T, u8>(data);
        let ofst_bytes = ofst * std::mem::size_of::<T>();
        self.read_bytes(ofst_bytes, data_bytes);
    }

    pub fn write<T: Sized + bytemuck::Pod>(&mut self, ofst: usize, data: &[T]) {
        let data_bytes = bytemuck::cast_slice::<T, u8>(data);
        let ofst_bytes = ofst * std::mem::size_of::<T>();
        self.write_bytes(ofst_bytes, data_bytes);
    }
}

#[cfg(feature = "hw-v80")]
mod v80;
#[cfg(all(feature = "hw-v80", feature = "utils"))]
pub use v80::HpuV80Pdi;

#[cfg(not(feature = "hw-v80"))]
pub(crate) mod sim;
