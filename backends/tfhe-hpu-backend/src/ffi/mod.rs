//! This ffi layer implement a wrapper around multiple ffi implementation
//! The aim is to completely hide underlying specificities and enable compile-time
//! swapping.
//!
//! Mainly replacing V80 by a simulation interface to ease CI

use crate::interface::FFIMode;

mod mem_alloc;
use mem_alloc::{MemAlloc, MemChunk};

// Some V80 constants
// Chunk_size inherited from XRT limitation
// NB: In Xilinx v80 implementation the HBM PC are not directly accessible.
// Indeed, there is an extra level of abstraction called port:
// Each HBM has 2 PC, and each PC has 2 Port.
// To keep thing simple this is hided from the SW, thus instead of viewing the board memory as:
//  * 2HBM with 8Bank each and 2PC per bank -> 32 memory
// It's seen as:
// * 2HBM with 8Bank each and 4PC per bank -> 64PC
pub const MEM_BANK_NB: usize = 64;
pub const MEM_BANK_SIZE_MB: usize = 512;
pub const MEM_CHUNK_SIZE_B: usize = 16 * 1024 * 1024;
pub const MEM_BASE_ADDR: u64 = 0x40_0000_0000;

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
    pub fn lazy_load(node_id: &[u8], mode: &FFIMode, force_reload: bool) {
        #[cfg(feature = "hw-v80")]
        {
            match mode {
                FFIMode::V80 { hpu_path, ami_path } => {
                    let board_dev_sn =
                        v80::get_board_dev_sn().expect("Error with V80_BOARD definition");
                    let dev_sn = node_id
                        .iter()
                        .map(|id| {
                            let (pcie_id, sn) = board_dev_sn
                                .get(*id as usize)
                                .expect("Request invalid board id");
                            (pcie_id.clone(), sn.clone())
                        })
                        .collect::<Vec<_>>();
                    v80::HpuHw::lazy_load(
                        dev_sn,
                        &hpu_path.expand(),
                        &ami_path.expand(),
                        force_reload,
                    );
                }
                _ => panic!("Unsupported config type with ffi::v80"),
            }
        }
        #[cfg(not(feature = "hw-v80"))]
        {
            let _node_id = node_id;
            let _mode = mode;
            let _force_reload = force_reload;
        }
    }

    pub fn get_mac_list() -> Vec<(String, String)> {
        #[cfg(feature = "hw-v80")]
        {
            v80::get_boards_mac().expect("Error with V80_BOARDS_MAC definition")
        }
        #[cfg(not(feature = "hw-v80"))]
        {
            Vec::new()
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

    /// Absolute read without preallocation
    /// Allocation was inherited from XRT not needed anymore
    pub fn read_abs<T: Sized + bytemuck::Pod>(&self, addr: u64, data: &mut [T]) {
        let data_bytes = bytemuck::cast_slice_mut::<T, u8>(data);
        self.0.read_abs_bytes(addr, data_bytes);
    }

    pub fn write_abs<T: Sized + bytemuck::Pod>(&mut self, addr: u64, data: &[T]) {
        let data_bytes = bytemuck::cast_slice::<T, u8>(data);
        self.0.write_abs_bytes(addr, data_bytes);
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
                FFIMode::V80 { hpu_path, .. } => {
                    let board_dev_sn =
                        v80::get_board_dev_sn().expect("Error with V80_BOARD definition");
                    let pcie_id = {
                        let (id, _sn) = board_dev_sn
                            .get(id as usize)
                            .expect("Request invalid board id");
                        id.clone()
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
