//! This ffi layer implement a wrapper around multiple ffi implementation
//! The aim is to completely hide underlying specificities and enable compile-time
//! swapping.
//!
//! Mainly replacing V80 by a simulation interface to ease CI

use crate::interface::FFIMode;

#[cfg(feature = "hw-v80")]
use crate::prelude::ShellString;

/// Enumeration to define the synchronisation of data between Host and Device
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum SyncMode {
    Host2Device,
    Device2Host,
}

/// Specify kind of the target memory
/// Used for target that has DDR and HBM
/// Hbm is targeted based on attach PC number, the DDR otherwise is targeted based on offset
/// For the sake of simplicity and prevent issue with large xfer, memory is always viewed as a chunk
/// of 16MiB This is inherited from XRT allocator limitation...
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
    #[cfg(feature = "hw-xrt")] cxx::UniquePtr<xrt::HpuHw>,
    #[cfg(feature = "hw-v80")] v80::HpuHw,
    #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))] sim::HpuHw,
);

impl HpuHw {
    /// Read Hw register through ffi
    #[inline(always)]
    pub fn read_reg(&self, addr: u64) -> u32 {
        #[cfg(feature = "hw-xrt")]
        {
            self.0.read_reg(addr)
        }

        #[cfg(feature = "hw-v80")]
        {
            self.0.ami.read_reg(addr)
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            self.0.read_reg(addr)
        }
    }

    /// Write Hw register through ffi
    #[inline(always)]
    pub fn write_reg(&mut self, addr: u64, value: u32) {
        #[cfg(feature = "hw-xrt")]
        {
            self.0.pin_mut().write_reg(addr, value)
        }

        #[cfg(feature = "hw-v80")]
        {
            self.0.ami.write_reg(addr, value)
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
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
        // NB: Currently only v80 backend required explicit memory init
        #[cfg(feature = "hw-v80")]
        {
            self.0.init_mem(config, params);
        }
    }
    /// Handle on-board memory allocation through ffi
    #[inline(always)]
    pub fn alloc(&mut self, props: MemZoneProperties) -> MemZone {
        #[cfg(feature = "hw-xrt")]
        {
            let xrt_mz = self.0.pin_mut().alloc(props.into());
            MemZone(xrt_mz)
        }

        #[cfg(feature = "hw-v80")]
        {
            MemZone(self.0.alloc(props))
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            MemZone(self.0.alloc(props))
        }
    }

    /// Handle on-board memory deallocation through ffi
    #[inline(always)]
    #[allow(unused_variables)]
    pub fn release(&mut self, zone: &mut MemZone) {
        // #[cfg(feature = "hw-xrt")]
        // {
        //     todo!("Handle memory release");
        // }

        #[cfg(feature = "hw-v80")]
        {
            self.0.release(&mut zone.0);
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            self.0.release(&mut zone.0);
        }
    }

    /// Handle ffi instantiation
    #[inline(always)]
    pub fn new_hpu_hw(mode: &FFIMode, #[allow(unused)] retry_rate: std::time::Duration) -> HpuHw {
        #[cfg(feature = "hw-xrt")]
        {
            use tracing::{enabled, Level};
            // Check config
            match mode {
                FFIMode::Xrt { id, kernel, xclbin } => {
                    // Extract trace verbosity and convert it in cxx understandable value
                    let verbosity = {
                        if enabled!(target: "cxx", Level::TRACE) {
                            xrt::VerbosityCxx::Trace
                        } else if enabled!(target: "cxx", Level::DEBUG) {
                            xrt::VerbosityCxx::Debug
                        } else if enabled!(target: "cxx", Level::INFO) {
                            xrt::VerbosityCxx::Info
                        } else if enabled!(target: "cxx", Level::WARN) {
                            xrt::VerbosityCxx::Warning
                        } else {
                            xrt::VerbosityCxx::Error
                        }
                    };
                    Self(xrt::new_hpu_hw(
                        *id,
                        kernel.expand(),
                        xclbin.expand(),
                        verbosity,
                    ))
                }
                _ => panic!("Unsupported config type with ffi::xrt"),
            }
        }

        #[cfg(feature = "hw-v80")]
        {
            match mode {
                FFIMode::V80 {
                    id,
                    board_sn,
                    hpu_path,
                    ami_path,
                    qdma_h2c,
                    qdma_c2h,
                    force_reload,
                } => Self(v80::HpuHw::new_hpu_hw(
                    &id.expand(),
                    &board_sn.expand(),
                    &hpu_path.expand(),
                    &ami_path.expand(),
                    retry_rate,
                    &qdma_h2c.expand(),
                    &qdma_c2h.expand(),
                    &force_reload
                        .clone()
                        .unwrap_or_else(|| ShellString::new("false".into()))
                        .expand(),
                )),
                _ => panic!("Unsupported config type with ffi::v80"),
            }
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            match mode {
                FFIMode::Sim { ipc_name } => Self(sim::HpuHw::new_hpu_hw(&ipc_name.expand())),
                _ => panic!("Unsupported config type with ffi::sim"),
            }
        }
    }

    /// Custom register command to retrieved custom parameters set from mockup.
    /// Only available with mockup FFI
    #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
    pub fn get_pbs_parameters(&mut self) -> crate::entities::HpuPBSParameters {
        self.0.get_pbs_parameters()
    }

    /// Custom command only supported on V80 to push work
    #[cfg(feature = "hw-v80")]
    pub fn iop_push(&mut self, stream: &[u32]) {
        self.0.ami.iop_push(stream)
    }

    /// Custom command only supported on V80 to push work
    #[cfg(feature = "hw-v80")]
    pub fn dop_push(&mut self, stream: &[u32]) {
        self.0.ami.dop_push(stream)
    }

    /// Custom command only supported on V80 to rd_ack
    #[cfg(feature = "hw-v80")]
    pub fn iop_ack_rd(&mut self) -> u32 {
        self.0.ami.iop_ackq_rd()
    }

    #[cfg(feature = "hw-v80")]
    pub fn map_bar_reg(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.0.ami.map_bar_reg()
    }
}

pub struct MemZone(
    #[cfg(feature = "hw-xrt")] cxx::UniquePtr<xrt::MemZone>,
    #[cfg(feature = "hw-v80")] v80::MemZone,
    #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))] sim::MemZone,
);

// With Xrt backend, Opaque Cxx Object prevent compiler to auto impl Send+Sync
// However, it's safe to implement them
#[cfg(feature = "hw-xrt")]
unsafe impl Send for MemZone {}
#[cfg(feature = "hw-xrt")]
unsafe impl Sync for MemZone {}

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
        #[cfg(feature = "hw-xrt")]
        {
            self.0.pin_mut().write_bytes(ofst, bytes)
        }

        #[cfg(feature = "hw-v80")]
        {
            self.0.write_bytes(ofst, bytes)
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            self.0.write_bytes(ofst, bytes)
        }
    }

    /// Map MemZone in userspace
    #[inline(always)]
    #[allow(unused)]
    pub fn mmap(&mut self) -> &mut [u64] {
        #[cfg(feature = "hw-xrt")]
        {
            self.0.pin_mut().mmap()
        }

        #[cfg(feature = "hw-v80")]
        {
            panic!("V80 ffi rely on QDMA and couldn't implement mmap")
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            self.0.mmap()
        }
    }

    /// Handle MemZone synchronisation with the hw target
    #[inline(always)]
    #[allow(unused)]
    pub fn sync(&mut self, mode: SyncMode) {
        #[cfg(feature = "hw-xrt")]
        {
            self.0.pin_mut().sync(mode.into())
        }

        #[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
        {
            self.0.sync(mode)
        }
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

#[cfg(feature = "hw-xrt")]
mod xrt;

#[cfg(not(any(feature = "hw-xrt", feature = "hw-v80")))]
pub(crate) mod sim;
