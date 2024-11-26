//! This ffi layer implement a wrapper around multiple ffi implementation
//! Aims is to completly hide underlying specificities and enable compile-time
//! swapping.
//!
//! Mainly replacing Xrt(u55c)/Aved(V80) by a simulation interface for ease CI

use crate::interface::FFIMode;

/// Enumeration to define the synchronisation of data between Host and Device
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SyncMode {
    Host2Device,
    Device2Host,
}

/// Define memory zone properties
#[derive(Debug, Clone)]
pub struct MemZoneProperties {
    pub hbm_pc: usize,
    pub size_b: usize,
}

pub struct HpuHw(
    #[cfg(feature = "hw-xrt")] cxx::UniquePtr<xrt::HpuHw>,
    #[cfg(not(feature = "hw-xrt"))] sim::HpuHw,
);

impl HpuHw {
    /// Read Hw register through ffi
    #[inline(always)]
    pub fn read_reg(&self, addr: u64) -> u32 {
        self.0.read_reg(addr)
    }

    /// Write Hw register through ffi
    #[inline(always)]
    pub fn write_reg(&mut self, addr: u64, value: u32) {
        #[cfg(feature = "hw-xrt")]
        {
            self.0.pin_mut().write_reg(addr, value)
        }

        #[cfg(not(feature = "hw-xrt"))]
        {
            self.0.write_reg(addr, value)
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

        #[cfg(not(feature = "hw-xrt"))]
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

        #[cfg(not(feature = "hw-xrt"))]
        {
            self.0.release(&mut zone.0);
        }
    }

    /// Handle ffi instanciation
    #[inline(always)]
    pub fn new_hpu_hw(mode: &FFIMode) -> HpuHw {
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
                        kernel.to_string(),
                        xclbin.to_string(),
                        verbosity,
                    ))
                }
                _ => panic!("Unsupported config type with ffi::xrt"),
            }
        }

        #[cfg(not(feature = "hw-xrt"))]
        {
            match mode {
                FFIMode::Sim { ipc_name } => Self(sim::HpuHw::new_hpu_hw(ipc_name)),
                _ => panic!("Unsupported config type with ffi::sim"),
            }
        }
    }

    /// Custom register command to retrived custom parameters set from mockup.
    /// Only available with mockup FFI
    #[cfg(not(feature = "hw-xrt"))]
    pub fn get_pbs_parameters(&mut self) -> crate::entities::HpuPBSParameters {
        self.0.get_pbs_parameters()
    }
}

pub struct MemZone(
    #[cfg(feature = "hw-xrt")] cxx::UniquePtr<xrt::MemZone>,
    #[cfg(not(feature = "hw-xrt"))] sim::MemZone,
);

impl MemZone {
    /// Read a bytes slice in the associated MemZone
    #[inline(always)]
    pub fn read_bytes(&self, ofst: usize, bytes: &mut [u8]) {
        self.0.read_bytes(ofst, bytes);
    }

    /// Get physical MemZone addresse
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

        #[cfg(not(feature = "hw-xrt"))]
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

        #[cfg(not(feature = "hw-xrt"))]
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

        #[cfg(not(feature = "hw-xrt"))]
        {
            self.0.sync(mode)
        }
    }
}

/// Generic function to easily handle mutiple word size
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

#[cfg(not(feature = "hw-xrt"))]
pub(crate) mod sim;
#[cfg(feature = "hw-xrt")]
mod xrt;
