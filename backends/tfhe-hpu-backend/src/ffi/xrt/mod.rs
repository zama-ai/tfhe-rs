use super::*;

// Exposed types
pub use extern_cxx::{new_hpu_hw, HpuHw, MemZone, MemZonePropertiesCxx, SyncModeCxx, VerbosityCxx};

#[cxx::bridge(namespace=ffi)]
mod extern_cxx {
    /// Enumeration to define the synchronisation of data between Host and Device
    #[derive(Debug, Clone)]
    enum SyncModeCxx {
        Host2Device,
        Device2Host,
    }

    /// Enumeration to define the verbosity in Cxx bridge
    #[derive(Debug, Clone)]
    #[repr(u8)]
    enum VerbosityCxx {
        Error = 0,
        Warning,
        Info,
        Debug,
        Trace,
    }

    /// Define memory zone properties
    #[derive(Debug, Clone)]
    struct MemZonePropertiesCxx {
        hbm_pc: usize,
        size_b: usize,
    }

    unsafe extern "C++" {
        include!("tfhe-hpu-backend/src/ffi/xrt/cxx/hpu_hw.h");

        // Use Opaque Cxx type
        type HpuHw;

        // Access Hw register
        fn read_reg(self: &HpuHw, addr: u64) -> u32;
        fn write_reg(self: Pin<&mut HpuHw>, addr: u64, value: u32);

        // Handle onbeard memory
        fn alloc(self: Pin<&mut HpuHw>, props: MemZonePropertiesCxx) -> UniquePtr<MemZone>;
        // fn release(self: Pin<&mut HpuHw>, zone: &MemZone);

        fn new_hpu_hw(
            fpga_id: u32,
            kernel_name: String,
            xclbin: String,
            verbose: VerbosityCxx,
        ) -> UniquePtr<HpuHw>;
    }

    unsafe extern "C++" {
        include!("tfhe-hpu-backend/src/ffi/xrt/cxx/mem_zone.h");

        // Use Opaque Cxx type
        type MemZone;

        fn read_bytes(&self, ofst: usize, bytes: &mut [u8]);
        fn paddr(&self) -> u64;
        #[allow(unused)]
        fn size(&self) -> usize;
        fn write_bytes(self: Pin<&mut MemZone>, ofst: usize, bytes: &[u8]);
        #[allow(unused)]
        fn mmap(self: Pin<&mut MemZone>) -> &mut [u64];
        fn sync(self: Pin<&mut MemZone>, mode: SyncModeCxx);
    }
}

/// Provide conversion between global SyncMode and Cxx version
impl From<SyncMode> for SyncModeCxx {
    fn from(value: SyncMode) -> Self {
        match value {
            SyncMode::Host2Device => Self::Host2Device,
            SyncMode::Device2Host => Self::Device2Host,
        }
    }
}

/// Provide conversion between global MemZoneProperties and Cxx version
impl From<MemZoneProperties> for MemZonePropertiesCxx {
    fn from(value: MemZoneProperties) -> Self {
        let hbm_pc = match value.mem_kind {
            MemKind::Ddr { .. } => {
                panic!("XRT don't support DDR allocation. Only Hbm is available on board")
            }
            MemKind::Hbm { pc } => pc,
        };
        Self {
            hbm_pc,
            size_b: value.size_b,
        }
    }
}
