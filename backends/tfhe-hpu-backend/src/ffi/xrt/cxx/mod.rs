use super::*;

#[cxx::bridge(namespace=ffi)]
mod extern_cxx {
    /// Enumeration to define the synchronisation of data between Host and Device
    #[derive(Debug, Clone)]
    enum SyncMode {
        Host2Device,
        Device2Host,
    }

    /// Enumeration to define the verbosity in Cxx bridge
    #[derive(Debug, Clone)]
    #[repr(u8)]
    enum Verbosity {
        Error = 0,
        Warning,
        Info,
        Debug,
        Trace,
    }

    unsafe extern "C++" {
        include!("hpu_hw.h");

        type HpuHw;
        // Access Hw register
        fn read_reg(&self, addr: u64) -> u32;
        fn write_reg(self: Pin<&mut HpuHw>, addr: u64, value: u32);

        // Handle onbeard memory
        fn alloc(self: Pin<&mut HpuHw>, props: MemZoneProperties) -> UniquePtr<MemZone>;
        // fn release(self: Pin<&mut HpuHw>, zone: &MemZone);

        fn new_hpu_hw(
            fpga_id: u32,
            kernel_name: String,
            xclbin: String,
            verbose: Verbosity,
        ) -> UniquePtr<HpuHw>;
    }

    /// Define memory zone properties
    #[derive(Debug, Clone)]
    struct MemZoneProperties {
        hbm_pc: usize,
        size_b: usize,
    }

    unsafe extern "C++" {
        include!("tfhe-hpu-backend/src/ffi/cxx/mem_zone.h");

        type MemZone;

        fn read_bytes(&self, ofst: usize, bytes: &mut [u8]);
        fn paddr(&self) -> u64;
        #[allow(unused)]
        fn size(&self) -> usize;
        fn write_bytes(self: Pin<&mut MemZone>, ofst: usize, bytes: &[u8]);
        #[allow(unused)]
        fn mmap(self: Pin<&mut MemZone>) -> &mut [u64];
        fn sync(self: Pin<&mut MemZone>, mode: SyncMode);
    }
}

/// Generic function to easily handle multiple word size
impl MemZone {
    pub fn read<T: Sized + bytemuck::Pod>(&self, ofst: usize, data: &mut [T]) {
        let data_bytes = bytemuck::cast_slice_mut::<T, u8>(data);
        let ofst_bytes = ofst * std::mem::size_of::<T>();
        self.read_bytes(ofst_bytes, data_bytes);
    }

    pub fn write<T: Sized + bytemuck::Pod>(self: Pin<&mut MemZone>, ofst: usize, data: &[T]) {
        let data_bytes = bytemuck::cast_slice::<T, u8>(data);
        let ofst_bytes = ofst * std::mem::size_of::<T>();
        self.write_bytes(ofst_bytes, data_bytes);
    }
}
