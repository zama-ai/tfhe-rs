//!
//! Structure used to handle memory associated with Bsk/Ksk
//! Huge memory are composed of multiple cut. Furthermore, each cut is allocated on a set of
//! fix-size buffer. This is to mitigate a limitation of XRT memory allocation.

use crate::ffi;

// Some XRT constants
// Use to circumvent current XRT limitation with huge buffer
// Any buffer is sliced into chunk of at max MEM_CHUNK_SIZE to prevent issue with XRT allocator
#[allow(unused)]
const MEM_BANK_SIZE_MB: usize = 512;
const MEM_CHUNK_SIZE_B: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct HugeMemoryProperties {
    pub mem_cut: Vec<ffi::MemKind>,
    pub cut_coefs: usize,
}

pub struct HugeMemory<T: Sized> {
    cut_coefs: usize,
    cut_mem: Vec<Vec<ffi::MemZone>>,
    phantom: std::marker::PhantomData<T>,
}
impl<T: Sized> std::fmt::Debug for HugeMemory<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HugeMemory<elem_size={}>{{cut_coefs: {}}}",
            std::mem::size_of::<T>(),
            self.cut_coefs
        )
    }
}

impl<T: Sized + bytemuck::Pod> HugeMemory<T> {
    /// This function allocate a set of memzone to store HugeMemory block
    /// HugeMemory block is spread over multiple Hbm cut. Furthermore, due to size and XRT
    /// limitation each cut is split on multiple buffer of 16MiB.
    /// We allocate 16MiB buffer only ( the last one isn't shrunk to fit the required memory size)
    #[tracing::instrument(level = "trace", skip(ffi_hw), ret)]
    pub fn alloc(ffi_hw: &mut ffi::HpuHw, props: HugeMemoryProperties) -> Self {
        assert_eq!(
            0,
            MEM_CHUNK_SIZE_B % std::mem::size_of::<T>(),
            "Word width must divide MEM_CHUNK_SIZE_B"
        );

        let all_chunks =
            usize::div_ceil(props.cut_coefs * std::mem::size_of::<T>(), MEM_CHUNK_SIZE_B);

        let mut cut_mem = Vec::new();
        for mem_kind in props.mem_cut.into_iter() {
            let mut cut_mz = Vec::new();
            let mut cur_mem_kind = mem_kind;

            for _chunk in 0..all_chunks {
                let chunk_props = ffi::MemZoneProperties {
                    mem_kind: cur_mem_kind,
                    size_b: MEM_CHUNK_SIZE_B,
                };
                // Update mem_kind if needed (i.e. update DDR offset for next chunk
                cur_mem_kind = match cur_mem_kind {
                    ffi::MemKind::Ddr { offset } => ffi::MemKind::Ddr {
                        offset: offset + MEM_CHUNK_SIZE_B,
                    },
                    ffi::MemKind::Hbm { .. } => cur_mem_kind,
                };
                let mz = ffi_hw.alloc(chunk_props);
                cut_mz.push(mz);
            }

            // Sanity check
            // cut buffer must be contiguous in memory
            let base_addr = cut_mz[0].paddr();
            for (i, mz) in cut_mz[1..].iter().enumerate() {
                let cont_addr = base_addr + ((i + 1) * MEM_CHUNK_SIZE_B) as u64;
                let real_addr = mz.paddr();
                assert_eq!(
                    cont_addr, real_addr,
                    "HugeMemory chunk weren't contiguous in memory"
                );
            }

            cut_mem.push(cut_mz);
        }
        Self {
            cut_mem,
            cut_coefs: props.cut_coefs,
            phantom: std::marker::PhantomData::<T>,
        }
    }

    /// This function release associated memzone
    #[tracing::instrument(level = "trace", skip(ffi_hw), ret)]
    pub fn release(&mut self, ffi_hw: &mut ffi::HpuHw) {
        self.cut_mem
            .iter_mut()
            .flatten()
            .for_each(|mz| ffi_hw.release(mz));
    }

    /// Write data slice into memory cut_id
    /// NB: User specify offset in unit of data.
    #[tracing::instrument(level = "trace", skip(data), ret)]
    pub fn write_cut_at(&mut self, cut_id: usize, ofst: usize, data: &[T]) {
        assert!(
            ofst + data.len() <= self.cut_coefs,
            "Invalid write size. Write stop beyond the HugeMemory boundaries"
        );
        let cut = self
            .cut_mem
            .get_mut(cut_id)
            .unwrap_or_else(|| panic!("Invalid cut_id: {cut_id}"));

        // Underlying memory is view as bytes memory
        // Extract byte ofst and byte length
        // NB: Don't use generic write method to prevent misunderstanding of ofst meaning
        // Indeed, we must used a bytes offset to compute the sub-bfr id and thus keep a
        // byte approach everywhere to prevent mismatch
        let ofst_b = ofst * std::mem::size_of::<T>();
        let len_b = std::mem::size_of_val(data);

        let bid_start = ofst_b / MEM_CHUNK_SIZE_B;
        let bid_stop = (ofst_b + len_b) / MEM_CHUNK_SIZE_B;
        let mut bid_ofst = ofst_b % MEM_CHUNK_SIZE_B;

        let mut rmn_data = len_b;
        let mut data_ofst = 0;

        let data_bytes = bytemuck::cast_slice::<T, u8>(data);
        for bfr in cut[bid_start..=bid_stop].iter_mut() {
            let size_b = std::cmp::min(rmn_data, MEM_CHUNK_SIZE_B - bid_ofst);
            bfr.write_bytes(bid_ofst, &data_bytes[data_ofst..data_ofst + size_b]);
            bfr.sync(ffi::SyncMode::Host2Device);
            data_ofst += size_b;
            rmn_data -= size_b;
            bid_ofst = 0;
        }
    }

    /// Read data slice from memory cut_id
    /// NB: User specify offset in unit of data.
    #[tracing::instrument(level = "trace", skip(data), ret)]
    #[allow(dead_code)]
    pub fn read_cut_at(&mut self, cut_id: usize, ofst: usize, data: &mut [T]) {
        assert!(
            ofst + data.len() <= self.cut_coefs,
            "Invalid read size. Read stop beyond the HugeMemory boundaries"
        );
        let cut = self.cut_mem.get_mut(cut_id).expect("Invalid cut_id");

        // Underlying memory is view as bytes memory
        // Extract byte ofst and byte length
        // NB: Don't use generic write method to prevent misunderstanding of ofst meaning
        // Indeed, we must used a bytes offset to compute the sub-bfr id and thus keep a
        // byte approach everywhere to prevent mismatch
        let ofst_b = ofst * std::mem::size_of::<T>();
        let len_b = std::mem::size_of_val(data);

        let bid_start = ofst_b / MEM_CHUNK_SIZE_B;
        let bid_stop = (ofst_b + len_b) / MEM_CHUNK_SIZE_B;
        let mut bid_ofst = ofst_b % MEM_CHUNK_SIZE_B;

        let mut rmn_data = len_b;
        let mut data_ofst = 0;

        let data_bytes = bytemuck::cast_slice_mut::<T, u8>(data);
        for bfr in cut[bid_start..=bid_stop].iter_mut() {
            let size_b = std::cmp::min(rmn_data, MEM_CHUNK_SIZE_B - bid_ofst);
            bfr.sync(ffi::SyncMode::Device2Host);
            bfr.read_bytes(bid_ofst, &mut data_bytes[data_ofst..data_ofst + size_b]);
            data_ofst += size_b;
            rmn_data -= size_b;
            bid_ofst = 0;
        }
    }

    /// Return paddr of cuts
    /// Use paddr of first buffer for Hw configuration
    #[tracing::instrument(level = "trace", ret)]
    pub fn cut_paddr(&self) -> Vec<u64> {
        self.cut_mem
            .iter()
            .map(|cut| cut[0].paddr())
            .collect::<Vec<_>>()
    }
}
