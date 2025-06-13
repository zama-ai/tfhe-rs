//! Implement a fake memory allocator for help bridging with the ffi API
//!
//! There is no memory allocator with the Qdma. Indeed, the all board memory could be
//! accessed through the driver.
//! However, in order to be mapped on the ffi API with fake an allocator. For this purpose
//! each HBM pc is view as a list of 16MiB chunks and register in a store
//! NB: 16MiB is selected as upper xfer bound to match the previous XRT limitations
//! Indeed, all the required logic is present in the backend driver to view any memspace as an
//! aggregation of 16MiB slices

use crate::entities::{hpu_big_lwe_ciphertext_size, HpuParameters};
use crate::ffi;
use crate::interface::{page_align, HpuConfig};

use std::collections::VecDeque;

// Some V80 constants
// Chunk_size inherited from XRT limitation
// NB: In Xilinx v80 implementation the HBM PC are not directly accessible.
// Indeed, there is an extra level of abstraction called port:
// Each HBM has 2 PC, and each PC has 2 Port.
// To keep thing simple this is hided from the SW, thus instead of viewing the board memory as:
//  * 2HBM with 8Bank each and 2PC per bank -> 32 memory
// It's seen as:
// * 2HBM with 8Bank each and 4PC per bank -> 64PC
const MEM_BANK_NB: usize = 64;
const MEM_BANK_SIZE_MB: usize = 512;
const MEM_CHUNK_SIZE_B: usize = 16 * 1024 * 1024;
const MEM_BASE_ADDR: u64 = 0x40_0000_0000;

#[derive(Debug, PartialOrd, PartialEq, Ord, Eq)]
pub struct MemChunk {
    pub(super) paddr: u64,
    pub(super) size_b: usize,
}

pub struct MemAlloc([VecDeque<MemChunk>; MEM_BANK_NB]);

impl MemAlloc {
    pub fn new(config: &HpuConfig, params: &HpuParameters) -> Self {
        // Extract Hbm pc used by ciphertext if any
        // For those bank, we use a different chunk size to match the ciphertext size
        // Also compute the chunk size that match with tfhe parameters
        let ct_pc = config
            .board
            .ct_pc
            .iter()
            .filter_map(|kind| match kind {
                ffi::MemKind::Ddr { .. } => None,
                ffi::MemKind::Hbm { pc } => Some(*pc as u64),
            })
            .collect::<Vec<_>>();

        let ct_chunk_b = page_align(
            hpu_big_lwe_ciphertext_size(params).div_ceil(params.pc_params.pem_pc)
                * std::mem::size_of::<u64>(),
        );

        let banks = (0..MEM_BANK_NB as u64)
            .map(|bank| {
                let bank_base_addr =
                    MEM_BASE_ADDR + bank * (MEM_BANK_SIZE_MB * (1024 * 1024)) as u64;
                if ct_pc.contains(&bank) {
                    // Allocation in this bank use small chunk that match ct cut_size
                    let bank_cut = (MEM_BANK_SIZE_MB * 1024 * 1024) / ct_chunk_b;
                    (0..bank_cut)
                        .map(|cut| MemChunk {
                            paddr: bank_base_addr + (cut * ct_chunk_b) as u64,
                            size_b: ct_chunk_b,
                        })
                        .collect::<VecDeque<_>>()
                } else {
                    let bank_cut = (MEM_BANK_SIZE_MB * 1024 * 1024) / MEM_CHUNK_SIZE_B;
                    (0..bank_cut)
                        .map(|cut| MemChunk {
                            paddr: bank_base_addr + (cut * MEM_CHUNK_SIZE_B) as u64,
                            size_b: MEM_CHUNK_SIZE_B,
                        })
                        .collect::<VecDeque<_>>()
                }
            })
            .collect::<Vec<_>>();

        Self(
            banks
                .try_into()
                .expect("Invalid banks slice size. Check parameters"),
        )
    }

    // FIXME Fact that chunk are contiguous must be mandatory and not only likely to happen
    pub fn alloc(&mut self, props: &ffi::MemZoneProperties) -> Vec<MemChunk> {
        match props.mem_kind {
            ffi::MemKind::Ddr { offset } => {
                tracing::warn!(
                    "DDR allocation isn't handled by FFI. User directly handled offset and range"
                );
                // TODO Add guard to prevent bad argument from user
                vec![MemChunk {
                    paddr: offset as u64,
                    size_b: props.size_b,
                }]
            }
            ffi::MemKind::Hbm { pc } => {
                let bank = &mut self.0[pc];
                // Compute required number of chunk
                let chunk_nb = props.size_b.div_ceil(MEM_CHUNK_SIZE_B);
                assert!(
                    bank.len() >= chunk_nb,
                    "Not enough memory in selected Hbm bank {pc} [req: {props:?}]"
                );
                bank.drain(0..chunk_nb).collect::<Vec<_>>()
            }
        }
    }

    pub fn release(&mut self, kind: &ffi::MemKind, chunks: &mut Vec<MemChunk>) {
        match kind {
            ffi::MemKind::Ddr { .. } => {
                // TODO properly handle it when DDR management is integrated in the FFI
            }
            ffi::MemKind::Hbm { pc } => {
                // Insert chunk back in the correct bank
                let bank = &mut self.0[*pc];
                while let Some(chunk) = chunks.pop() {
                    bank.push_back(chunk)
                }

                // Sort chunk to maximize chance to obtain contiguous MemChunk
                bank.make_contiguous();
                bank.as_mut_slices().0.sort();
            }
        }
    }
}
