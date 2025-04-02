// Xrt required memory allocation to be page aligned
pub(crate) const MEM_PAGE_SIZE_B: usize = 4096;

/// Compute the minimal size to keep page alignment
pub fn page_align(size_b: usize) -> usize {
    size_b.div_ceil(MEM_PAGE_SIZE_B) * MEM_PAGE_SIZE_B
}

pub(crate) mod ciphertext;
pub(crate) mod huge;
pub use ciphertext::{CiphertextBundle, CiphertextMemory, CiphertextMemoryProperties};
pub use huge::{HugeMemory, HugeMemoryProperties};
