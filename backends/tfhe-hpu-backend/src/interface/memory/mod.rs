// Xrt required memory allocation to be page aligned
pub(crate) const MEM_PAGE_SIZE_B: usize = 4096;

pub(crate) mod ciphertext;
pub(crate) mod huge;
pub use ciphertext::{CiphertextBundle, CiphertextMemory, CiphertextMemoryProperties};
pub use huge::{HugeMemory, HugeMemoryProperties};
