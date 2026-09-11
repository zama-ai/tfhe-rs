// Pure Rust Helpers
mod u64_conv;
pub use u64_conv::{u64_to_vec_u2, vec_u2_to_u64};
pub mod encryption;

mod cipher;
mod tables;
pub use cipher::{decrypt, encrypt};

/// PRINCEv2 operates on 64-bit blocks. The state is split into elements of 1, 2 or 4 bits
/// depending on the layer, one element per ciphertext (see the nibble formats in `cipher`).
pub const BLOCK_NB_BITS: usize = 64;
pub const BLOCK_NB_U2: usize = BLOCK_NB_BITS / 2;
pub const BLOCK_NB_U4: usize = BLOCK_NB_BITS / 4;
