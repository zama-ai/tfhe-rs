//! A module implementing a random number generator, using the x86_64 `aesni` instructions.
//!
//! This module implements a cryptographically secure pseudorandom number generator
//! (CS-PRNG), using a fast block cipher. The implementation is based on the
//! [intel aesni white paper 323641-001 revision 3.0](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf).

mod block_cipher;

mod generator;
pub use generator::*;

#[cfg(feature = "parallel")]
mod parallel;
#[cfg(feature = "parallel")]
pub use parallel::*;
