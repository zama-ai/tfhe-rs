//! A module using a software fallback implementation of random number generator.

mod block_cipher;

mod generator;
pub use generator::*;

#[cfg(feature = "parallel")]
mod parallel;
#[cfg(feature = "parallel")]
pub use parallel::*;
