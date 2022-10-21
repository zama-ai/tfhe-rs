//! Secret keys for the concrete schemes.
pub use glwe::*;
pub use lwe::*;

pub mod generators;

mod glwe;
mod lwe;
