#![cfg_attr(
    test,
    allow(
        deprecated,
        reason = "tests of deprecated items are expected to use them"
    )
)]

pub mod curve_446;
pub mod curve_api;
#[cfg(feature = "gpu")]
pub mod gpu;
pub mod proofs;
pub mod serialization;

pub mod backward_compatibility;
mod four_squares;
