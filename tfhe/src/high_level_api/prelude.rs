//! The purpose of this module is to make it easier to have the most commonly needed
//! traits of this crate.
//!
//! It is meant to be glob imported:
//! ```
//! # #[allow(unused_imports)]
//! use tfhe::prelude::*;
//! ```
pub use crate::high_level_api::traits::{
    BitSlice, CiphertextList, DivRem, FheDecrypt, FheEncrypt, FheEq, FheKeyswitch, FheMax, FheMin,
    FheOrd, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt, FheWait, IfThenElse,
    OverflowingAdd, OverflowingMul, OverflowingNeg, OverflowingSub, RotateLeft, RotateLeftAssign,
    RotateRight, RotateRightAssign, ScalarIfThenElse, SquashNoise, Tagged,
};
#[cfg(feature = "hpu")]
pub use crate::high_level_api::traits::{FheHpu, HpuHandle};

pub use crate::conformance::ParameterSetConformant;
pub use crate::core_crypto::prelude::{CastFrom, CastInto};

pub use crate::high_level_api::array::traits::FheSliceDotProduct;

#[cfg(feature = "gpu")]
pub use crate::high_level_api::gpu_utils::*;
#[cfg(feature = "strings")]
pub use crate::high_level_api::strings::traits::*;
#[cfg(feature = "gpu")]
pub use crate::high_level_api::traits::{
    AddSizeOnGpu, BitAndSizeOnGpu, BitNotSizeOnGpu, BitOrSizeOnGpu, BitXorSizeOnGpu,
    FheMaxSizeOnGpu, FheMinSizeOnGpu, FheOrdSizeOnGpu, RotateLeftSizeOnGpu, RotateRightSizeOnGpu,
    ShlSizeOnGpu, ShrSizeOnGpu, SizeOnGpu, SubSizeOnGpu,
};
