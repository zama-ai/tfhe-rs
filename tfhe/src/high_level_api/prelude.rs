//! The purpose of this module is to make it easier to have the most commonly needed
//! traits of this crate.
//!
//! It is meant to be glob imported:
//! ```
//! # #[allow(unused_imports)]
//! use tfhe::prelude::*;
//! ```
#[cfg(feature = "hpu-xfer")]
pub use crate::high_level_api::traits::HwXfer;
pub use crate::high_level_api::traits::{
    BitSlice, CiphertextList, DivRem, FheDecrypt, FheEncrypt, FheEq, FheKeyswitch, FheMax, FheMin,
    FheOrd, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt, FheWait, IfThenElse,
    OverflowingAdd, OverflowingMul, OverflowingSub, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign, Tagged,
};

pub use crate::conformance::ParameterSetConformant;
pub use crate::core_crypto::prelude::{CastFrom, CastInto};

#[cfg(feature = "strings")]
pub use crate::high_level_api::strings::traits::*;
