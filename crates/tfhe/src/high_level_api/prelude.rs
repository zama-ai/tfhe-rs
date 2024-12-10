//! The purpose of this module is to make it easier to have the most commonly needed
//! traits of this crate.
//!
//! It is meant to be glob imported:
//! ```
//! # #[allow(unused_imports)]
//! use tfhe::prelude::*;
//! ```
pub use crate::high_level_api::traits::{
    BitSlice, CiphertextList, DivRem, FheBootstrap, FheDecrypt, FheEncrypt, FheEq, FheKeyswitch,
    FheMax, FheMin, FheNumberConstant, FheOrd, FheTrivialEncrypt, FheTryEncrypt,
    FheTryTrivialEncrypt, IfThenElse, OverflowingAdd, OverflowingMul, OverflowingSub, RotateLeft,
    RotateLeftAssign, RotateRight, RotateRightAssign, Tagged,
};

pub use crate::core_crypto::prelude::{CastFrom, CastInto};
pub use tfhe_safe_serialization::conformance::ParameterSetConformant;
