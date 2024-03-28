//! The purpose of this module is to make it easier to have the most commonly needed
//! traits of this crate.
//!
//! It is meant to be glob imported:
//! ```
//! use tfhe::prelude::*;
//! ```
pub use crate::high_level_api::traits::{
    DivRem, FheBootstrap, FheDecrypt, FheEncrypt, FheEq, FheKeyswitch, FheMax, FheMin,
    FheNumberConstant, FheOrd, FheTrivialEncrypt, FheTryEncrypt, FheTryTrivialEncrypt, IfThenElse,
    OverflowingAdd, OverflowingMul, OverflowingSub, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};

pub use crate::conformance::ParameterSetConformant;
pub use crate::core_crypto::prelude::{CastFrom, CastInto};
