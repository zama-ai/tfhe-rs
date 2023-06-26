//! The purpose of this module is to make it easier to have the most commonly needed
//! traits of this crate.
//!
//! It is meant to be glob imported:
//! ```
//! use tfhe::prelude::*;
//! ```
pub use crate::high_level_api::traits::{
    DivRem, DynamicFheEncryptor, DynamicFheTrivialEncryptor, DynamicFheTryEncryptor, FheBootstrap,
    FheDecrypt, FheEncrypt, FheEq, FheMax, FheMin, FheNumberConstant, FheOrd, FheTrivialEncrypt,
    FheTryEncrypt, FheTryTrivialEncrypt, RotateLeft, RotateLeftAssign, RotateRight,
    RotateRightAssign,
};
