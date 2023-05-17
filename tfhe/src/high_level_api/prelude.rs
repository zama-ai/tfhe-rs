//! The purpose of this module is to make it easier to have the most commonly needed
//! traits of this crate.
//!
//! It is meant to be glob imported:
//! ```
//! use tfhe::prelude::*;
//! ```
pub use crate::high_level_api::traits::{
    DynamicFheEncryptor, DynamicFheTrivialEncryptor, DynamicFheTryEncryptor, FheBootstrap,
    FheDecrypt, FheEncrypt, FheEq, FheNumberConstant, FheOrd, FheTrivialEncrypt, FheTryEncrypt,
    FheTryTrivialEncrypt,
};

pub use crate::high_level_api::ops::*;
