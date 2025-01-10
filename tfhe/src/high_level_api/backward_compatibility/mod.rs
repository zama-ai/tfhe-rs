#![allow(clippy::large_enum_variant)]
// Backward compatibility types should not be themselves versioned
#![cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]

pub mod booleans;
pub mod compact_list;
pub mod compressed_ciphertext_list;
pub mod config;
pub mod integers;
pub mod keys;
#[cfg(feature = "strings")]
pub mod strings;
pub mod tag;
