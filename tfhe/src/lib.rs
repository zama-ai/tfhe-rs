#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(feature = "nightly-avx512", feature(stdsimd, avx512_target_feature))]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "__c_api")]
pub mod c_api;

#[cfg(feature = "boolean")]
///Welcome to the TFHE-rs `boolean` module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod boolean;

///Welcome to the TFHE-rs `core_crypto` module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod core_crypto;

#[cfg(feature = "shortint")]
///Welcome to the TFHE-rs `shortint` module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod shortint;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
pub mod js_on_wasm_api;
#[cfg(feature = "__wasm_api")]
pub use js_on_wasm_api::*;

#[cfg(all(doctest, feature = "shortint", feature = "boolean"))]
mod test_user_docs;
