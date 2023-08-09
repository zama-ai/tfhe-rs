//! Welcome to the TFHE-rs API documentation!
//!
//! TFHE-rs is a fully homomorphic encryption (FHE) library that implements Zama's variant of TFHE.

#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(feature = "nightly-avx512", feature(stdsimd, avx512_target_feature))]
#![cfg_attr(all(doc, not(doctest)), feature(doc_auto_cfg))]
#![cfg_attr(all(doc, not(doctest)), feature(doc_cfg))]
#![warn(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "__c_api")]
pub mod c_api;

#[cfg(feature = "boolean")]
/// Welcome to the TFHE-rs [`boolean`](`crate::boolean`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod boolean;

/// Welcome to the TFHE-rs [`core_crypto`](`crate::core_crypto`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod core_crypto;

#[cfg(feature = "integer")]
/// Welcome to the TFHE-rs [`integer`](`crate::integer`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod integer;

#[cfg(feature = "shortint")]
/// Welcome to the TFHE-rs [`shortint`](`crate::shortint`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod shortint;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
pub mod js_on_wasm_api;
#[cfg(feature = "__wasm_api")]
pub use js_on_wasm_api::*;

#[cfg(all(
    doctest,
    feature = "shortint",
    feature = "boolean",
    feature = "integer"
))]
mod test_user_docs;

/// cbindgen:ignore
#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
pub(crate) mod high_level_api;

#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
pub use high_level_api::*;

/// cbindgen:ignore
#[cfg(any(test, doctest, feature = "internal-keycache"))]
pub mod keycache;
