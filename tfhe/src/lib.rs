#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(feature = "nightly-avx512", feature(stdsimd, avx512_target_feature))]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "__c_api")]
pub mod c_api;

#[cfg(feature = "boolean")]
/// cbindgen:ignore
pub mod boolean;
/// cbindgen:ignore
pub mod core_crypto;
#[cfg(feature = "shortint")]
/// cbindgen:ignore
pub mod shortint;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
pub mod js_on_wasm_api;
#[cfg(feature = "__wasm_api")]
pub use js_on_wasm_api::*;

pub mod seeders;

#[cfg(all(doctest, feature = "shortint", feature = "boolean"))]
mod test_user_docs;
