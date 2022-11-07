#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(
    feature = "backend_fft_nightly_avx512",
    feature(stdsimd, avx512_target_feature)
)]

#[cfg(feature = "__c_api")]
pub mod c_api;

#[cfg(feature = "booleans")]
/// cbindgen:ignore
pub mod boolean;
/// cbindgen:ignore
pub mod core_crypto;
#[cfg(feature = "shortints")]
/// cbindgen:ignore
pub mod shortint;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
pub mod js_on_wasm_api;
#[cfg(feature = "__wasm_api")]
pub use js_on_wasm_api::*;

#[cfg(any(feature = "booleans", feature = "shortints"))]
pub(crate) mod seeders;
