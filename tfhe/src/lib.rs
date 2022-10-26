#![cfg_attr(feature = "__wasm_api", allow(dead_code))]

#[cfg(feature = "booleans")]
/// cbindgen:ignore
pub mod boolean;
#[cfg(feature = "__c_api")]
pub mod c_api;
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

pub(crate) mod seeders;
