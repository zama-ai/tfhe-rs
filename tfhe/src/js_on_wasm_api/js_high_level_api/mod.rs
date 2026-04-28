#[cfg(feature = "integer-js-wasm-api")]
use wasm_bindgen::prelude::*;

pub(crate) mod client;

#[cfg(feature = "integer-js-wasm-api")]
pub(crate) mod config;
#[cfg(feature = "integer-js-wasm-api")]
pub(crate) mod integers;
#[cfg(feature = "integer-js-wasm-api")]
pub(crate) mod keys;

#[cfg(feature = "integer-js-wasm-api")]
#[wasm_bindgen]
#[allow(non_camel_case_types)]
pub struct tfhe {}
