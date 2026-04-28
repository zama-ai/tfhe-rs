use wasm_bindgen::prelude::*;

pub(crate) mod config;

pub(crate) mod integers;

// using Self does not work well with #[wasm_bindgen] macro
#[allow(clippy::use_self)]
pub(crate) mod keys;

#[wasm_bindgen]
#[allow(non_camel_case_types)]
pub struct tfhe {}
