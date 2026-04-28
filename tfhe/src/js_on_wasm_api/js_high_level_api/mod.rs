use wasm_bindgen::prelude::*;

pub(crate) mod config;

pub(crate) mod integers;

pub(crate) mod keys;

#[wasm_bindgen]
#[allow(non_camel_case_types)]
pub struct tfhe {}
