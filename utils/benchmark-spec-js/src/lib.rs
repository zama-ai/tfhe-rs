//! `wasm-bindgen` surface over [`benchmark_spec::browser_benches`].

use benchmark_spec::{Statistic, browser_benches, measured_name};
use wasm_bindgen::prelude::*;

const CROSS_ORIGIN: &str = "cross_origin";

/// The browser name is appended later by the web driver.
#[wasm_bindgen]
pub fn mean_name(bench_id: &str, cross_origin: bool) -> String {
    measured_name(
        bench_id,
        Statistic::Mean,
        cross_origin.then_some(CROSS_ORIGIN),
    )
}

#[wasm_bindgen]
pub fn cpk_gen_id(param_name: &str, bits: u32) -> String {
    browser_benches::cpk_gen(param_name, bits)
}

#[wasm_bindgen]
pub fn compressed_server_key_gen_id(param_name: &str) -> String {
    browser_benches::compressed_server_key_gen(param_name)
}

#[wasm_bindgen]
pub fn compressed_server_key_serialize_id(param_name: &str) -> String {
    browser_benches::compressed_server_key_serialize(param_name)
}

#[wasm_bindgen]
pub fn compact_list_encrypt_id(param_name: &str, bits: u32, num_elements: u64) -> String {
    browser_benches::compact_list_encrypt(param_name, bits, num_elements)
}

#[wasm_bindgen]
pub fn compact_list_serialize_id(param_name: &str, bits: u32, num_elements: u64) -> String {
    browser_benches::compact_list_serialize(param_name, bits, num_elements)
}

#[wasm_bindgen]
pub fn zk_proof_id(
    param_name: &str,
    bits_packed: u32,
    crs_bits: u32,
    compute_load: &str,
    scheme: &str,
) -> Result<String, JsError> {
    Ok(browser_benches::zk_proof(
        param_name,
        bits_packed,
        crs_bits,
        compute_load,
        scheme,
    )?)
}

#[wasm_bindgen]
pub fn zk_proven_list_size_id(
    param_name: &str,
    bits_packed: u32,
    crs_bits: u32,
    compute_load: &str,
    scheme: &str,
) -> Result<String, JsError> {
    Ok(browser_benches::zk_proven_list_size(
        param_name,
        bits_packed,
        crs_bits,
        compute_load,
        scheme,
    )?)
}
