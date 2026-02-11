use wasm_bindgen::prelude::*;
use wasm_par_mq::{
    ParallelIterator, ParallelSlice, PoolMode, execute_async, par_fn, register_fn, sync_fn,
};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

fn double(x: i32) -> i32 {
    x * 2
}
register_fn!(double, i32, i32);

fn square(x: i32) -> i32 {
    x * x
}
register_fn!(square, i32, i32);

/// Double all numbers using async workers.
#[wasm_bindgen]
pub async fn double_all(data: Vec<i32>) -> Vec<i32> {
    data.par_iter().map(par_fn!(double)).collect_vec().await
}

/// Chain two parallel operations: double then square.
#[wasm_bindgen]
pub async fn double_then_square(data: Vec<i32>) -> Vec<i32> {
    let doubled: Vec<i32> = data.par_iter().map(par_fn!(double)).collect_vec().await;
    doubled.par_iter().map(par_fn!(square)).collect_vec().await
}

/// Double all numbers using the sync executor.
fn double_all_impl(data: Vec<i32>) -> Vec<i32> {
    data.par_iter().map(par_fn!(double)).collect_vec_sync()
}
register_fn!(double_all_impl, Vec<i32>, Vec<i32>);

#[wasm_bindgen]
pub async fn double_all_sync(data: Vec<i32>) -> Result<Vec<i32>, JsValue> {
    execute_async(sync_fn!(double_all_impl), &data)
        .await
        .map_err(|e| JsValue::from_str(&e))
}

/// Initialize pool in async mode.
#[wasm_bindgen]
pub async fn init_async(
    num_workers: u32,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), JsValue> {
    wasm_par_mq::init_pool(PoolMode::Async, Some(num_workers), wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Initialize pool in sync executor mode.
#[wasm_bindgen]
pub async fn init_sync(
    num_workers: u32,
    wasm_url: &str,
    bindgen_url: &str,
    coordinator_url: &str,
) -> Result<(), JsValue> {
    wasm_par_mq::init_pool(
        PoolMode::Sync {
            coordinator_url: coordinator_url.to_string(),
        },
        Some(num_workers),
        wasm_url,
        bindgen_url,
    )
    .await
    .map_err(|e| JsValue::from_str(&e.to_string()))
}
