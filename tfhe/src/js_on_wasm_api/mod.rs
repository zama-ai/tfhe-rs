#[cfg(feature = "integer")]
pub(crate) mod client;

#[cfg(feature = "shortint-client-js-wasm-api")]
mod shortint;

#[cfg(feature = "boolean-client-js-wasm-api")]
mod boolean;

// We need to use the init_thread_pool for it to be publicly visible but it appears unused when
// compiling
#[allow(unused_imports)]
#[cfg(feature = "parallel-wasm-api")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[cfg(feature = "integer-client-js-wasm-api")]
mod js_high_level_api;

pub(crate) fn into_js_error<E: std::fmt::Debug>(e: E) -> wasm_bindgen::JsError {
    wasm_bindgen::JsError::new(format!("{e:?}").as_str())
}

pub(crate) fn catch_panic_result<F, R>(closure: F) -> Result<R, wasm_bindgen::JsError>
where
    F: FnOnce() -> Result<R, wasm_bindgen::JsError>,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure))
        .unwrap_or_else(|_| Err(wasm_bindgen::JsError::new("Operation Failed")))
}

pub(crate) fn catch_panic<F, R>(closure: F) -> Result<R, wasm_bindgen::JsError>
where
    F: FnOnce() -> R,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)).map_or_else(
        |_| Err(wasm_bindgen::JsError::new("Operation Failed")),
        |ret| Ok(ret),
    )
}
