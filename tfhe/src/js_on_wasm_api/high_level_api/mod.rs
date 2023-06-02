use wasm_bindgen::prelude::*;

pub(crate) mod config;
pub(crate) mod integers;
pub(crate) mod keys;

pub(crate) fn into_js_error<E: std::fmt::Debug>(e: E) -> wasm_bindgen::JsError {
    wasm_bindgen::JsError::new(format!("{e:?}").as_str())
}

pub(crate) fn catch_panic_result<F, R>(closure: F) -> Result<R, JsError>
where
    F: FnOnce() -> Result<R, JsError>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)) {
        Ok(inner_result) => inner_result,
        _ => Err(JsError::new("Operation Failed")),
    }
}

pub(crate) fn catch_panic<F, R>(closure: F) -> Result<R, JsError>
where
    F: FnOnce() -> R,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure)) {
        Ok(ret) => Ok(ret),
        _ => Err(JsError::new("Operation Failed")),
    }
}

#[wasm_bindgen]
#[allow(non_camel_case_types)]
pub struct tfhe {}
