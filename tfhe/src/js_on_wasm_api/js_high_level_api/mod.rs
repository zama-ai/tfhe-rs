use wasm_bindgen::prelude::*;

pub(crate) mod config;

pub(crate) mod integers;
// using Self does not work well with #[wasm_bindgen] macro
#[allow(clippy::use_self)]
pub(crate) mod keys;
#[cfg(feature = "zk-pok")]
mod zk;

use super::into_js_error;

pub(crate) fn catch_panic_result<F, R>(closure: F) -> Result<R, JsError>
where
    F: FnOnce() -> Result<R, JsError>,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure))
        .unwrap_or_else(|_| Err(JsError::new("Operation Failed")))
}

pub(crate) fn catch_panic<F, R>(closure: F) -> Result<R, JsError>
where
    F: FnOnce() -> R,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(closure))
        .map_or_else(|_| Err(JsError::new("Operation Failed")), |ret| Ok(ret))
}

#[wasm_bindgen]
#[allow(non_camel_case_types)]
pub struct tfhe {}
