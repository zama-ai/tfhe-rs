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

use serde::de::DeserializeOwned;
use serde::Serialize;
use tfhe_safe_serialize::Named;
use tfhe_versionable::{Unversionize, Versionize};
pub(crate) fn generic_safe_serialize<T: Serialize + Versionize + Named>(
    value: &T,
    serialized_size_limit: u64,
) -> Result<Vec<u8>, wasm_bindgen::JsError> {
    let mut buffer = vec![];
    catch_panic_result(|| {
        crate::safe_serialization::SerializationConfig::new(serialized_size_limit)
            .serialize_into(value, &mut buffer)
            .map_err(into_js_error)
    })?;

    Ok(buffer)
}

pub(crate) fn generic_safe_deserialize<T: Named + DeserializeOwned + Unversionize>(
    buffer: &[u8],
    serialized_size_limit: u64,
) -> Result<T, wasm_bindgen::JsError> {
    catch_panic_result(|| {
        crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
            .disable_conformance()
            .deserialize_from(buffer)
            .map_err(into_js_error)
    })
}

#[cfg(feature = "shortint-client-js-wasm-api")]
pub(crate) fn generic_safe_deserialize_conformant<
    T: Named + DeserializeOwned + Unversionize + tfhe_safe_serialize::ParameterSetConformant,
>(
    buffer: &[u8],
    serialized_size_limit: u64,
    parameter_set: &T::ParameterSet,
) -> Result<T, wasm_bindgen::JsError> {
    catch_panic_result(|| {
        crate::safe_serialization::DeserializationConfig::new(serialized_size_limit)
            .deserialize_from(buffer, parameter_set)
            .map_err(into_js_error)
    })
}
