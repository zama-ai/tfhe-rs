#[cfg(feature = "shortint-client-js-wasm-api")]
mod shortint;
#[cfg(feature = "shortint-client-js-wasm-api")]
pub use shortint::*;

#[cfg(feature = "boolean-client-js-wasm-api")]
mod boolean;
#[cfg(feature = "boolean-client-js-wasm-api")]
pub use boolean::*;

#[cfg(feature = "parallel-wasm-api")]
pub use wasm_bindgen_rayon::init_thread_pool;

mod js_high_level_api;
pub use js_high_level_api::*;
