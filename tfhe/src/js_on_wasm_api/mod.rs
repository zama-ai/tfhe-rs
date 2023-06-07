#[cfg(feature = "shortint-client-js-wasm-api")]
pub mod shortint;
#[cfg(feature = "shortint-client-js-wasm-api")]
pub use shortint::*;

#[cfg(feature = "boolean-client-js-wasm-api")]
pub mod boolean;
#[cfg(feature = "boolean-client-js-wasm-api")]
pub use boolean::*;

#[cfg(feature = "parallel-wasm-api")]
pub use wasm_bindgen_rayon::init_thread_pool;

pub mod high_level_api;
pub use high_level_api::*;
