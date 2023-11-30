#[cfg(feature = "shortint-client-js-wasm-api")]
mod shortint;

#[cfg(feature = "boolean-client-js-wasm-api")]
mod boolean;

// We need to use the init_thread_pool for it to be publicly visible but it appears unused when
// compiling
#[allow(unused_imports)]
#[cfg(feature = "parallel-wasm-api")]
pub use wasm_bindgen_rayon::init_thread_pool;

mod js_high_level_api;
