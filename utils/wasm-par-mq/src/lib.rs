use wasm_bindgen::prelude::*;

// Direct binding to `globalThis`
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(thread_local_v2, js_name = "globalThis")]
    static GLOBAL_THIS: JsValue;
}

pub(crate) fn global_this() -> JsValue {
    GLOBAL_THIS.with(JsValue::clone)
}

#[cfg(feature = "sync-api")]
pub(crate) mod coordinator;
pub(crate) mod iterator;
pub(crate) mod messages;
pub(crate) mod pool;
pub(crate) mod registry;
#[cfg(feature = "sync-api")]
pub(crate) mod sync_executor;
pub(crate) mod worker;

#[cfg(feature = "sync-api")]
pub use coordinator::register_coordinator;
pub use iterator::{IntoIter, IntoParallelIterator, Iter, ParMap, ParallelIterator, ParallelSlice};
pub use pool::{init_pool_async, is_pool_initialized, num_workers};
#[cfg(feature = "sync-api")]
pub use pool::{init_pool_sync, init_pool_sync_from_worker};
#[cfg(feature = "sync-api")]
pub use sync_executor::{execute_async, start_sync_executor};
pub use worker::start_worker;

/// Internal module for macro implementation details. Do not use directly.
#[doc(hidden)]
pub mod __private {
    // Re-export macros so that users don't have to add them as dependencies
    pub use inventory::submit as submit_fn_entry;
    pub use paste::paste;

    // Re-export registry internals for macros
    pub use crate::registry::{
        FnEntry, NewFnEntry, RegisteredFn, deserialize_input_chunk, serialize_output_chunk,
    };
}
