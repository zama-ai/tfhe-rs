#[cfg(feature = "sync-api")]
use crate::coordinator::{CoordinatorUrl, signal_done_to_coordinator};
use crate::global_this;
use crate::messages::{ChunkOutcome, MainToWorker, WorkerToMain, from_js, to_js};
use crate::registry::{self, init_registry};

use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

// Bindings to worker_helpers.js snippet (placed by wasm-bindgen at
// `pkg/snippets/wasm-par-mq-<hash>/js/worker_helpers.js`).
//
// Worker creation uses the `new Worker(new URL('./worker_helpers.js', import.meta.url))`
// pattern in JS, which bundlers (like webpack) recognize and process as a worker
// entry point, resolving imports inside the worker automatically.
#[wasm_bindgen(module = "/js/worker_helpers.js")]
extern "C" {
    /// Create a compute worker via the bundler-recognized JS pattern.
    #[wasm_bindgen(js_name = "createComputeWorker")]
    pub(crate) fn create_compute_worker() -> web_sys::Worker;

    /// Create a sync executor worker via the bundler-recognized JS pattern.
    #[wasm_bindgen(js_name = "createSyncExecutorWorker")]
    pub(crate) fn create_sync_executor_worker() -> web_sys::Worker;

    /// Get the origin of the current context (main thread or worker).
    #[wasm_bindgen(js_name = "getWorkerOrigin")]
    pub(crate) fn get_worker_origin() -> String;
}

/// Entry point called from worker_helpers.js bootstrap when loaded as a
/// compute worker. Sets up message handling for task execution.
#[wasm_bindgen]
pub fn start_worker(origin: &str) {
    init_registry();

    #[cfg(feature = "sync-api")]
    CoordinatorUrl::set(origin);

    #[cfg(not(feature = "sync-api"))]
    let _ = origin;

    let global: DedicatedWorkerGlobalScope = global_this().unchecked_into();

    let onmessage = Closure::wrap(Box::new(handle_chunk_message) as Box<dyn FnMut(MessageEvent)>);
    global.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    // Signal ready to parent (main thread or SyncExecutor)
    send_to_main(&WorkerToMain::Ready);
}

fn handle_chunk_message(event: MessageEvent) {
    let msg: MainToWorker = match from_js(event.data()) {
        Ok(m) => m,
        Err(e) => {
            web_sys::console::error_1(&format!("Failed to parse message: {e}").into());
            return;
        }
    };

    let MainToWorker {
        chunk_id,
        fn_id,
        data,
        #[cfg(feature = "sync-api")]
        task_id,
    } = msg;

    let result = registry::execute(fn_id, &data);
    let outcome = ChunkOutcome { chunk_id, result };

    #[cfg(feature = "sync-api")]
    // If there is a task id, it means that the pool is running in sync mode
    if let Some(task_id) = task_id {
        signal_done_to_coordinator(task_id, outcome);
    } else {
        send_to_main(&WorkerToMain::Done(outcome));
    }

    #[cfg(not(feature = "sync-api"))]
    send_to_main(&WorkerToMain::Done(outcome));
}

/// Send a message to the main thread.
pub(crate) fn send_to_main(msg: &WorkerToMain) {
    let global: DedicatedWorkerGlobalScope = global_this().unchecked_into();
    match to_js(msg) {
        Ok(js_msg) => {
            let _ = global.post_message(&js_msg);
        }
        Err(e) => {
            web_sys::console::error_1(&format!("Failed to serialize message: {e}").into());
        }
    }
}
