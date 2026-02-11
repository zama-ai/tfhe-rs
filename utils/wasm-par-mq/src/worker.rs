#[cfg(feature = "sync-api")]
use crate::coordinator::{CoordinatorUrl, signal_done_to_coordinator};
use crate::global_this;
use crate::messages::{ChunkOutcome, MainToWorker, WorkerToMain, from_js, to_js};
use crate::registry::{self, init_registry};

use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

/// Entry point called from worker.js bootstrap.
/// Sets up message handling for task execution.
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

const WORKER_JS_TEMPLATE: &str = include_str!("../js/worker.js");

/// Create a blob URL for the worker script with the given wasm and bindgen URLs embedded.
pub(crate) fn create_worker_url(wasm_url: &str, bindgen_url: &str) -> String {
    // Substitute values into the template
    let js_code = WORKER_JS_TEMPLATE
        .replace("__WASM_URL__", wasm_url)
        .replace("__BINDGEN_URL__", bindgen_url);

    let prop = web_sys::BlobPropertyBag::new();
    prop.set_type("application/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(
        &js_sys::Array::of1(&js_code.into()),
        &prop,
    )
    .unwrap();
    web_sys::Url::create_object_url_with_blob(&blob).unwrap()
}

/// Resolve a potentially relative URL to an absolute URL using the current location as base.
pub(crate) fn resolve_url(url: &str) -> String {
    let base = {
        let global = global_this();
        js_sys::Reflect::get(&global, &"location".into())
            .ok()
            .and_then(|loc| {
                js_sys::Reflect::get(&loc, &"href".into())
                    .ok()
                    .and_then(|href| href.as_string())
            })
    };

    match base {
        Some(base) => web_sys::Url::new_with_base(url, &base)
            .map(|u| u.href())
            .unwrap_or_else(|_| url.to_string()),
        None => url.to_string(),
    }
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
