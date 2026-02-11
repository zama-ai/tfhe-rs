//! Coordinator (Service Worker) client for sync API.
//!
//! The coordinator is a Service Worker that tracks task completion and holds requests until all
//! chunks are done. The actual service worker logic is implemented in JavaScript
//! (`js/coordinator.js`) and exported as `setupCoordinator()` — end users import it into their
//! own Service Worker file. This Rust module provides the client side: registering the SW and
//! communicating with it via synchronous XHR.
//!
//! This module provides:
//! - Registration of the coordinator from the main thread
//! - Sync XHR helpers to communicate with the coordinator from the SyncExecutor

use std::cell::RefCell;

use serde_json::json;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{DedicatedWorkerGlobalScope, Request, RequestInit, XmlHttpRequest};

use crate::messages::{ChunkOutcome, CoordinatorToSyncExecutor, WorkerToCoordinator};

thread_local! {
    static COORDINATOR_URL: RefCell<Option<CoordinatorUrl>> = const { RefCell::new(None) };
}

/// Store origin at runtime for making absolute URLs (workers in blob context can't use relative
/// URLs)
pub(crate) struct CoordinatorUrl {
    origin: String,
}

impl CoordinatorUrl {
    const COORDINATOR_PATH: &str = "/__wasm_par__";

    fn with<F, R>(f: F) -> R
    where
        F: FnOnce(&Self) -> R,
    {
        COORDINATOR_URL.with(|coord| {
            f(coord
                .borrow()
                .as_ref()
                .expect("coordinator url should be set at this point"))
        })
    }

    /// Setup the absolute url for the coordinator service worker.
    ///
    /// This needs to be called inside any worker that will have to reach the coordinator
    /// (ie: sync executor and compute workers)
    pub(crate) fn set(origin: &str) {
        COORDINATOR_URL.with(|url| *url.borrow_mut() = Some(Self::new(origin)));
    }

    fn new(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
        }
    }

    /// Build the full url for a given endpoint
    fn url(endpoint: &str) -> String {
        Self::with(|coord| format!("{}{}{}", coord.origin, Self::COORDINATOR_PATH, endpoint))
    }

    /// The url for the /ping endpoint
    fn ping() -> String {
        Self::url("/ping")
    }

    /// The url for the /wait endpoint
    fn wait(task_id: u64) -> String {
        Self::url(&format!("{}/{}", "/wait", task_id))
    }

    /// The url for the /done endpoint
    fn done() -> String {
        Self::url("/done")
    }

    /// The url for the /task endpoint
    fn task() -> String {
        Self::url("/task")
    }

    /// The url for the /cancel endpoint
    fn cancel(task_id: u64) -> String {
        Self::url(&format!("{}/{}", "/cancel", task_id))
    }
}

/// Register the coordinator service worker.
pub async fn register_coordinator(coordinator_url: &str) -> Result<(), String> {
    let window = web_sys::window()
        .ok_or_else(|| "no window object (sync mode requires main thread)".to_string())?;

    let navigator = window.navigator();
    let service_worker = navigator.service_worker();

    let options = web_sys::RegistrationOptions::new();
    // The coordinator is defined as a "module" service worker that can be embedded by the end-user
    // in its own code.
    options.set_type("module");
    let promise = service_worker.register_with_options(coordinator_url, &options);

    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|e| format!("failed to register coordinator: {e:?}"))?;

    // Wait for the service worker to be ready
    let ready_promise = service_worker
        .ready()
        .map_err(|e| format!("failed to get service worker ready promise: {e:?}"))?;

    wasm_bindgen_futures::JsFuture::from(ready_promise)
        .await
        .map_err(|e| format!("service worker not ready: {e:?}"))?;

    // Wait until the service worker has claimed this page as a client.
    // The `ready` promise resolves when there's an active worker, but
    // `clients.claim()` in the activate event may still be pending.
    // We poll until `navigator.serviceWorker.controller` is set.
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 50; // 50 * 20ms = 1 second max
    while service_worker.controller().is_none() {
        if attempts >= MAX_ATTEMPTS {
            return Err("Service worker did not claim this page in time".to_string());
        }
        // Sleep for 20ms
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            let window = web_sys::window().unwrap();
            window
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 20)
                .unwrap();
        });
        wasm_bindgen_futures::JsFuture::from(promise).await.ok();
        attempts += 1;
    }

    Ok(())
}

/// Perform a synchronous GET request. Blocks until response is received.
fn sync_xhr_get(url: &str) -> Result<String, String> {
    let xhr = XmlHttpRequest::new().map_err(|e| format!("XHR new failed: {e:?}"))?;
    xhr.open_with_async("GET", url, false)
        .map_err(|e| format!("XHR open failed: {e:?}"))?;
    xhr.send().map_err(|e| format!("XHR send failed: {e:?}"))?;

    let status = xhr
        .status()
        .map_err(|e| format!("XHR status failed: {e:?}"))?;
    if status != 200 {
        if let Ok(Some(message)) = xhr.response_text() {
            return Err(format!("XHR failed with status {status}: {message}"));
        } else {
            return Err(format!("XHR failed with status {status}"));
        }
    }

    xhr.response_text()
        .map_err(|e| format!("failed to get XHR response: {e:?}"))?
        .ok_or_else(|| "XHR returned no response text".to_string())
}

/// Perform a synchronous POST request with JSON body. Blocks until response is received.
fn sync_xhr_post(url: &str, body: &str) -> Result<String, String> {
    let xhr = XmlHttpRequest::new().map_err(|e| format!("XHR new failed: {e:?}"))?;
    xhr.open_with_async("POST", url, false)
        .map_err(|e| format!("XHR open failed: {e:?}"))?;
    xhr.set_request_header("Content-Type", "application/json")
        .map_err(|e| format!("XHR set_request_header failed: {e:?}"))?;
    xhr.send_with_opt_str(Some(body))
        .map_err(|e| format!("XHR send failed: {e:?}"))?;

    let status = xhr
        .status()
        .map_err(|e| format!("XHR status failed: {e:?}"))?;
    if status != 200 {
        if let Ok(Some(message)) = xhr.response_text() {
            return Err(format!("XHR failed with status {status}: {message}"));
        } else {
            return Err(format!("XHR failed with status {status}"));
        }
    }

    xhr.response_text()
        .map_err(|e| format!("XHR response_text failed: {e:?}"))?
        .ok_or_else(|| "XHR returned no response text".to_string())
}

/// Wait for the Service Worker coordinator to start intercepting requests.
///
/// When a worker is first created, there's a brief window where it's not yet registered as a
/// client of the Service Worker, so requests would go to the actual server. This function polls
/// the coordinator's ping endpoint until it responds, with a timeout of 5 seconds.
pub(crate) async fn wait_for_coordinator() -> Result<(), String> {
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 100; // 100 * 50ms = 5 seconds max
    loop {
        if ping_coordinator().is_ok() {
            return Ok(());
        }
        attempts += 1;
        if attempts >= MAX_ATTEMPTS {
            return Err(
                "Service Worker not intercepting requests after timeout".to_string(),
            );
        }
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            let global: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
            global
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 50)
                .unwrap();
        });
        wasm_bindgen_futures::JsFuture::from(promise).await.ok();
    }
}

/// Ping the coordinator to verify it's intercepting requests from this context.
fn ping_coordinator() -> Result<(), String> {
    let xhr = XmlHttpRequest::new().map_err(|e| format!("XHR new failed: {e:?}"))?;
    let url = CoordinatorUrl::ping();
    xhr.open_with_async("GET", &url, false)
        .map_err(|e| format!("XHR open failed: {e:?}"))?;
    xhr.send().map_err(|e| format!("XHR send failed: {e:?}"))?;

    let status = xhr
        .status()
        .map_err(|e| format!("XHR status failed: {e:?}"))?;

    if status == 200 {
        Ok(())
    } else {
        Err(format!("Ping failed with status {status}"))
    }
}

pub(crate) fn register_task(task_id: u64, num_chunks: usize) -> Result<(), String> {
    let url = CoordinatorUrl::task();
    sync_xhr_post(
        &url,
        &json!({
            "task_id": task_id,
            "num_chunks": num_chunks
        })
        .to_string(),
    )?;

    Ok(())
}

pub(crate) fn wait_task(task_id: u64) -> Result<Vec<Vec<u8>>, String> {
    let url = CoordinatorUrl::wait(task_id);
    let response = sync_xhr_get(&url)?;

    let parsed: CoordinatorToSyncExecutor = serde_json::from_str(&response)
        .map_err(|e| format!("Failed to deserialize task {task_id} result: {e}"))?;

    // Sort by chunk_id
    let mut outcomes = parsed.results;
    outcomes.sort_by_key(|r| r.chunk_id);

    // Early return if any chunk returned an error
    let outcomes = outcomes
        .into_iter()
        .map(|outcome| {
            outcome
                .result
                .map_err(|err| format!("Chunk {} failed: {}", outcome.chunk_id, err))
        })
        // At this point we have Vec<Result>, we use collect to convert to Result<Vec>
        .collect::<Result<Vec<_>, _>>()?;

    // If there is no error, return the data in order
    Ok(outcomes)
}

pub(crate) fn cancel_task(task_id: u64) -> Result<(), String> {
    let url = CoordinatorUrl::cancel(task_id);
    sync_xhr_get(&url).map(|_| ())
}

/// Signal to the coordinator that work on a chunk is finished
pub(crate) fn signal_done_to_coordinator(task_id: u64, outcome: ChunkOutcome) {
    let req = WorkerToCoordinator { task_id, outcome };
    let Ok(body) = serde_json::to_string(&req).inspect_err(|e| {
        web_sys::console::error_1(&format!("Failed to serialize done request: {e}").into());
    }) else {
        return;
    };

    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&JsValue::from_str(&body));

    let url = CoordinatorUrl::done();
    let Ok(request) = Request::new_with_str_and_init(&url, &init).inspect_err(|e| {
        web_sys::console::error_1(&format!("Failed to create request: {e:?}").into())
    }) else {
        return;
    };

    if let Err(e) = request.headers().set("Content-Type", "application/json") {
        web_sys::console::error_1(&format!("Failed to set request header: {e:?}").into());
        return;
    }

    wasm_bindgen_futures::spawn_local(async move {
        let global: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
        let promise = global.fetch_with_request(&request);
        if let Err(e) = wasm_bindgen_futures::JsFuture::from(promise).await {
            web_sys::console::error_1(&format!("Failed to signal done: {e:?}").into());
        }
    });
}
