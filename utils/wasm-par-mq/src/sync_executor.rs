//! A dedicated worker that runs user's synchronous parallel code.
//!
//! The SyncExecutor is spawned by the main thread and initializes the worker
//! pool with a sync result handler. It receives work requests from the main
//! thread, executes user code that may call `collect_vec_sync()`, and returns
//! results.
//!
//! The sync blocking is achieved by:
//! 1. Dispatching chunks to compute workers via postMessage
//! 2. Blocking on a sync XHR to the Coordinator (Service Worker)
//! 3. When XHR returns, the queued postMessage results are processed
//! 4. Results are collected and returned
//!
//! The SyncExecutor is required for this, since modern browsers reject sync
//! XHR requests from the main thread.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use futures::channel::oneshot;
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent, Worker};

use crate::coordinator::CoordinatorUrl;
use crate::messages::{self, JobOutcome, MainToSyncExecutor, SyncExecutorToMain};
use crate::pool::{self, ReadySender};
use crate::registry::{FnEntry, RegisteredFn};

thread_local! {
    static SYNC_EXECUTOR: RefCell<Option<SyncExecutor>> = const { RefCell::new(None) };
}

struct SyncExecutor {
    worker: Worker,
    waiters: HashMap<u64, oneshot::Sender<Result<Vec<u8>, String>>>,
    next_job_id: u64,
}

impl SyncExecutor {
    pub fn new(worker: Worker) -> Self {
        Self {
            worker,
            waiters: HashMap::new(),
            next_job_id: 0,
        }
    }

    fn next_job_id(&mut self) -> u64 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.checked_add(1).expect("job id overflow");
        id
    }
}

const SYNC_EXECUTOR_JS_TEMPLATE: &str = include_str!("../js/sync_executor.js");

/// Create a blob URL for the sync executor script with the given URLs embedded.
pub(crate) fn create_sync_executor_url(
    wasm_url: &str,
    bindgen_url: &str,
    num_workers: Option<u32>,
) -> String {
    let js_code = SYNC_EXECUTOR_JS_TEMPLATE
        .replace("__WASM_URL__", wasm_url)
        .replace("__BINDGEN_URL__", bindgen_url)
        .replace(
            "__WORKERS__",
            &num_workers
                .map(|n| n.to_string())
                .unwrap_or(String::from("undefined")),
        );

    let prop = web_sys::BlobPropertyBag::new();
    prop.set_type("application/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(
        &js_sys::Array::of1(&js_code.into()),
        &prop,
    )
    .unwrap();
    web_sys::Url::create_object_url_with_blob(&blob).unwrap()
}

pub(crate) async fn register_sync_executor(
    num_workers: Option<u32>,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), String> {
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();
    let ready_tx = Rc::new(RefCell::new(Some(ready_tx)));

    let sync_executor_url = create_sync_executor_url(wasm_url, bindgen_url, num_workers);

    let executor = Worker::new(&sync_executor_url)
        .map_err(|e| format!("failed to create SyncExecutor: {e:?}"))?;

    // Set up message handler to wait for ready signal
    let ready_tx = ready_tx.clone();
    let onmessage = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
        handle_sync_executor_message(event, &ready_tx)
    }) as Box<dyn FnMut(_)>);

    executor.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();

    // Set up error handler
    let onerror = Closure::wrap(Box::new(move |e: web_sys::ErrorEvent| {
        web_sys::console::error_1(
            &format!(
                "SyncExecutor error: {} at {}:{}",
                e.message(),
                e.filename(),
                e.lineno()
            )
            .into(),
        );
    }) as Box<dyn FnMut(_)>);
    executor.set_onerror(Some(onerror.as_ref().unchecked_ref()));
    onerror.forget();

    // Store executor reference
    SYNC_EXECUTOR.set(Some(SyncExecutor::new(executor)));

    // Wait for SyncExecutor to be ready
    ready_rx
        .await
        .map_err(|_| "SyncExecutor channel closed".to_string())?
        .map_err(|e| format!("SyncExecutor init failed: {e}"))?;

    Ok(())
}

fn handle_sync_executor_message(event: web_sys::MessageEvent, ready_tx: &ReadySender) {
    {
        use crate::messages::SyncExecutorToMain;

        let msg: SyncExecutorToMain = match messages::from_js(event.data()) {
            Ok(m) => m,
            Err(e) => {
                web_sys::console::error_1(
                    &format!("Failed to parse SyncExecutor message: {e}").into(),
                );
                return;
            }
        };
        match msg {
            SyncExecutorToMain::Ready => {
                if let Some(tx) = ready_tx.borrow_mut().take() {
                    let _ = tx.send(Ok(()));
                }
            }
            SyncExecutorToMain::Done(outcome) => {
                SYNC_EXECUTOR.with(|executor| {
                    if let Some(ref mut executor) = *executor.borrow_mut()
                        && let Some(tx) = executor.waiters.remove(&outcome.job_id)
                    {
                        let _ = tx.send(outcome.result);
                    } else {
                        web_sys::console::warn_1(
                            &format!(
                                "SyncExecutor: dropping result for job {}, no waiter",
                                outcome.job_id
                            )
                            .into(),
                        );
                    }
                });
            }
        }
    }
}

/// Entry point called from sync_executor.js bootstrap.
#[wasm_bindgen]
pub fn start_sync_executor(wasm_url: &str, bindgen_url: &str, num_workers: Option<u32>) {
    use crate::worker::create_worker_url;

    let origin = web_sys::Url::new(wasm_url)
        .map(|u| u.origin())
        .unwrap_or_default();

    CoordinatorUrl::set(&origin);

    let global: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();

    // Create blob URL for compute workers (URLs already absolute from main thread)
    let worker_url = create_worker_url(wasm_url, bindgen_url);

    // Initialize the pool with sync result handler
    // We use spawn_local since init_pool_with_handler is async (waits for workers to be ready)
    wasm_bindgen_futures::spawn_local(async move {
        // Wait until the Service Worker is intercepting our requests.
        // When this worker is first created, there's a brief window where it's not
        // yet registered as a client of the SW, so requests would go to the actual server.
        use crate::coordinator::ping_coordinator;
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 100; // 100 * 50ms = 5 seconds max
        loop {
            if ping_coordinator().is_ok() {
                break;
            }
            attempts += 1;
            if attempts >= MAX_ATTEMPTS {
                web_sys::console::error_1(
                    &"SyncExecutor: Service Worker not intercepting requests after timeout".into(),
                );
                return;
            }
            // Sleep for 50ms before retrying
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                let global: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
                global
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 50)
                    .unwrap();
            });
            wasm_bindgen_futures::JsFuture::from(promise).await.ok();
        }

        if let Err(e) = pool::init_pool_with_handler(num_workers, &worker_url, None).await {
            web_sys::console::error_1(&format!("Failed to init pool: {e}").into());
            return;
        }

        // Signal ready to main thread
        send_to_main(&SyncExecutorToMain::Ready);
    });

    // Set up message handler for work requests from main thread
    let onmessage = Closure::wrap(Box::new(handle_job_message) as Box<dyn FnMut(_)>);
    global.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    onmessage.forget();
}

/// Handle messages from the main thread.
fn handle_job_message(event: MessageEvent) {
    let msg: MainToSyncExecutor = match messages::from_js(event.data()) {
        Ok(m) => m,
        Err(e) => {
            web_sys::console::error_1(
                &format!("SyncExecutor: failed to parse message: {e}").into(),
            );
            return;
        }
    };

    match msg {
        MainToSyncExecutor::Job {
            job_id,
            fn_id,
            data,
        } => {
            // Execute the registered function
            let result = crate::registry::execute(fn_id, &data);
            let outcome = JobOutcome { job_id, result };
            send_to_main(&SyncExecutorToMain::Done(outcome));
        }
    }
}

/// Send a message to the main thread.
fn send_to_main(msg: &SyncExecutorToMain) {
    let global: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    match messages::to_js(msg) {
        Ok(js_msg) => {
            if let Err(e) = global.post_message(&js_msg) {
                web_sys::console::error_1(
                    &format!("SyncExecutor: failed to post message: {e:?}").into(),
                );
            }
        }
        Err(e) => {
            web_sys::console::error_1(
                &format!("SyncExecutor: failed to serialize message: {e}").into(),
            );
        }
    }
}

fn send_to_sync_executor(msg: &MainToSyncExecutor) -> Result<(), String> {
    let js_msg = messages::to_js(msg)?;
    SYNC_EXECUTOR.with(|se_worker| {
        se_worker
            .borrow()
            .as_ref()
            .ok_or("pool not initialized")?
            .worker
            .post_message(&js_msg)
            .map_err(|e| format!("{e:?}"))
    })
}

pub async fn execute_async<F, I, O>(f: FnEntry<F>, input: &I) -> Result<O, String>
where
    I: serde::Serialize,
    O: serde::de::DeserializeOwned,
    F: RegisteredFn<Input = I, Output = O>,
{
    // Wrap input in a single-element Vec to match the chunk-based registry format.
    // The registered handler expects Vec<Input> and returns Vec<Output>.
    // We use Vec (not array) because postcard serializes arrays without length prefix,
    // but Vec deserialization expects one.
    let wrapped_input = vec![input];
    let data =
        postcard::to_allocvec(&wrapped_input).map_err(|e| format!("serialize input error: {e}"))?;

    let (tx, rx) = oneshot::channel();
    let job_id = next_job_id()?;

    let job = MainToSyncExecutor::Job {
        job_id,
        fn_id: f.id().clone(),
        data,
    };
    send_to_sync_executor(&job).map_err(|e| format!("Failed to run job on sync executor {e}"))?;

    SYNC_EXECUTOR.with(|executor| -> Result<(), String> {
        let mut executor = executor.borrow_mut();
        let executor = executor.as_mut().ok_or("Sync Executor not initialized")?;

        executor.waiters.insert(job_id, tx);

        Ok(())
    })?;

    let result_bytes: Vec<u8> = rx.await.map_err(|_| "task channel closed".to_string())??;

    // Unwrap the Vec<Output> to get the single result
    let results: Vec<O> =
        postcard::from_bytes(&result_bytes).map_err(|e| format!("deserialize result: {e}"))?;
    results
        .into_iter()
        .next()
        .ok_or_else(|| "empty result from sync executor".to_string())
}

pub(crate) fn next_job_id() -> Result<u64, String> {
    SYNC_EXECUTOR.with(|executor| {
        let mut executor = executor.borrow_mut();
        let executor = executor.as_mut().ok_or("Sync Executor not initialized")?;
        Ok(executor.next_job_id())
    })
}
