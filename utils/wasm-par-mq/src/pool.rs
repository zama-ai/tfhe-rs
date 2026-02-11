//! Worker pool for parallel execution.
//!
//! Manages a pool of web workers and distributes tasks across them.
//! Supports both async (main thread) and sync (SyncExecutor) result handling.

#[cfg(feature = "sync-api")]
use crate::coordinator::{
    CoordinatorUrl, cancel_task, register_task, wait_for_coordinator, wait_task,
};
use crate::global_this;
use crate::messages::{self, MainToWorker, WorkerToMain};
use crate::registry::{FnEntry, RegisteredFn, init_registry};
#[cfg(feature = "sync-api")]
use crate::sync_executor::register_sync_executor;
use crate::worker::{create_worker_url, resolve_url};
use futures::channel::oneshot;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use web_sys::Worker;

pub(crate) type ReadySender = Rc<RefCell<Option<oneshot::Sender<Result<(), String>>>>>;

thread_local! {
    static POOL: RefCell<Option<WorkerPool>> = const { RefCell::new(None) };
}

/// Get the number of logical CPUs via `navigator.hardwareConcurrency`.
fn get_hardware_concurrency() -> u32 {
    // Try with Window (main thread)
    if let Some(window) = web_sys::window() {
        return window.navigator().hardware_concurrency() as u32;
    }

    // Try with DedicatedWorkerGlobalScope (SyncExecutor)
    #[cfg(feature = "sync-api")]
    if let Ok(worker) = global_this().dyn_into::<web_sys::DedicatedWorkerGlobalScope>() {
        return worker.navigator().hardware_concurrency() as u32;
    }

    // Fallback
    4
}

/// How results are delivered to the caller
pub(crate) struct AsyncResultHandler {
    /// Results are delivered via oneshot channels
    waiters: HashMap<u64, oneshot::Sender<Result<Vec<u8>, String>>>,
}

impl AsyncResultHandler {
    fn new() -> Self {
        Self {
            waiters: HashMap::new(),
        }
    }

    /// Handle an incoming result from a worker
    fn handle_result(&mut self, chunk_id: u64, result: Result<Vec<u8>, String>) {
        if let Some(tx) = self.waiters.remove(&chunk_id) {
            let _ = tx.send(result);
        }
    }

    /// Register an async waiter for a chunk (only valid in Async mode)
    fn register_waiter(&mut self, chunk_id: u64, tx: oneshot::Sender<Result<Vec<u8>, String>>) {
        self.waiters.insert(chunk_id, tx);
    }
}

struct WorkerPool {
    workers: Vec<Worker>,
    // In async mode, the result handle is used to send the results to the correct task
    result_handler: Option<AsyncResultHandler>,
    // In sync mode, the coordinator needs a task id to be able to send back results
    // to the correct task
    #[cfg(feature = "sync-api")]
    next_task_id: u64,
    next_chunk_id: u64,
    next_worker: u32,
}

impl WorkerPool {
    fn new(result_handler: Option<AsyncResultHandler>) -> Self {
        Self {
            workers: Vec::new(),
            result_handler,
            #[cfg(feature = "sync-api")]
            next_task_id: 0,
            next_chunk_id: 0,
            next_worker: 0,
        }
    }

    fn num_workers(&self) -> u32 {
        self.workers
            .len()
            .try_into()
            .expect("workers len should not be > u32::MAX and usize is 32b on wasm")
    }

    #[cfg(feature = "sync-api")]
    fn next_task_id(&mut self) -> u64 {
        let id = self.next_task_id;
        self.next_task_id = self.next_task_id.checked_add(1).expect("task id overflow");
        id
    }

    fn next_chunk_id(&mut self) -> u64 {
        let id = self.next_chunk_id;
        self.next_chunk_id = self
            .next_chunk_id
            .checked_add(1)
            .expect("chunk id overflow");
        id
    }

    fn next_worker_idx(&mut self) -> u32 {
        let num = self.num_workers();
        if num == 0 {
            return 0;
        }
        let idx = self.next_worker;
        self.next_worker = idx.checked_add(1).expect("worker idx overflow") % num;
        idx
    }
}

/// Initialize the parallel execution pool in async mode.
///
/// Workers are spawned directly from the main thread and results are delivered
/// via async/await.
///
/// The compute workers are automatically embedded (no need to serve worker.js).
///
/// # Arguments
/// * `num_workers` - Number of workers. If `None`, auto-detects via `hardwareConcurrency`.
/// * `wasm_url` - URL to the WASM module
/// * `bindgen_url` - URL to the wasm-bindgen JS glue
///
/// # Example
/// ```ignore
/// init_pool_async(None, "/pkg/app_bg.wasm", "/pkg/app.js").await?;
/// ```
pub async fn init_pool_async(
    num_workers: Option<u32>,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), String> {
    // Resolve relative URLs to absolute - required because blob URL workers
    // cannot resolve relative imports
    let wasm_url = resolve_url(wasm_url);
    let bindgen_url = resolve_url(bindgen_url);
    // Create blob URL with embedded absolute URLs
    let worker_url = create_worker_url(&wasm_url, &bindgen_url);
    init_pool_with_handler(num_workers, &worker_url, Some(AsyncResultHandler::new())).await
}

/// Initialize the pool with a custom result handler.
///
/// Used internally by `init_pool_async` and `SyncExecutor` (sync).
pub(crate) async fn init_pool_with_handler(
    num_workers: Option<u32>,
    worker_url: &str,
    result_handler: Option<AsyncResultHandler>,
) -> Result<(), String> {
    init_registry();

    let num_workers = num_workers.unwrap_or_else(get_hardware_concurrency);

    let already_initialized = POOL.with(|pool| {
        if pool.borrow().is_some() {
            return true;
        }
        *pool.borrow_mut() = Some(WorkerPool::new(result_handler));
        false
    });

    if already_initialized {
        return Ok(());
    }

    let workers_ready = Rc::new(RefCell::new(0));
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();
    let ready_tx = Rc::new(RefCell::new(Some(ready_tx)));

    for i in 0..num_workers {
        // worker_url is a blob URL with wasm/bindgen URLs already embedded
        let worker =
            Worker::new(worker_url).map_err(|e| format!("failed to create worker: {e:?}"))?;

        // Set up message handler
        let workers_ready = workers_ready.clone();
        let ready_tx_clone = ready_tx.clone();
        let onmessage = Closure::wrap(Box::new(move |event: web_sys::MessageEvent| {
            handle_worker_message(event, &workers_ready, &ready_tx_clone, num_workers);
        }) as Box<dyn FnMut(_)>);

        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        // Set up error handler
        let onerror = Closure::wrap(Box::new(move |e: web_sys::ErrorEvent| {
            web_sys::console::error_1(
                &format!(
                    "Worker {} error: {} at {}:{}",
                    i,
                    e.message(),
                    e.filename(),
                    e.lineno()
                )
                .into(),
            );
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);

        worker.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        POOL.with(|pool| {
            pool.borrow_mut()
                .as_mut()
                .expect("pool exists at this point")
                .workers
                .push(worker);
        });
    }

    // Wait for all workers to be ready
    ready_rx
        .await
        .map_err(|_| "worker channel closed".to_string())?
        .map_err(|e| format!("worker init failed: {e}"))?;

    Ok(())
}

/// Initialize pool in sync mode.
///
/// Spawns a SyncExecutor worker which manages compute workers.
/// Enables blocking `collect_vec_sync()` calls.
///
/// # Arguments
/// * `num_workers` - Number of workers. If `None`, auto-detects via `hardwareConcurrency`.
/// * `wasm_url` - URL to the WASM module
/// * `bindgen_url` - URL to the wasm-bindgen JS glue
///
/// # Warning
/// The coordinator Service Worker must already be registered from the main
/// thread (via [`register_coordinator`]) before calling this.
#[cfg(feature = "sync-api")]
pub async fn init_pool_sync(
    num_workers: Option<u32>,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), String> {
    // Resolve relative URLs to absolute - required because blob URL workers
    // cannot resolve relative imports
    let wasm_url = resolve_url(wasm_url);
    let bindgen_url = resolve_url(bindgen_url);
    register_sync_executor(num_workers, &wasm_url, &bindgen_url).await?;

    Ok(())
}

/// Initialize pool in sync mode, reusing the current worker as SyncExecutor.
///
/// Use this when your code is already running in a dedicated worker and you
/// want to call `collect_vec_sync()` directly, without spawning a separate
/// SyncExecutor worker.
///
/// # Arguments
/// * `num_workers` - Number of workers. If `None`, auto-detects via `hardwareConcurrency`.
/// * `wasm_url` - URL to the WASM module
/// * `bindgen_url` - URL to the wasm-bindgen JS glue
///
/// # Warning
/// The coordinator Service Worker must already be registered from the main
/// thread (via [`register_coordinator`]) before calling this.
#[cfg(feature = "sync-api")]
pub async fn init_pool_sync_from_worker(
    num_workers: Option<u32>,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), String> {
    let origin = web_sys::Url::new(wasm_url)
        .map(|u| u.origin())
        .unwrap_or_default();

    CoordinatorUrl::set(&origin);

    wait_for_coordinator().await?;

    let worker_url = create_worker_url(wasm_url, bindgen_url);
    init_pool_with_handler(num_workers, &worker_url, None).await
}

fn handle_worker_message(
    event: web_sys::MessageEvent,
    workers_ready: &Rc<RefCell<u32>>,
    ready_tx: &ReadySender,
    num_workers: u32,
) {
    let msg: WorkerToMain = match messages::from_js(event.data()) {
        Ok(m) => m,
        Err(e) => {
            web_sys::console::error_1(&format!("Failed to parse worker message: {e}").into());
            return;
        }
    };

    match msg {
        WorkerToMain::Ready => {
            let mut ready_count = workers_ready.borrow_mut();
            *ready_count += 1;
            if *ready_count == num_workers
                && let Some(tx) = ready_tx.borrow_mut().take()
            {
                let _ = tx.send(Ok(()));
            }
        }
        WorkerToMain::Done(chunk_outcome) => {
            POOL.with(|pool| {
                if let Some(ref mut p) = *pool.borrow_mut()
                    && let Some(handler) = p.result_handler.as_mut()
                {
                    handler.handle_result(chunk_outcome.chunk_id, chunk_outcome.result)
                } else {
                    // Not a lot to do here apart from logging
                    web_sys::console::warn_1(
                        &format!(
                            "Pool: dropping result for chunk {}, no handler available",
                            chunk_outcome.chunk_id
                        )
                        .into(),
                    );
                }
            });
        }
    }
}

fn send_to_worker(worker: &Worker, msg: &MainToWorker) -> Result<(), String> {
    let js_msg = messages::to_js(msg)?;
    worker.post_message(&js_msg).map_err(|e| format!("{e:?}"))
}

/// Check if the pool has been initialized
pub fn is_pool_initialized() -> bool {
    POOL.with(|pool| pool.borrow().is_some())
}

/// Get the number of workers in the pool
pub fn num_workers() -> u32 {
    POOL.with(|pool| pool.borrow().as_ref().map(|p| p.num_workers()).unwrap_or(0))
}

/// Submit a task to a worker and return a receiver for the result
fn submit_chunk<F: RegisteredFn>(
    f: FnEntry<F>,
    data: Vec<u8>,
) -> Result<oneshot::Receiver<Result<Vec<u8>, String>>, String> {
    POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let pool = pool.as_mut().ok_or("pool not initialized")?;

        let chunk_id = pool.next_chunk_id();
        let (tx, rx) = oneshot::channel();
        let handler = pool
            .result_handler
            .as_mut()
            // Async submission requires result_handler (oneshot channels).
            // In sync mode, results go through the coordinator instead; mixing is not supported.
            // Maybe at some point we could add some static typing tricks to check that they are
            // not mixed but it would require a larger refactor.
            .ok_or("pool initialized in sync mode, but called async API (collect_vec). Use collect_vec_sync instead.")?;
        handler.register_waiter(chunk_id, tx);

        let worker_idx = pool.next_worker_idx();
        if let Some(worker) = pool.workers.get(worker_idx as usize) {
            send_to_worker(
                worker,
                &MainToWorker {
                    chunk_id,
                    fn_id: f.id().clone(),
                    data,
                    #[cfg(feature = "sync-api")]
                    task_id: None,
                },
            )?;
        }

        Ok(rx)
    })
}

/// Submit a task without waiting for the result (sync mode).
/// Returns the chunk_id for later retrieval.
#[cfg(feature = "sync-api")]
pub(crate) fn submit_chunk_sync<F: RegisteredFn>(
    f: FnEntry<F>,
    data: Vec<u8>,
    task_id: u64,
) -> Result<(), String> {
    POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let pool = pool.as_mut().ok_or("pool not initialized")?;

        let chunk_id = pool.next_chunk_id();

        let worker_idx = pool.next_worker_idx();
        if let Some(worker) = pool.workers.get(worker_idx as usize) {
            send_to_worker(
                worker,
                &MainToWorker {
                    chunk_id,
                    fn_id: f.id().clone(),
                    data,
                    task_id: Some(task_id),
                },
            )?;
        }

        Ok(())
    })
}

/// Execute a parallel map operation across workers
pub(crate) async fn execute_par_map<F, I, O>(f: FnEntry<F>, data: &[I]) -> Result<Vec<O>, String>
where
    I: serde::Serialize,
    O: serde::de::DeserializeOwned,
    F: RegisteredFn<Input = I, Output = O>,
{
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let num_workers = num_workers();

    if num_workers == 0 {
        return Err("No workers initialized".to_string());
    }

    let chunk_size = data.len().div_ceil(num_workers as usize);
    let chunks = data.chunks(chunk_size);

    let mut receivers = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let chunk_bytes =
            postcard::to_allocvec(&chunk).map_err(|e| format!("serialize chunk error: {e}"))?;
        let rx = submit_chunk::<F>(f.clone(), chunk_bytes)?;
        receivers.push(rx);
    }

    let mut results = Vec::new();
    for rx in receivers {
        let result_bytes = rx.await.map_err(|_| "task channel closed".to_string())??;
        let chunk_results: Vec<O> =
            postcard::from_bytes(&result_bytes).map_err(|e| format!("deserialize result: {e}"))?;
        results.extend(chunk_results);
    }

    Ok(results)
}

#[cfg(feature = "sync-api")]
pub(crate) fn execute_par_map_sync<F, I, O>(f: FnEntry<F>, data: &[I]) -> Result<Vec<O>, String>
where
    I: serde::Serialize,
    O: serde::de::DeserializeOwned,
    F: RegisteredFn<Input = I, Output = O>,
{
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let num_workers = num_workers();

    if num_workers == 0 {
        return Err("No workers initialized".to_string());
    }

    let task_id = next_task_id()?;

    let chunk_size = data.len().div_ceil(num_workers as usize);
    let chunks = data.chunks(chunk_size);
    // Register the task in the coordinator
    register_task(task_id, chunks.len())?;

    // Send all chunks to workers
    for chunk in chunks {
        let chunk_res = postcard::to_allocvec(&chunk)
            .map_err(|e| format!("serialize chunk error: {e}"))
            .and_then(|chunk_bytes| submit_chunk_sync::<F>(f.clone(), chunk_bytes, task_id));
        if let Err(e) = chunk_res {
            cancel_task(task_id)?;
            return Err(e);
        }
    }

    // Block on the coordinator until the task completes
    let res_chunks = wait_task(task_id)?;

    let mut results = Vec::with_capacity(data.len());
    for result_bytes in res_chunks {
        let chunk_results: Vec<O> =
            postcard::from_bytes(&result_bytes).map_err(|e| format!("deserialize result: {e}"))?;
        results.extend(chunk_results);
    }

    Ok(results)
}

#[cfg(feature = "sync-api")]
pub(crate) fn next_task_id() -> Result<u64, String> {
    POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let pool = pool.as_mut().ok_or("pool not initialized")?;
        Ok(pool.next_task_id())
    })
}
