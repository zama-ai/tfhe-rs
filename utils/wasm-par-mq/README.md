# wasm-par-mq

Rayon-like parallel iterators for WebAssembly using web workers and message passing.

## Overview

`wasm-par-mq` provides Rayon-like parallel iterators for web environments where COOP/COEP headers cannot be set and `SharedArrayBuffer` is unavailable. It spawns web workers and dispatches work through message queues, which incurs some serialization overhead.

## Features

- **Parallel Iterators** - Familiar Rayon-like API with `par_iter()`, `into_par_iter()`, `map()`, and `collect_vec()`
- **Universal** - No specific server side headers required
- **Compile-time Function Registration** - Type-safe function registration using macros
- **Web Worker Pool** - Automatic worker management with round-robin task distribution
- **Async Execution** - Non-blocking parallel operations using async/await
- **Sync Mode** - Optional blocking mode for easier integration with synchronous code

## Usage

### 1. Register your functions

Since workers do not share memory and cannot exchange pointers, a global registry is used to dispatch work.
Functions must be registered at compile time to be used in parallel operations:

```rust
use wasm_par_mq::register_fn;

fn double(x: u32) -> u32 {
    x * 2
}
// Arguments: function name, input type, return type
register_fn!(double, u32, u32);
```

Current limitations (may be lifted in the future):
- Closures are not supported
- Only functions with exactly one parameter are supported

### 2. Run parallel operations
At the call site, wrap the function in the `par_fn!` macro to retrieve its registry ID:

```rust
use wasm_par_mq::{par_fn, ParallelSlice};

let data: Vec<u32> = (0..1000).collect();

let results = data
    .par_iter()
    .map(par_fn!(double))
    .collect_vec()
    .await;
```

### 3. Initialize the worker pool

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn init_parallel(
    num_workers: u32,
    wasm_url: &str,
    bindgen_url: &str,
) -> Result<(), JsValue> {
    wasm_par_mq::init_pool_async(Some(num_workers), wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}
```

```javascript
import init, { init_parallel } from './pkg/your_crate.js';

await init();
await init_parallel(4, './pkg/your_crate_bg.wasm', './pkg/your_crate.js');
```

## Sync Executor

The default async mode (`collect_vec().await`) requires the calling code to be async.
The sync executor provides a blocking alternative (`collect_vec_sync()`) so that parallel
iterators can be used from synchronous Rust code compiled to WASM.

### How it works

The sync executor introduces a few concepts:

- **SyncExecutor**: a dedicated web worker that runs jobs and blocks until results
  are ready. Because synchronous XHR is forbidden on the main thread, blocking must
  happen inside a worker. The SyncExecutor fills that role: it receives jobs from
  the main thread, dispatches chunks to compute workers, and blocks on the
  Coordinator until all chunks complete.
- **Job**: a call to a registered function that runs inside the SyncExecutor worker.
  The job receives a serialized input from the main thread; it can be kept small to
  minimize the data transferred between threads. The function body can then build or
  load larger data sets and call `par_iter().collect_vec_sync()` on them.
- **Chunk**: when `collect_vec_sync()` is called inside a job, the iterator's data is
  split into chunks that are distributed across compute workers.
- **Coordinator**: a service worker that tracks chunk completion. The SyncExecutor
  blocks on a **synchronous XMLHttpRequest** to the Coordinator, which only responds
  once every chunk has been processed.

```
                                                  Coordinator
  Main Thread        SyncExecutor Worker        (Service Worker)      Workers
  ───────────        ───────────────────        ────────────────      ───────
       │  postMessage(job)  │                         │                  │
       │───────────────────>│                         │                  │
       │                    ├ run job func.           │                  │
       │                    ├ call par_iter()         │                  │
       │                    │                         │                  │
       │                    │  postMessage(chunks)    │                  │
       │                    │─────────────────────────│─────────────────>│
       │                    │                         │                  │
       │                    │  sync XHR GET /wait     │                  │
       │                    │────────────────────────>│                  │
       │                    │                         │    POST /done    │
       │                    │                         │    (chunk res.)  │
       │                    │       (blocked)         │<─────────────────│
       │                    │                         │<─────────────────│
       │                    │                         │                  │
       │                    │<────────────────────────│                  │
       │                    │   (all chunks done)     │                  │
       │  postMessage       │                         │                  │
       │  (result)          │                         │                  │
       │<───────────────────│                         │                  │
```

1. The main thread sends a job (function ID + serialized input) to the SyncExecutor
   via `postMessage`.
2. The SyncExecutor deserializes the input and runs the registered function.
3. When the function calls `collect_vec_sync()`, the data is split into chunks and
   sent to compute workers.
4. Each compute worker processes its chunk and POSTs the result to the Coordinator.
5. Meanwhile the SyncExecutor performs a **synchronous XHR GET** to the Coordinator,
   which blocks until every chunk result has been received.
6. The Coordinator responds with the aggregated results, and the SyncExecutor
   sends the job output back to the main thread.

### Usage

#### 1. Write a sync wrapper for your parallel operation

The function that calls `collect_vec_sync()` runs inside the SyncExecutor worker.
Register it like any other function:

```rust
use wasm_par_mq::{register_fn, par_fn, ParallelIterator, ParallelSlice};

fn double(x: i32) -> i32 { x * 2 }
register_fn!(double, i32, i32);

// This function runs inside the SyncExecutor — it can block.
fn double_all_impl(data: Vec<i32>) -> Vec<i32> {
    data.par_iter().map(par_fn!(double)).collect_vec_sync()
}
register_fn!(double_all_impl, Vec<i32>, Vec<i32>);
```

#### 2. Expose it to JavaScript

Although the job itself runs synchronously inside the SyncExecutor, you still need an
async wrapper on the main thread to avoid blocking it. `execute_async` sends the job
to the SyncExecutor via `postMessage` and returns a `Future` that resolves when the
result comes back. The `sync_fn!` macro retrieves the registry ID of the job function,
similar to what `par_fn!` does for iterator functions:

```rust
use wasm_bindgen::prelude::*;
use wasm_par_mq::{execute_async, sync_fn};

#[wasm_bindgen]
pub async fn double_all_sync(data: Vec<i32>) -> Result<Vec<i32>, JsValue> {
    execute_async(sync_fn!(double_all_impl), &data)
        .await
        .map_err(|e| JsValue::from_str(&e))
}
```

From JavaScript, this is called like any other async WASM export — the main thread
stays responsive while the SyncExecutor does the blocking work in the background.

If your code is already running on a dedicated worker and you used
`init_pool_sync_from_worker`, you don't need `execute_async` or the `sync_fn!`
macro. You can call `collect_vec_sync()` directly since the current worker acts as
the SyncExecutor.

#### 3. Deploy the Coordinator Service Worker

Sync mode uses a Service Worker to coordinate blocking XHR. You need to create a
small Service Worker file whose scope covers your page. The scope defaults to the
directory where the SW file is served, so placing it next to your page is sufficient.

Create a `sw.js`:

```javascript
// sw.js
import { setupCoordinator } from './pkg/coordinator.js';
setupCoordinator();
```

`coordinator.js` ships with the npm package (or can be copied from `js/coordinator.js`
in this repository). It must be served at the path you import from above.

**Bundler users** (Vite, webpack, etc.): the bundler resolves the import, so
`coordinator.js` is inlined automatically — no extra file to deploy.

**Static file users**: copy `coordinator.js` next to your wasm-bindgen output
(e.g. into `pkg/`) and adjust the import path in `sw.js` accordingly.

#### 4. Initialize in sync mode

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn init_parallel_sync(
    num_workers: u32,
    wasm_url: &str,
    bindgen_url: &str,
    coordinator_url: &str,
) -> Result<(), JsValue> {
    // register_coordinator must be called from the main thread.
    //
    // You can then either:
    // - call init_pool_sync here (from the main thread), which spawns a
    //   dedicated SyncExecutor worker, or
    // - call init_pool_sync_from_worker from a worker you manage yourself,
    //   which reuses that worker as the SyncExecutor. This avoids the extra
    //   SyncExecutor worker and the message-passing round-trip between the
    //   main thread and the executor.
    wasm_par_mq::register_coordinator(coordinator_url)
        .await
        .map_err(|e| JsValue::from_str(&e))?;
    wasm_par_mq::init_pool_sync(Some(num_workers), wasm_url, bindgen_url)
        .await
        .map_err(|e| JsValue::from_str(&e))
}
```

```javascript
import init, { init_parallel_sync } from './pkg/your_crate.js';

await init();
// The coordinator_url must point to the SW file created above.
await init_parallel_sync(4, './pkg/your_crate_bg.wasm', './pkg/your_crate.js', '/sw.js');
```

## API

### Macros

- `register_fn!(fn_name, InputType, OutputType)` - Register a function for parallel execution
- `par_fn!(fn_name)` - Get a registered function for use with parallel iterators

### Traits

- `ParallelIterator` - Core trait for parallel iteration
- `IntoParallelIterator` - Convert collections into parallel iterators
- `ParallelSlice` - Extension trait adding `par_iter()` to slices

### Functions

- `init_pool_async(num_workers, wasm_url, bindgen_url)` - Initialize the worker pool in async mode
- `register_coordinator(coordinator_url)` - Register the coordinator service worker (sync mode)
- `init_pool_sync(num_workers, wasm_url, bindgen_url)` - Initialize the worker pool in sync mode (coordinator must be registered first)
- `init_pool_sync_from_worker(num_workers, wasm_url, bindgen_url)` - Initialize in sync mode, reusing the current worker as SyncExecutor
- `start_worker()` - Entry point for compute workers

## Examples

See `examples/msm` for a complete example.
