// Worker pool helpers for wasm-par-mq.
//
// Inspired by wasm-bindgen-rayon's workerHelpers.js pattern.
//
// It serves dual purpose:
// 1. When imported as a module (main thread / sync executor): exports helper
//    functions used by the Rust pool code.
// 2. When loaded as a Worker entry point: bootstraps compute workers or the
//    sync executor based on the Worker's `name` option.
//
// This file is included as a wasm-bindgen snippet via
// `#[wasm_bindgen(module = "/js/worker_helpers.js")]` and placed at
// `pkg/snippets/wasm-par-mq-<hash>/js/worker_helpers.js`. With this trick,
// wasm-bindgen handles the copy of this js file, nothing is done by the user.
//
// The consuming crate's bindgen JS is loaded via `import('../../..')`, which
// resolves to the package root (3 levels up from the snippet location).
// For no-bundler usage (--target=web), the import path may need patching.

// These names are used to detect if this script is loaded as a worker entrypoint or as a module
export const WORKER_NAME = "wasm_par_mq_worker";
export const SYNC_EXECUTOR_NAME = "wasm_par_mq_sync_executor";

// === Purpose 1: Worker bootstrap (runs only when loaded as a Worker) ===

// `self` is not defined in Node.js. Skip worker bootstrap here.
if (typeof self !== "undefined") {
  // Compute worker
  if (self.name === WORKER_NAME) {
    addEventListener(
      "message",
      async () => {
        const mod = await import("../../..");
        await mod.default();
        mod.start_worker(self.location.origin);
      },
      { once: true },
    );

    // Sync executor
  } else if (self.name === SYNC_EXECUTOR_NAME) {
    addEventListener(
      "message",
      async ({ data: { numWorkers } }) => {
        const mod = await import("../../..");
        await mod.default();
        mod.start_sync_executor(numWorkers);
      },
      { once: true },
    );
  }
}

// === Purpose 2: Utils for rust bindings (imported as a module) ===

// Return the origin of the current context (works in both main thread and workers).
// Used by Rust code to derive the coordinator URL without relying on import.meta.url.
export function getWorkerOrigin() {
  return self.location.origin;
}

// Worker creation helpers.
//
// They use the `new Worker(new URL(...), ...)` pattern
// that bundlers recognize and process as a worker entry point, resolving imports
// inside the worker automatically.
// See: https://webpack.js.org/guides/web-workers/

// Create a compute worker
export function createComputeWorker() {
  return new Worker(new URL("./worker_helpers.js", import.meta.url), {
    type: "module",
    name: WORKER_NAME,
  });
}

// Create a sync executor worker
export function createSyncExecutorWorker() {
  return new Worker(new URL("./worker_helpers.js", import.meta.url), {
    type: "module",
    name: SYNC_EXECUTOR_NAME,
  });
}
