import { threads } from "wasm-feature-detect";

/**
 * Boot the wasm pkg and pick the right thread-pool strategy.
 * The pkg is passed in (not imported here) so the same helper works
 * against both the full and the client builds.
 *
 * @param {object} pkg - The wasm-bindgen-generated pkg namespace
 *   (e.g. `await import("/pkg/tfhe.js")`).
 */
export async function initRuntime(pkg) {
  await pkg.default();

  if (await threads()) {
    await pkg.initThreadPool(navigator.hardwareConcurrency);
  } else {
    console.warn(
      "This browser does not support threads, using cross-origin workers",
    );
    // We are already in a web Worker, from_worker will reuse it as SyncExecutor
    await pkg.init_cross_origin_worker_pool_from_worker();
  }

  await pkg.init_panic_hook();
}
