// Minimal sync executor bootstrap - all logic is in Rust
// URLs and config are injected at runtime via string replacement
const wasmUrl = "__WASM_URL__";
const bindgenUrl = "__BINDGEN_URL__";
const numWorkers = __WORKERS__;

import(bindgenUrl).then(async (module) => {
    await module.default(wasmUrl);
    module.start_sync_executor(wasmUrl, bindgenUrl, numWorkers);
}).catch(e => console.error('SyncExecutor init failed:', e));
