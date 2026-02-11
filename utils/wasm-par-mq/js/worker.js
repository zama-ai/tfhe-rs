// Minimal worker bootstrap - all logic is in Rust
// URLs are injected at runtime via string replacement
const wasmUrl = "__WASM_URL__";
const bindgenUrl = "__BINDGEN_URL__";

import(bindgenUrl).then(async (module) => {
    await module.default(wasmUrl);
    module.start_worker(new URL(wasmUrl).origin);
}).catch(e => console.error('Worker init failed:', e));
