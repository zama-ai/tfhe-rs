import { threads } from "wasm-feature-detect";
import * as Comlink from "comlink";
import { asyncMainThreadCompactPublicKeyZeroKnowledgeTest } from "./full/tests/zk.js";

const IS_CLIENT = new URLSearchParams(window.location.search).has("client");

// Names of demos exposed by the worker via Comlink. Must match the keys in
// `Comlink.proxy({ ... })` in the corresponding worker.js AND the button ids
// in index.html.
const WORKER_DEMO_NAMES_FULL = Object.freeze([
  "publicKeyTest",
  "compressedPublicKeyTest",
  "compressedCompactPublicKeyTest256BitBig",
  "compressedCompactPublicKeyTest256BitSmall",
  "compactPublicKeyZeroKnowledgeTest",
  "compactPublicKeyBench32BitBig",
  "compactPublicKeyBench32BitSmall",
  "compactPublicKeyBench256BitBig",
  "compactPublicKeyBench256BitSmall",
  "compactPublicKeyWithCastingTest256Bit",
  "compressedCompactPublicKeyWithCastingTest256Bit",
  "compressedServerKeyBenchMessage1Carry1",
  "compressedServerKeyBenchMessage2Carry2",
  "compactPublicKeyZeroKnowledgeBench",
  "x86CompatTest",
  "x86CompatBench",
]);

// Subset of demos supported by the client pkg.
const WORKER_DEMO_NAMES_CLIENT = Object.freeze([
  "x86CompatTest",
  "x86CompatBench",
]);

const WORKER_DEMO_NAMES = IS_CLIENT
  ? WORKER_DEMO_NAMES_CLIENT
  : WORKER_DEMO_NAMES_FULL;

// Main-thread demos are full-only (they use set_server_key & friends).
const MAIN_THREAD_DEMOS = IS_CLIENT
  ? Object.freeze({})
  : Object.freeze({ asyncMainThreadCompactPublicKeyZeroKnowledgeTest });
const MAIN_THREAD_DEMO_NAMES = Object.keys(MAIN_THREAD_DEMOS);

const PKG_URL = IS_CLIENT ? "./pkg-client/tfhe.js" : "./pkg/tfhe.js";

// Worker URLs must be static literals so webpack can statically resolve and
// bundle each worker separately. We instantiate only the relevant one at runtime.
function createWorker() {
  return IS_CLIENT
    ? new Worker(new URL("./client/worker.js", import.meta.url), {
        type: "module",
      })
    : new Worker(new URL("./full/worker.js", import.meta.url), {
        type: "module",
      });
}

function setButtonsDisabledState(buttonIds, state) {
  for (const id of buttonIds) {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = state;
    }
  }
}

async function setup() {
  console.info(`Running in ${IS_CLIENT ? "client" : "full"} mode`);

  const supportsThreads = await threads();
  if (crossOriginIsolated) {
    if (supportsThreads) {
      console.info("Running in multithreaded mode");
    } else {
      console.error("This browser does not support threads");
      return;
    }
  } else {
    // Register the coordinator Service Worker for cross-origin parallelism
    console.info("Running in cross-origin worker mode");
    const pkg = await import(/* webpackIgnore: true */ PKG_URL);
    await pkg.default();
    await pkg.register_cross_origin_coordinator("/coordinator.js");
  }

  const worker = createWorker();

  const demos = await Comlink.wrap(worker).demos;

  const allDemoNames = [...WORKER_DEMO_NAMES, ...MAIN_THREAD_DEMO_NAMES];

  const loader = document.getElementById("loader");
  const testSuccess = document.getElementById("testSuccess");
  const benchmarkResults = document.getElementById("benchmarkResults");
  const benchmarkResultsView = document.getElementById("benchmarkResultsView");
  const statusEl = document.getElementById("status");
  const statusLabel = statusEl.querySelector(".label");
  const copyBtn = document.getElementById("copyResults");

  function setStatus(state, text) {
    statusEl.classList.remove("success", "error");
    if (state) statusEl.classList.add(state);
    statusLabel.textContent = text;
  }

  function setResults(value) {
    // Keep the hidden <input> in sync for CI webdriver assertions.
    benchmarkResults.value = value ?? "";
    benchmarkResultsView.textContent = value ?? "";
    copyBtn.disabled = !value;
  }

  copyBtn.onclick = async () => {
    if (!benchmarkResultsView.textContent) return;
    try {
      await navigator.clipboard.writeText(benchmarkResultsView.textContent);
      const original = copyBtn.value;
      copyBtn.value = "Copied!";
      setTimeout(() => {
        copyBtn.value = original;
      }, 1000);
    } catch (err) {
      console.error("Clipboard write failed:", err);
    }
  };

  function setupBtn(id, fn) {
    const button = document.getElementById(id);
    if (button === null) {
      console.error(`button with id: ${id} not found`);
      return null;
    }

    button.onclick = async () => {
      loader.hidden = false;
      testSuccess.checked = false;
      setStatus(null, `running ${id}…`);
      setButtonsDisabledState(allDemoNames, true);

      console.log(`Running: ${id}`);
      try {
        const results = await fn();
        testSuccess.checked = true;
        if (results !== undefined) {
          setResults(JSON.stringify(results, null, 2));
        }
        setStatus("success", `ok — ${id}`);
      } catch (error) {
        console.error(`Test Failed: ${error}`);
        testSuccess.checked = false;
        setStatus("error", `failed — ${id}`);
      }
      loader.hidden = true;
      setButtonsDisabledState(allDemoNames, false);
    };
    button.disabled = false;

    return button;
  }

  for (const demo of WORKER_DEMO_NAMES) {
    setupBtn(demo, demos[demo]);
  }

  // Main-thread demos need the SyncExecutor initialized on the main thread.
  if (!crossOriginIsolated && MAIN_THREAD_DEMO_NAMES.length > 0) {
    const pkg = await import(/* webpackIgnore: true */ PKG_URL);
    await pkg.init_cross_origin_worker_pool("/coordinator.js", null);
    await pkg.init_panic_hook();

    for (const demo of MAIN_THREAD_DEMO_NAMES) {
      setupBtn(demo, MAIN_THREAD_DEMOS[demo]);
    }
  }
}

setup();
