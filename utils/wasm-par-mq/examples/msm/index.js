import init, * as wasm_bindgen from "./pkg/wasm_par_mq_example_msm.js";

const status = document.getElementById("status");
const poolStatus = document.getElementById("pool-status");
const workerCountSelect = document.getElementById("worker-count");
const poolModeSelect = document.getElementById("pool-mode");

// Read mode and worker count from URL parameters (for persistence across reloads)
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.has("mode")) {
  poolModeSelect.value = urlParams.get("mode");
}
if (urlParams.has("workers")) {
  workerCountSelect.value = urlParams.get("workers");
}
const msmLenSelect = document.getElementById("msm-len");
const buttons = {
  msmParallel: document.getElementById("btn-msm-parallel"),
  msmSync: document.getElementById("btn-msm-sync"),
  msmSequential: document.getElementById("btn-msm-sequential"),
  msmCompare: document.getElementById("btn-msm-compare"),
};
const results = {
  msm: document.getElementById("result-msm"),
};

let currentWorkerCount = 4;
let currentPoolMode = "async";

function showResult(el, text, isError = false) {
  el.textContent = text;
  el.hidden = false;
  el.classList.toggle("error", isError);
}

async function initPool(numWorkers, mode) {
  currentWorkerCount = numWorkers;
  currentPoolMode = mode;
  poolStatus.textContent = `(${numWorkers} workers, ${mode} mode)`;
  status.textContent = `Starting worker pool (${mode} mode)...`;

  if (mode === "sync") {
    await wasm_bindgen.init_parallel_sync(numWorkers, "/coordinator.js");
  } else {
    await wasm_bindgen.init_parallel(numWorkers);
  }
  status.textContent = "Ready! Click a button to test.";
  status.className = "status-ready";
}

function updateButtonStates() {
  const isSyncMode = currentPoolMode === "sync";
  // Sync executor button only works in sync mode
  buttons.msmSync.disabled = !isSyncMode;
  // Async parallel buttons only work in async mode
  buttons.msmParallel.disabled = isSyncMode;
  buttons.msmCompare.disabled = isSyncMode;
}

async function main() {
  try {
    // Initialize WASM (web target uses ES module default export)
    status.textContent = "Initializing WASM...";
    await init();

    // Initialize the parallel pool
    const numWorkers = parseInt(workerCountSelect.value, 10);
    const mode = poolModeSelect.value;
    await initPool(numWorkers, mode);

    // Enable buttons
    Object.values(buttons).forEach((btn) => (btn.disabled = false));

    // Update button states based on mode
    updateButtonStates();
  } catch (e) {
    status.textContent = `Error: ${e}`;
    status.className = "status-error";
    console.error(e);
  }
}

// Button handlers
buttons.msmParallel.onclick = async () => {
  buttons.msmParallel.disabled = true;
  try {
    const len = parseInt(msmLenSelect.value, 10);

    status.textContent = "Generating test data...";
    const data = wasm_bindgen.generate_test_data(len);

    status.textContent = "Running parallel MSM...";
    const start = performance.now();
    const result = await wasm_bindgen.run_msm_parallel(data);
    const elapsed = (performance.now() - start).toFixed(2);

    status.textContent = "Ready! Click a button to test.";
    showResult(
      results.msm,
      `[PARALLEL - ${currentWorkerCount} workers]\n` +
        `Elements: ${len}\n` +
        `Result: ${JSON.stringify(result)}\n` +
        `Time: ${elapsed}ms`,
    );
  } catch (e) {
    status.textContent = "Ready! Click a button to test.";
    showResult(results.msm, `Error: ${e}`, true);
  }
  buttons.msmParallel.disabled = false;
};

buttons.msmSync.onclick = async () => {
  buttons.msmSync.disabled = true;
  try {
    const len = parseInt(msmLenSelect.value, 10);

    status.textContent = "Generating test data...";
    const data = wasm_bindgen.generate_test_data(len);

    status.textContent = "Running sync executor MSM...";
    const start = performance.now();
    const result = await wasm_bindgen.run_msm_sync(data);
    const elapsed = (performance.now() - start).toFixed(2);

    status.textContent = "Ready! Click a button to test.";
    showResult(
      results.msm,
      `[SYNC EXECUTOR - ${currentWorkerCount} workers]\n` +
        `Elements: ${len}\n` +
        `Result: ${JSON.stringify(result)}\n` +
        `Time: ${elapsed}ms`,
    );
  } catch (e) {
    status.textContent = "Ready! Click a button to test.";
    showResult(results.msm, `Error: ${e}`, true);
  }
  buttons.msmSync.disabled = false;
};

buttons.msmSequential.onclick = () => {
  buttons.msmSequential.disabled = true;
  try {
    const len = parseInt(msmLenSelect.value, 10);

    status.textContent = "Generating test data...";
    const data = wasm_bindgen.generate_test_data(len);

    status.textContent = "Running sequential MSM...";
    const start = performance.now();
    const result = wasm_bindgen.run_msm_sequential(data);
    const elapsed = (performance.now() - start).toFixed(2);

    status.textContent = "Ready! Click a button to test.";
    showResult(
      results.msm,
      `[SEQUENTIAL]\n` +
        `Elements: ${len}\n` +
        `Result: ${JSON.stringify(result)}\n` +
        `Time: ${elapsed}ms`,
    );
  } catch (e) {
    status.textContent = "Ready! Click a button to test.";
    showResult(results.msm, `Error: ${e}`, true);
  }
  buttons.msmSequential.disabled = false;
};

buttons.msmCompare.onclick = async () => {
  buttons.msmCompare.disabled = true;
  try {
    const len = parseInt(msmLenSelect.value, 10);

    status.textContent = "Generating test data...";
    const data = wasm_bindgen.generate_test_data(len);

    status.textContent = "Running sequential then parallel MSM...";
    const start = performance.now();
    const result = await wasm_bindgen.run_msm_compare(data);
    const elapsed = (performance.now() - start).toFixed(2);

    status.textContent = "Ready! Click a button to test.";
    showResult(
      results.msm,
      `[COMPARE - ${currentWorkerCount} workers]\n` +
        `Elements: ${len}\n` +
        `${result}\n` +
        `Total time: ${elapsed}ms`,
    );
  } catch (e) {
    status.textContent = "Ready! Click a button to test.";
    showResult(results.msm, `Error: ${e}`, true);
  }
  buttons.msmCompare.disabled = false;
};

main();
