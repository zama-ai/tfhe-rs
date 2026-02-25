import { threads } from "wasm-feature-detect";
import * as Comlink from "comlink";
import init, {
  register_cross_origin_coordinator
} from "./pkg/tfhe.js";

function setButtonsDisabledState(buttonIds, state) {
  for (let id of buttonIds) {
    let btn = document.getElementById(id);
    if (btn) {
      btn.disabled = state;
    }
  }
}

async function setup() {
  let supportsThreads = await threads();
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
    await init();
    await register_cross_origin_coordinator("/sw.js");
  }

  const worker = new Worker(new URL("./worker.js", import.meta.url), {
    type: "module",
  });

  const demos = await Comlink.wrap(worker).demos;

  const demoNames = [
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
  ];

  function setupBtn(id) {
    let button = document.getElementById(id);
    if (button === null) {
      console.error(`button with id: ${id} not found`);
      return null;
    }

    // Assign onclick handler + enable the button.
    button.onclick = async () => {
      document.getElementById("loader").hidden = false;
      document.getElementById("testSuccess").checked = false;
      setButtonsDisabledState(demoNames, true);

      let fn = demos[id];
      console.log(`Running: ${id}`);
      try {
        let results = await fn();
        document.getElementById("testSuccess").checked = true;
        if (results !== undefined) {
          document.getElementById("benchmarkResults").value =
            JSON.stringify(results);
        }
      } catch (error) {
        console.error(`Test Failed: ${error}`);
        document.getElementById("testSuccess").checked = false;
      }
      document.getElementById("loader").hidden = true;
      setButtonsDisabledState(demoNames, false);
    };
    button.disabled = false;

    return button;
  }

  for (let demo of demoNames) {
    setupBtn(demo);
  }
}

setup();
