import { threads } from "wasm-feature-detect";
import * as Comlink from "comlink";

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
  if (!supportsThreads) {
    console.error("This browser does not support threads");
    return;
  }

  const worker = new Worker(new URL("worker.js", import.meta.url), {
    type: "module",
  });
  const demos = await Comlink.wrap(worker).demos;

  const demoNames = [
    // "publicKeyTest",
    // "compressedPublicKeyTest",
    // "compressedCompactPublicKeyTest256BitBig",
    // "compressedCompactPublicKeyTest256BitSmall",
    // "compactPublicKeyZeroKnowledgeTest",
    // "compactPublicKeyBench32BitBig",
    // "compactPublicKeyBench32BitSmall",
    // "compactPublicKeyBench256BitBig",
    // "compactPublicKeyBench256BitSmall",
    // "compactPublicKeyWithCastingTest256Bit",
    // "compressedCompactPublicKeyWithCastingTest256Bit",
    // "compressedServerKeyBenchMessage1Carry1",
    // "compressedServerKeyBenchMessage2Carry2",
    "compactPublicKeyZeroKnowledgeBench",
  ];

  function setupBtn(id) {
    // Handlers are named in the same way as buttons.
    let fn = demos[id];

    let button = document.getElementById(id);
    if (button === null) {
      console.error(`button with id: ${id} not found`);
      return null;
    }

    // Assign onclick handler + enable the button.
    Object.assign(button, {
      onclick: async () => {
        document.getElementById("loader").hidden = false;
        document.getElementById("testSuccess").checked = false;
        setButtonsDisabledState(demoNames, true);

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
      },
      disabled: false,
    });

    return button;
  }

  for (let demo of demoNames) {
    setupBtn(demo);
  }
}

setup();
