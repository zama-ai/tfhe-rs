import { threads } from "wasm-feature-detect";
import * as Comlink from "comlink";
import init, {
  register_cross_origin_coordinator,
  init_cross_origin_worker_pool,
  init_panic_hook,
  TfheClientKey,
  TfheServerKey,
  TfheCompactPublicKey,
  TfheConfigBuilder,
  set_server_key,
  shortint_params_name,
  ShortintParametersName,
  ShortintParameters,
  ZkComputeLoad,
  CompactPkeCrs,
  CompactCiphertextList,
  ProvenCompactCiphertextList,
  ShortintCompactPublicKeyEncryptionParameters,
  ShortintCompactPublicKeyEncryptionParametersName,
} from "./pkg/tfhe.js";

function setButtonsDisabledState(buttonIds, state) {
  for (let id of buttonIds) {
    let btn = document.getElementById(id);
    if (btn) {
      btn.disabled = state;
    }
  }
}

function assert_eq(a, b, text) {
  if (a === b) return;
  throw new Error(text || `Equality assertion failed!: ${a} != ${b}`);
}

function generateRandomBigInt(bitLen) {
  let result = BigInt(0);
  for (let i = 0; i < bitLen; i++) {
    result <<= 1n;
    result |= BigInt(Math.random() < 0.5);
  }
  return result;
}

function get_tfhe_config_with_casting(block_params_name, casting_params_name) {
  const block_params = new ShortintParameters(block_params_name);
  const casting_params = new ShortintCompactPublicKeyEncryptionParameters(
    casting_params_name,
  );
  return TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .use_dedicated_compact_public_key_parameters(casting_params)
    .build();
}

// Test the workflow where we run the proof in cross origin mode directly from the main thread
// and not in a worker
async function asyncMainThreadCompactPublicKeyZeroKnowledgeTest() {
  let config = get_tfhe_config_with_casting(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
  );

  let clientKey = TfheClientKey.generate(config);
  let serverKey = TfheServerKey.new(clientKey);
  let publicKey = TfheCompactPublicKey.new(clientKey);

  set_server_key(serverKey);

  console.log("Start CRS generation");
  console.time("CRS generation");
  let crs = CompactPkeCrs.from_config(config, 4 * 64);
  console.timeEnd("CRS generation");

  const metadata = new Uint8Array(320 / 8);
  crypto.getRandomValues(metadata);

  {
    let input = generateRandomBigInt(64);
    let start = performance.now();

    let builder = CompactCiphertextList.builder(publicKey);
    builder.push_u64(input);

    // Use async variant of the proof that can be called from the main thread
    let list = await builder.build_with_proof_packed_async(
      crs,
      metadata,
      ZkComputeLoad.Proof,
    );
    let end = performance.now();
    console.log(
      "Time to encrypt + prove (async, main thread) CompactFheUint64: ",
      end - start,
      " ms",
    );

    let serialized = list.safe_serialize(BigInt(10000000));
    console.log("CompactCiphertextList size:", serialized.length);
    let deserialized = ProvenCompactCiphertextList.safe_deserialize(
      serialized,
      BigInt(10000000),
    );

    let expander = deserialized.verify_and_expand(crs, publicKey, metadata);
    assert_eq(expander.get_uint64(0).decrypt(clientKey), input);
  }

  {
    let inputs = [
      generateRandomBigInt(64),
      generateRandomBigInt(64),
      generateRandomBigInt(64),
      generateRandomBigInt(64),
    ];
    let start = performance.now();
    let builder = CompactCiphertextList.builder(publicKey);
    for (let input of inputs) {
      builder.push_u64(input);
    }
    let encrypted = await builder.build_with_proof_packed_async(
      crs,
      metadata,
      ZkComputeLoad.Proof,
    );
    let end = performance.now();
    console.log(
      "Time to encrypt + prove (async, main thread) CompactFheUint64List of 4: ",
      end - start,
      " ms",
    );

    let expander = encrypted.verify_and_expand(crs, publicKey, metadata);

    assert_eq(expander.get_uint64(0).decrypt(clientKey), inputs[0]);
    assert_eq(expander.get_uint64(1).decrypt(clientKey), inputs[1]);
    assert_eq(expander.get_uint64(2).decrypt(clientKey), inputs[2]);
    assert_eq(expander.get_uint64(3).decrypt(clientKey), inputs[3]);
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
    await register_cross_origin_coordinator("/coordinator.js");
  }

  const worker = new Worker(new URL("./worker.js", import.meta.url), {
    type: "module",
  });

  const demos = await Comlink.wrap(worker).demos;

  // Worker-based tests (run in Comlink worker)
  const workerDemoNames = [
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

  // Main-thread tests (run directly, no worker)
  const mainThreadDemos = {
    asyncMainThreadCompactPublicKeyZeroKnowledgeTest,
  };
  const mainThreadDemoNames = Object.keys(mainThreadDemos);

  const allDemoNames = [...workerDemoNames, ...mainThreadDemoNames];

  function setupBtn(id, fn) {
    let button = document.getElementById(id);
    if (button === null) {
      console.error(`button with id: ${id} not found`);
      return null;
    }

    // Assign onclick handler + enable the button.
    button.onclick = async () => {
      document.getElementById("loader").hidden = false;
      document.getElementById("testSuccess").checked = false;
      setButtonsDisabledState(allDemoNames, true);

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
      setButtonsDisabledState(allDemoNames, false);
    };
    button.disabled = false;

    return button;
  }

  for (let demo of workerDemoNames) {
    setupBtn(demo, demos[demo]);
  }

  // Main-thread demos need the SyncExecutor initialized on the main thread
  if (!crossOriginIsolated) {
    await init_cross_origin_worker_pool("/coordinator.js", null);
    await init_panic_hook();

    for (let demo of mainThreadDemoNames) {
      setupBtn(demo, mainThreadDemos[demo]);
    }
  }
}

setup();
