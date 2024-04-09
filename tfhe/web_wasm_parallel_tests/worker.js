import * as Comlink from "comlink";
import init, {
  initThreadPool,
  init_panic_hook,
  ShortintParametersName,
  ShortintParameters,
  TfheClientKey,
  TfhePublicKey,
  TfheCompressedPublicKey,
  TfheCompressedServerKey,
  TfheCompressedCompactPublicKey,
  TfheCompactPublicKey,
  TfheConfigBuilder,
  FheUint8,
  CompactFheUint32List,
  CompactFheUint256List,
  ZkComputeLoad,
  ProvenCompactFheUint64,
  ProvenCompactFheUint64List,
  CompactPkeCrs,
  Shortint,
  CompactFheUint64,
} from "./pkg/tfhe.js";

function assert(cond, text) {
  if (cond) return;
  if (console.assert.useDebugger) debugger;
  throw new Error(text || "Assertion failed!");
}

function assert_eq(a, b, text) {
  if (a === b) return;
  if (console.assert.useDebugger) debugger;
  throw new Error(text || `Equality assertion failed!: ${a} != ${b}`);
}

function append_param_name(bench_results, params_name) {
  let results = {};
  for (const bench_name in bench_results) {
    results[`${bench_name}_${params_name}`] = bench_results[bench_name];
  }
  return results;
}

async function compressedPublicKeyTest() {
  let config = TfheConfigBuilder.default_with_small_encryption().build();

  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompressedPublicKey Gen");
  let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
  console.timeEnd("CompressedPublicKey Gen");

  let data = compressedPublicKey.serialize();
  console.log("CompressedPublicKey size:", data.length);

  console.time("CompressedPublicKey Decompression");
  let publicKey = compressedPublicKey.decompress();
  console.timeEnd("CompressedPublicKey Decompression");

  console.time("FheUint8 encrypt with CompressedPublicKey");
  let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
  console.timeEnd("FheUint8 encrypt with CompressedPublicKey");

  let ser = encrypted.serialize();
  console.log("Ciphertext Size", ser.length);

  let decrypted = encrypted.decrypt(clientKey);
  assert_eq(decrypted, 255);
}

async function publicKeyTest() {
  let config = TfheConfigBuilder.default_with_small_encryption().build();

  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("PublicKey Gen");
  let publicKey = TfhePublicKey.new(clientKey);
  console.timeEnd("PublicKey Gen");

  console.time("FheUint8 encrypt with PublicKey");
  let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
  console.timeEnd("FheUint8 encrypt with PublicKey");

  let ser = encrypted.serialize();
  console.log("Ciphertext Size", ser.length);

  let decrypted = encrypted.decrypt(clientKey);
  assert_eq(decrypted, 255);
}

const U32_MAX = 4294967295;

async function compactPublicKeyTest32BitOnConfig(config) {
  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompactPublicKey Gen");
  let publicKey = TfheCompactPublicKey.new(clientKey);
  console.timeEnd("CompactPublicKey Gen");

  let serialized_pk = publicKey.serialize();
  console.log("Serialized CompactPublicKey size: ", serialized_pk.length);

  let values = [0, 1, 2394, U32_MAX];

  console.time("CompactFheUint32List Encrypt");
  let compact_list = CompactFheUint32List.encrypt_with_compact_public_key(
    values,
    publicKey,
  );
  console.timeEnd("CompactFheUint32List Encrypt");

  {
    console.time("CompactFheUint32List Expand");
    let encrypted_list = compact_list.expand();
    console.timeEnd("CompactFheUint32List Expand");

    assert_eq(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++) {
      let decrypted = encrypted_list[i].decrypt(clientKey);
      assert_eq(decrypted, values[i]);
    }
  }

  let serialized_list = compact_list.serialize();
  console.log("Serialized CompactFheUint32List size: ", serialized_list.length);

  let deserialized_list = CompactFheUint32List.deserialize(serialized_list);
  let encrypted_list = deserialized_list.expand();
  assert_eq(encrypted_list.length, values.length);

  for (let i = 0; i < values.length; i++) {
    let decrypted = encrypted_list[i].decrypt(clientKey);
    assert_eq(decrypted, values[i]);
  }
}

async function compactPublicKeyTest32BitBig() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compactPublicKeyTest32BitOnConfig(config);
}

async function compactPublicKeyTest32BitSmall() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compactPublicKeyTest32BitOnConfig(config);
}

async function compactPublicKeyBench32BitOnConfig(config) {
  const bench_loops = 100;
  let bench_results = {};

  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  // Generate PK for encryption for later
  console.time("CompactPublicKey Gen");
  let publicKey = TfheCompactPublicKey.new(clientKey);
  console.timeEnd("CompactPublicKey Gen");

  // Bench the pk generation for bench_loops iterations
  let start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = TfheCompactPublicKey.new(clientKey);
  }
  let end = performance.now();
  const timing_1 = (end - start) / bench_loops;
  console.log("CompactPublicKey Gen bench: ", timing_1, " ms");
  bench_results["compact_public_key_gen_32bit_mean"] = timing_1;

  let values = [0, 1, 2, 2394, U32_MAX];

  // Encrypt compact CT list for serialization for later
  console.time("CompactFheUint32List Encrypt");
  let compact_list = CompactFheUint32List.encrypt_with_compact_public_key(
    values,
    publicKey,
  );
  console.timeEnd("CompactFheUint32List Encrypt");

  // Bench the encryption for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = CompactFheUint32List.encrypt_with_compact_public_key(
      values,
      publicKey,
    );
  }
  end = performance.now();
  const timing_2 = (end - start) / bench_loops;
  console.log("CompactFheUint32List Encrypt bench: ", timing_2, " ms");
  bench_results["compact_fheunit32_list_encrypt_mean"] = timing_2;

  let serialized_list = compact_list.serialize();
  console.log("Serialized CompactFheUint32List size: ", serialized_list.length);

  // Bench the serialization for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = compact_list.serialize();
  }
  end = performance.now();
  const timing_3 = (end - start) / bench_loops;
  console.log("CompactFheUint32List serialization bench: ", timing_3, " ms");
  bench_results["compact_fheunit32_list_serialization_mean"] = timing_3;

  return bench_results;
}

async function compactPublicKeyBench32BitBig() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench32BitOnConfig(config),
    "PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS",
  );
}

async function compactPublicKeyBench32BitSmall() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench32BitOnConfig(config),
    "PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS",
  );
}

async function compactPublicKeyTest256BitOnConfig(config) {
  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompactPublicKey Gen");
  let publicKey = TfheCompactPublicKey.new(clientKey);
  console.timeEnd("CompactPublicKey Gen");

  let serialized_pk = publicKey.serialize();
  console.log("Serialized CompactPublicKey size: ", serialized_pk.length);

  let values = [0, 1, 2394, U32_MAX].map((e) => BigInt(e));

  console.time("CompactFheUint256List Encrypt");
  let compact_list = CompactFheUint256List.encrypt_with_compact_public_key(
    values,
    publicKey,
  );
  console.timeEnd("CompactFheUint256List Encrypt");

  {
    console.time("CompactFheUint256List Expand");
    let encrypted_list = compact_list.expand();
    console.timeEnd("CompactFheUint256List Expand");

    assert_eq(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++) {
      let decrypted = encrypted_list[i].decrypt(clientKey);
      assert_eq(decrypted, values[i]);
    }
  }

  let serialized_list = compact_list.serialize();
  console.log(
    "Serialized CompactFheUint256List size: ",
    serialized_list.length,
  );

  let deserialized_list = CompactFheUint256List.deserialize(serialized_list);
  let encrypted_list = deserialized_list.expand();
  assert_eq(encrypted_list.length, values.length);

  for (let i = 0; i < values.length; i++) {
    let decrypted = encrypted_list[i].decrypt(clientKey);
    assert_eq(decrypted, values[i]);
  }
}

async function compactPublicKeyTest256BitBig() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compactPublicKeyTest256BitOnConfig(config);
}

async function compactPublicKeyTest256BitSmall() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compactPublicKeyTest256BitOnConfig(config);
}

async function compressedCompactPublicKeyTest256BitOnConfig(config) {
  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompressedCompactPublicKey Gen");
  let publicKey = TfheCompressedCompactPublicKey.new(clientKey);
  console.timeEnd("CompressedCompactPublicKey Gen");

  let serialized_pk = publicKey.serialize();
  console.log(
    "Serialized CompressedCompactPublicKey size: ",
    serialized_pk.length,
  );

  console.time("CompressedCompactPublicKey Decompression");
  publicKey = publicKey.decompress();
  console.timeEnd("CompressedCompactPublicKey Decompression");

  let values = [0, 1, 2394, U32_MAX].map((e) => BigInt(e));

  console.time("CompactFheUint256List Encrypt");
  let compact_list = CompactFheUint256List.encrypt_with_compact_public_key(
    values,
    publicKey,
  );
  console.timeEnd("CompactFheUint256List Encrypt");

  {
    console.time("CompactFheUint256List Expand");
    let encrypted_list = compact_list.expand();
    console.timeEnd("CompactFheUint256List Expand");

    assert_eq(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++) {
      let decrypted = encrypted_list[i].decrypt(clientKey);
      assert_eq(decrypted, values[i]);
    }
  }

  let serialized_list = compact_list.serialize();
  console.log(
    "Serialized CompactFheUint256List size: ",
    serialized_list.length,
  );

  let deserialized_list = CompactFheUint256List.deserialize(serialized_list);
  let encrypted_list = deserialized_list.expand();
  assert_eq(encrypted_list.length, values.length);

  for (let i = 0; i < values.length; i++) {
    let decrypted = encrypted_list[i].decrypt(clientKey);
    assert_eq(decrypted, values[i]);
  }
}

function generateRandomBigInt(bitLen) {
  let result = BigInt(0);
  for (let i = 0; i < bitLen; i++) {
    result << 1n;
    result |= BigInt(Math.random() < 0.5);
  }
  return result;
}

async function compactPublicKeyZeroKnowledge() {
  let block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40,
  );

  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();

  let clientKey = TfheClientKey.generate(config);
  let publicKey = TfheCompactPublicKey.new(clientKey);

  console.log("Start CRS generation");
  console.time("CRS generation");
  let crs = CompactPkeCrs.from_config(config, 4 * 64);
  console.timeEnd("CRS generation");
  let public_params = crs.public_params();

  {
    let input = generateRandomBigInt(64);
    let start = performance.now();
    let encrypted = ProvenCompactFheUint64.encrypt_with_compact_public_key(
      input,
      public_params,
      publicKey,
      ZkComputeLoad.Proof,
    );
    let end = performance.now();
    console.log(
      "Time to encrypt + prove CompactFheUint64: ",
      end - start,
      " ms",
    );

    let bytes = encrypted.serialize();
    console.log("ProvenCompactFheUint64 size:", bytes.length);

    assert_eq(encrypted.verifies(public_params, publicKey), true);

    start = performance.now();
    let expanded = encrypted.verify_and_expand(public_params, publicKey);
    end = performance.now();
    console.log(
      "Time to verify + expand CompactFheUint64: ",
      end - start,
      " ms",
    );

    let decrypted = expanded.decrypt(clientKey);
    assert_eq(decrypted, input);
  }

  {
    let inputs = [
      generateRandomBigInt(64),
      generateRandomBigInt(64),
      generateRandomBigInt(64),
      generateRandomBigInt(64),
    ];
    let start = performance.now();
    let encrypted = ProvenCompactFheUint64List.encrypt_with_compact_public_key(
      inputs,
      public_params,
      publicKey,
      ZkComputeLoad.Proof,
    );
    let end = performance.now();
    console.log(
      "Time to encrypt + prove CompactFheUint64List of 4: ",
      end - start,
      " ms",
    );
    assert_eq(encrypted.verifies(public_params, publicKey), true);

    start = performance.now();
    let expanded_list = encrypted.verify_and_expand(public_params, publicKey);
    end = performance.now();
    console.log(
      "Time to verify + expand CompactFheUint64: ",
      end - start,
      " ms",
    );

    for (let i = 0; i < inputs.length; i++) {
      let decrypted = expanded_list[i].decrypt(clientKey);
      assert_eq(decrypted, inputs[i]);
    }
  }
}

async function compressedCompactPublicKeyTest256BitBig() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compressedCompactPublicKeyTest256BitOnConfig(config);
}

async function compressedCompactPublicKeyTest256BitSmall() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compressedCompactPublicKeyTest256BitOnConfig(config);
}

async function compactPublicKeyBench256BitOnConfig(config) {
  const bench_loops = 100;
  let bench_results = {};

  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  // Generate PK for encryption for later
  console.time("CompactPublicKey Gen");
  let publicKey = TfheCompactPublicKey.new(clientKey);
  console.timeEnd("CompactPublicKey Gen");

  // Bench the pk generation for bench_loops iterations
  let start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = TfheCompactPublicKey.new(clientKey);
  }
  let end = performance.now();
  const timing_1 = (end - start) / bench_loops;
  console.log("CompactPublicKey Gen bench: ", timing_1, " ms");
  bench_results["compact_public_key_gen_256bit_mean"] = timing_1;

  let values = [0, 1, 2, 2394, U32_MAX].map((e) => BigInt(e));

  // Encrypt compact CT list for serialization for later
  console.time("CompactFheUint256List Encrypt");
  let compact_list = CompactFheUint256List.encrypt_with_compact_public_key(
    values,
    publicKey,
  );
  console.timeEnd("CompactFheUint256List Encrypt");

  // Bench the encryption for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = CompactFheUint256List.encrypt_with_compact_public_key(
      values,
      publicKey,
    );
  }
  end = performance.now();
  const timing_2 = (end - start) / bench_loops;
  console.log("CompactFheUint256List Encrypt bench: ", timing_2, " ms");
  bench_results["compact_fheunit256_list_encrypt_mean"] = timing_2;

  let serialized_list = compact_list.serialize();
  console.log(
    "Serialized CompactFheUint256List size: ",
    serialized_list.length,
  );

  // Bench the serialization for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = compact_list.serialize();
  }
  end = performance.now();
  const timing_3 = (end - start) / bench_loops;
  console.log("CompactFheUint256List serialization bench: ", timing_3, " ms");
  bench_results["compact_fheunit256_list_serialization_mean"] = timing_3;

  return bench_results;
}

async function compactPublicKeyBench256BitBig() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench256BitOnConfig(config),
    "PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS",
  );
}

async function compactPublicKeyBench256BitSmall() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench256BitOnConfig(config),
    "PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS",
  );
}

async function compressedServerKeyBenchConfig(config) {
  const bench_loops = 35;
  let bench_results = {};

  console.log("Begin benchmarks"); // DEBUG
  let clientKey = TfheClientKey.generate(config);

  // Bench the sk generation for bench_loops iterations
  let start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = TfheCompressedServerKey.new(clientKey);
  }
  let end = performance.now();
  const timing_1 = (end - start) / bench_loops;
  console.log("CompressedServerKey Gen bench: ", timing_1, " ms");
  bench_results["compressed_server_key_gen_mean"] = timing_1;

  let serverKey = TfheCompressedServerKey.new(clientKey);
  let serialized_key = serverKey.serialize();
  console.log("Serialized ServerKey size: ", serialized_key.length);

  // Bench the serialization for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = serverKey.serialize();
  }
  end = performance.now();
  const timing_2 = (end - start) / bench_loops;
  console.log("CompressedServerKey serialization bench: ", timing_2, " ms");
  bench_results["compressed_server_key_serialization_mean"] = timing_2;

  return bench_results;
}

async function compressedServerKeyBenchMessage1Carry1() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_1_CARRY_1_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compressedServerKeyBenchConfig(config),
    "PARAM_MESSAGE_1_CARRY_1_KS_PBS",
  );
}

async function compressedServerKeyBenchMessage2Carry2() {
  const block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compressedServerKeyBenchConfig(config),
    "PARAM_MESSAGE_2_CARRY_2_KS_PBS",
  );
}

async function compactPublicKeyZeroKnowledgeBench() {
  let block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40,
  );

  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();

  let clientKey = TfheClientKey.generate(config);
  let publicKey = TfheCompactPublicKey.new(clientKey);

  console.log("Start CRS generation");
  console.time("CRS generation");
  let crs = CompactPkeCrs.from_config(config, 4 * 64);
  console.timeEnd("CRS generation");
  let public_params = crs.public_params();

  const bench_loops = 4; // The computation is expensive
  let bench_results = {};
  let load_choices = [ZkComputeLoad.Proof, ZkComputeLoad.Verify];
  const load_to_str = {
    [ZkComputeLoad.Proof]: "compute_load_proof",
    [ZkComputeLoad.Verify]: "compute_load_verify",
  };
  for (const loadChoice of load_choices) {
    let timing = 0;
    for (let i = 0; i < bench_loops; i++) {
      let input = generateRandomBigInt(64);

      const start = performance.now();
      let _ = ProvenCompactFheUint64.encrypt_with_compact_public_key(
        input,
        public_params,
        publicKey,
        loadChoice,
      );
      const end = performance.now();
      timing += end - start;
    }
    const mean = timing / bench_loops;

    const bench_str =
      "compact_fhe_uint64_proven_encryption_" +
      load_to_str[loadChoice] +
      "_mean";
    console.log(bench_str, ": ", mean, " ms");
    bench_results["compact_fhe_uint64_proven_encryption_"] = mean;
  }

  return bench_results;
}

async function main() {
  await init();
  await initThreadPool(navigator.hardwareConcurrency);
  await init_panic_hook();

  return Comlink.proxy({
    publicKeyTest,
    compressedPublicKeyTest,
    compactPublicKeyTest32BitSmall,
    compactPublicKeyTest32BitBig,
    compactPublicKeyTest256BitSmall,
    compactPublicKeyTest256BitBig,
    compressedCompactPublicKeyTest256BitSmall,
    compressedCompactPublicKeyTest256BitBig,
    compactPublicKeyZeroKnowledge,
    compactPublicKeyBench32BitBig,
    compactPublicKeyBench32BitSmall,
    compactPublicKeyBench256BitBig,
    compactPublicKeyBench256BitSmall,
    compressedServerKeyBenchMessage1Carry1,
    compressedServerKeyBenchMessage2Carry2,
    compactPublicKeyZeroKnowledgeBench,
  });
}

Comlink.expose({
  demos: main(),
});
