import * as Comlink from "comlink";
import init, {
  initThreadPool,
  init_panic_hook,
  set_server_key,
  shortint_params_name,
  ShortintParametersName,
  ShortintParameters,
  TfheClientKey,
  TfhePublicKey,
  TfheServerKey,
  TfheCompressedPublicKey,
  TfheCompressedServerKey,
  TfheCompressedCompactPublicKey,
  TfheCompactPublicKey,
  TfheConfigBuilder,
  FheUint8,
  ZkComputeLoad,
  CompactPkeCrs,
  CompactCiphertextList,
  ProvenCompactCiphertextList,
  ShortintCompactPublicKeyEncryptionParameters,
  ShortintCompactPublicKeyEncryptionParametersName,
} from "./pkg/tfhe.js";

const U32_MAX = 4294967295;
const U64_MAX = BigInt("0xffffffffffffffff");

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
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompressedPublicKey Gen");
  let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
  console.timeEnd("CompressedPublicKey Gen");

  let data = compressedPublicKey.safe_serialize(BigInt(10000000));
  console.log("CompressedPublicKey size:", data.length);

  console.time("CompressedPublicKey Decompression");
  let publicKey = compressedPublicKey.decompress();
  console.timeEnd("CompressedPublicKey Decompression");

  console.time("FheUint8 encrypt with CompressedPublicKey");
  let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
  console.timeEnd("FheUint8 encrypt with CompressedPublicKey");

  let ser = encrypted.safe_serialize(BigInt(10000000));
  console.log("Ciphertext Size", ser.length);

  let decrypted = encrypted.decrypt(clientKey);
  assert_eq(decrypted, 255);
}

async function publicKeyTest() {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("PublicKey Gen");
  let publicKey = TfhePublicKey.new(clientKey);
  console.timeEnd("PublicKey Gen");

  console.time("FheUint8 encrypt with PublicKey");
  let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
  console.timeEnd("FheUint8 encrypt with PublicKey");

  let ser = encrypted.safe_serialize(BigInt(10000000));
  console.log("Ciphertext Size", ser.length);

  let decrypted = encrypted.decrypt(clientKey);
  assert_eq(decrypted, 255);
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

  let values = [0, 1, 2, 2394, U32_MAX].map(BigInt);

  // Bench the encryption for bench_loops iterations
  start = performance.now();
  let compact_list;
  for (let i = 0; i < bench_loops; i++) {
    let builder = CompactCiphertextList.builder(publicKey);
    for (let value of values) {
      builder.push_u256(value);
    }
    compact_list = builder.build();
  }
  end = performance.now();
  const timing_2 = (end - start) / bench_loops;
  console.log("CompactFheUint32List Encrypt bench: ", timing_2, " ms");
  bench_results["compact_fheunit32_list_encrypt_mean"] = timing_2;

  let serialized_list = compact_list.safe_serialize(BigInt(10000000));
  console.log("Serialized CompactFheUint32List size: ", serialized_list.length);

  // Bench the serialization for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = compact_list.safe_serialize(BigInt(10000000));
  }
  end = performance.now();
  const timing_3 = (end - start) / bench_loops;
  console.log("CompactFheUint32List serialization bench: ", timing_3, " ms");
  bench_results["compact_fheunit32_list_serialization_mean"] = timing_3;

  return bench_results;
}

async function compactPublicKeyBench32BitBig() {
  const params =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64;
  const block_params = new ShortintParameters(params);
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench32BitOnConfig(config),
    shortint_params_name(params),
  );
}

async function compactPublicKeyBench32BitSmall() {
  const params =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64;
  const block_params = new ShortintParameters(params);
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench32BitOnConfig(config),
    shortint_params_name(params),
  );
}

function generateRandomBigInt(bitLen) {
  let result = BigInt(0);
  for (let i = 0; i < bitLen; i++) {
    result << 1n;
    result |= BigInt(Math.random() < 0.5);
  }
  return result;
}

async function compressedCompactPublicKeyTest256BitOnConfig(config) {
  console.time("ClientKey Gen");
  let clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompressedCompactPublicKey Gen");
  let publicKey = TfheCompressedCompactPublicKey.new(clientKey);
  console.timeEnd("CompressedCompactPublicKey Gen");

  let serialized_pk = publicKey.safe_serialize(BigInt(10000000));
  console.log(
    "Serialized CompressedCompactPublicKey size: ",
    serialized_pk.length,
  );

  console.time("CompressedCompactPublicKey Decompression");
  publicKey = publicKey.decompress();
  console.timeEnd("CompressedCompactPublicKey Decompression");

  let clear_u2 = 3;
  let clear_i32 = -3284;
  let clear_bool = true;
  let clear_u256 = generateRandomBigInt(256);

  let builder = CompactCiphertextList.builder(publicKey);
  builder.push_u2(clear_u2);
  builder.push_i32(clear_i32);
  builder.push_boolean(clear_bool);
  builder.push_u256(clear_u256);

  let num_bits_encrypted = 2 + 4 + 1 + 256;
  console.log("Numb bits in compact list: ", num_bits_encrypted);

  console.time("CompactCiphertextList Encrypt");
  let list = builder.build();
  console.timeEnd("CompactCiphertextList Encrypt");

  let serialized = list.safe_serialize(BigInt(10000000));
  console.log("Serialized CompactCiphertextList size: ", serialized.length);
  let deserialized = CompactCiphertextList.safe_deserialize(
    serialized,
    BigInt(10000000),
  );

  let expander = deserialized.expand();

  assert_eq(expander.get_uint2(0).decrypt(clientKey), clear_u2);

  assert_eq(expander.get_int32(1).decrypt(clientKey), clear_i32);

  assert_eq(expander.get_bool(2).decrypt(clientKey), clear_bool);

  assert_eq(expander.get_uint256(3).decrypt(clientKey), clear_u256);
}

async function compactPublicKeyWithCastingTest256Bit() {
  let block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
  );
  let casting_params = new ShortintCompactPublicKeyEncryptionParameters(
    ShortintCompactPublicKeyEncryptionParametersName.SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
  );

  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .use_dedicated_compact_public_key_parameters(casting_params)
    .build();

  let clientKey = TfheClientKey.generate(config);
  let serverKey = TfheServerKey.new(clientKey);
  let publicKey = TfheCompactPublicKey.new(clientKey);

  set_server_key(serverKey);

  let clear_u2 = 3;
  let clear_i32 = -3284;
  let clear_bool = true;
  let clear_u256 = generateRandomBigInt(256);

  let builder = CompactCiphertextList.builder(publicKey);
  builder.push_u2(clear_u2);
  builder.push_i32(clear_i32);
  builder.push_boolean(clear_bool);
  builder.push_u256(clear_u256);

  let num_bits_encrypted = 2 + 4 + 1 + 256;
  console.log("Numb bits in compact list: ", num_bits_encrypted);

  console.time("CompactCiphertextList Encrypt");
  let list = builder.build_packed();
  console.timeEnd("CompactCiphertextList Encrypt");

  let serialized = list.safe_serialize(BigInt(10000000));
  console.log("Serialized CompactCiphertextList size: ", serialized.length);
  let deserialized = CompactCiphertextList.safe_deserialize(
    serialized,
    BigInt(10000000),
  );

  let expander = deserialized.expand();

  assert_eq(expander.get_uint2(0).decrypt(clientKey), clear_u2);

  assert_eq(expander.get_int32(1).decrypt(clientKey), clear_i32);

  assert_eq(expander.get_bool(2).decrypt(clientKey), clear_bool);

  assert_eq(expander.get_uint256(3).decrypt(clientKey), clear_u256);
}

async function compressedCompactPublicKeyWithCastingTest256Bit() {
  let block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
  );
  let casting_params = new ShortintCompactPublicKeyEncryptionParameters(
    ShortintCompactPublicKeyEncryptionParametersName.SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
  );

  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .use_dedicated_compact_public_key_parameters(casting_params)
    .build();

  let clientKey = TfheClientKey.generate(config);
  let serverKey = TfheServerKey.new(clientKey);
  let compressedPublicKey = TfheCompressedCompactPublicKey.new(clientKey);
  let publicKey = compressedPublicKey.decompress();

  set_server_key(serverKey);

  let clear_u2 = 3;
  let clear_i32 = -3284;
  let clear_bool = true;
  let clear_u256 = generateRandomBigInt(256);

  let builder = CompactCiphertextList.builder(publicKey);
  builder.push_u2(clear_u2);
  builder.push_i32(clear_i32);
  builder.push_boolean(clear_bool);
  builder.push_u256(clear_u256);

  let num_bits_encrypted = 2 + 4 + 1 + 256;
  console.log("Numb bits in compact list: ", num_bits_encrypted);

  console.time("CompactCiphertextList Encrypt");
  let list = builder.build_packed();
  console.timeEnd("CompactCiphertextList Encrypt");

  let serialized = list.safe_serialize(BigInt(10000000));
  console.log("Serialized CompactCiphertextList size: ", serialized.length);
  let deserialized = CompactCiphertextList.safe_deserialize(
    serialized,
    BigInt(10000000),
  );

  let expander = deserialized.expand();

  assert_eq(expander.get_uint2(0).decrypt(clientKey), clear_u2);

  assert_eq(expander.get_int32(1).decrypt(clientKey), clear_i32);

  assert_eq(expander.get_bool(2).decrypt(clientKey), clear_bool);

  assert_eq(expander.get_uint256(3).decrypt(clientKey), clear_u256);
}

async function compactPublicKeyZeroKnowledgeTest() {
  let block_params = new ShortintParameters(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
  );
  let casting_params = new ShortintCompactPublicKeyEncryptionParameters(
    ShortintCompactPublicKeyEncryptionParametersName.SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
  );

  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .use_dedicated_compact_public_key_parameters(casting_params)
    .build();

  let clientKey = TfheClientKey.generate(config);
  let serverKey = TfheServerKey.new(clientKey);
  let publicKey = TfheCompactPublicKey.new(clientKey);

  set_server_key(serverKey);

  console.log("Start CRS generation");
  console.time("CRS generation");
  let crs = CompactPkeCrs.from_config(config, 4 * 64);
  console.timeEnd("CRS generation");

  let serialized = crs.safe_serialize(BigInt(1000000000));
  console.log("CompactPkeCrs size:", serialized.length);
  let deserialized = CompactPkeCrs.safe_deserialize(
    serialized,
    BigInt(1000000000),
  );

  // 320 bits is a use case we have, 8 bits per byte
  const metadata = new Uint8Array(320 / 8);
  crypto.getRandomValues(metadata);

  {
    let input = generateRandomBigInt(64);
    let start = performance.now();

    let builder = CompactCiphertextList.builder(publicKey);
    builder.push_u64(input);
    let list = builder.build_with_proof_packed(
      crs,
      metadata,
      ZkComputeLoad.Proof,
    );
    let end = performance.now();
    console.log(
      "Time to encrypt + prove CompactFheUint64: ",
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

    let unverified_expander = deserialized.expand_without_verification();

    assert_eq(unverified_expander.get_uint64(0).decrypt(clientKey), input);
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
    let encrypted = builder.build_with_proof_packed(
      crs,
      metadata,
      ZkComputeLoad.Proof,
    );
    let end = performance.now();
    console.log(
      "Time to encrypt + prove CompactFheUint64List of 4: ",
      end - start,
      " ms",
    );

    let expander = encrypted.verify_and_expand(crs, publicKey, metadata);

    assert_eq(expander.get_uint64(0).decrypt(clientKey), inputs[0]);

    assert_eq(expander.get_uint64(1).decrypt(clientKey), inputs[1]);

    assert_eq(expander.get_uint64(2).decrypt(clientKey), inputs[2]);

    assert_eq(expander.get_uint64(3).decrypt(clientKey), inputs[3]);

    let unverified_expander = encrypted.expand_without_verification();

    assert_eq(unverified_expander.get_uint64(0).decrypt(clientKey), inputs[0]);

    assert_eq(unverified_expander.get_uint64(1).decrypt(clientKey), inputs[1]);

    assert_eq(unverified_expander.get_uint64(2).decrypt(clientKey), inputs[2]);

    assert_eq(unverified_expander.get_uint64(3).decrypt(clientKey), inputs[3]);
  }
}

async function compressedCompactPublicKeyTest256BitBig() {
  const block_params = new ShortintParameters(
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
  );
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  await compressedCompactPublicKeyTest256BitOnConfig(config);
}

async function compressedCompactPublicKeyTest256BitSmall() {
  const block_params = new ShortintParameters(
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64,
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

  // Bench the encryption for bench_loops iterations
  start = performance.now();
  let compact_list;
  for (let i = 0; i < bench_loops; i++) {
    console.time("CompactFheUint256List Encrypt");
    let builder = CompactCiphertextList.builder(publicKey);
    for (let value of values) {
      builder.push_u256(value);
    }
    compact_list = builder.build();
    console.timeEnd("CompactFheUint256List Encrypt");
  }
  end = performance.now();
  const timing_2 = (end - start) / bench_loops;
  console.log("CompactFheUint256List Encrypt bench: ", timing_2, " ms");
  bench_results["compact_fheunit256_list_encrypt_mean"] = timing_2;

  let serialized_list = compact_list.safe_serialize(BigInt(10000000));
  console.log(
    "Serialized CompactFheUint256List size: ",
    serialized_list.length,
  );

  // Bench the serialization for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = compact_list.safe_serialize(BigInt(10000000));
  }
  end = performance.now();
  const timing_3 = (end - start) / bench_loops;
  console.log("CompactFheUint256List serialization bench: ", timing_3, " ms");
  bench_results["compact_fheunit256_list_serialization_mean"] = timing_3;

  return bench_results;
}

async function compactPublicKeyBench256BitBig() {
  const params =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64;
  const block_params = new ShortintParameters(params);
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench256BitOnConfig(config),
    shortint_params_name(params),
  );
}

async function compactPublicKeyBench256BitSmall() {
  const params =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64;
  const block_params = new ShortintParameters(params);
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compactPublicKeyBench256BitOnConfig(config),
    shortint_params_name(params),
  );
}

async function compressedServerKeyBenchConfig(config) {
  const bench_loops = 5;
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
  let serialized_key = serverKey.safe_serialize(BigInt(1000000000));
  console.log("Serialized ServerKey size: ", serialized_key.length);

  // Bench the serialization for bench_loops iterations
  start = performance.now();
  for (let i = 0; i < bench_loops; i++) {
    let _ = serverKey.safe_serialize(BigInt(1000000000));
  }
  end = performance.now();
  const timing_2 = (end - start) / bench_loops;
  console.log("CompressedServerKey serialization bench: ", timing_2, " ms");
  bench_results["compressed_server_key_serialization_mean"] = timing_2;

  return bench_results;
}

async function compressedServerKeyBenchMessage1Carry1() {
  const params =
    ShortintParametersName.V0_11_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64;
  const block_params = new ShortintParameters(params);
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compressedServerKeyBenchConfig(config),
    shortint_params_name(params),
  );
}

async function compressedServerKeyBenchMessage2Carry2() {
  const params =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
  const block_params = new ShortintParameters(params);
  let config = TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
  return append_param_name(
    await compressedServerKeyBenchConfig(config),
    shortint_params_name(params),
  );
}

async function compactPublicKeyZeroKnowledgeBench() {
  let params_to_bench = [
    {
      zk_scheme: "ZKV2",
      name: shortint_params_name(
        ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
      ),
      block_params: new ShortintParameters(
        ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
      ),
      casting_params: new ShortintCompactPublicKeyEncryptionParameters(
        ShortintCompactPublicKeyEncryptionParametersName.SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
      ),
    },
    {
      zk_scheme: "ZKV1",
      name: shortint_params_name(
        ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
      ),
      block_params: new ShortintParameters(
        ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
      ),
      casting_params: new ShortintCompactPublicKeyEncryptionParameters(
        ShortintCompactPublicKeyEncryptionParametersName.SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1,
      ),
    },
  ];

  let bench_results = {};

  for (const params of params_to_bench) {
    let block_params_name = params.name;
    let block_params = params.block_params;
    let casting_params = params.casting_params;

    let config = TfheConfigBuilder.default()
      .use_custom_parameters(block_params)
      .use_dedicated_compact_public_key_parameters(casting_params)
      .build();

    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    const bench_loops = 5; // The computation is expensive
    let load_choices = [ZkComputeLoad.Proof, ZkComputeLoad.Verify];
    const load_to_str = {
      [ZkComputeLoad.Proof]: "compute_load_proof",
      [ZkComputeLoad.Verify]: "compute_load_verify",
    };

    let bits_to_encrypt = [64, 640, 1280, 4096];

    let encrypt_counts = bits_to_encrypt.map((v) => v / 64);

    for (const encrypt_count of encrypt_counts) {
      console.log("Start CRS generation");
      console.time("CRS generation");
      let crs = CompactPkeCrs.from_config(config, encrypt_count * 64);
      console.timeEnd("CRS generation");

      // 320 bits is a use case we have, 8 bits per byte
      const metadata = new Uint8Array(320 / 8);
      crypto.getRandomValues(metadata);

      let inputs = Array.from(Array(encrypt_count).keys()).map((_) => U64_MAX);
      for (const loadChoice of load_choices) {
        let serialized_size = 0;
        let timing = 0;
        for (let i = 0; i < bench_loops; i++) {
          console.time("Loop " + i);
          let compact_list_builder =
            ProvenCompactCiphertextList.builder(publicKey);
          for (let j = 0; j < encrypt_count; j++) {
            compact_list_builder.push_u64(inputs[j]);
          }
          const start = performance.now();
          let list = compact_list_builder.build_with_proof_packed(
            crs,
            metadata,
            loadChoice,
          );
          const end = performance.now();
          console.timeEnd("Loop " + i);
          timing += end - start;
          serialized_size = list.safe_serialize(BigInt(10000000)).length;
        }
        const mean = timing / bench_loops;
        const common_bench_str =
          "compact_fhe_uint_proven_encryption_" +
          params.zk_scheme +
          "_" +
          encrypt_count * 64 +
          "_bits_packed_" +
          load_to_str[loadChoice];
        const bench_str_1 = common_bench_str + "_mean_" + block_params_name;
        console.log(bench_str_1, ": ", mean, " ms");
        const bench_str_2 =
          common_bench_str + "_serialized_size_mean_" + block_params_name;
        console.log(bench_str_2, ": ", serialized_size, " bytes");

        bench_results[bench_str_1] = mean;
        bench_results[bench_str_2] = serialized_size;
      }
    }
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
    compressedCompactPublicKeyTest256BitSmall,
    compressedCompactPublicKeyTest256BitBig,
    compactPublicKeyZeroKnowledgeTest,
    compactPublicKeyBench32BitBig,
    compactPublicKeyBench32BitSmall,
    compactPublicKeyBench256BitBig,
    compactPublicKeyBench256BitSmall,
    compactPublicKeyWithCastingTest256Bit,
    compressedCompactPublicKeyWithCastingTest256Bit,
    compressedServerKeyBenchMessage1Carry1,
    compressedServerKeyBenchMessage2Carry2,
    compactPublicKeyZeroKnowledgeBench,
  });
}

Comlink.expose({
  demos: main(),
});
