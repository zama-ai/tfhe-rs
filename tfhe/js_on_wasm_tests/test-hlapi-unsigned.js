const test = require("node:test");
const assert = require("node:assert").strict;
const { performance } = require("perf_hooks");
const {
  init_panic_hook,
  TfheClientKey,
  TfhePublicKey,
  TfheCompressedPublicKey,
  TfheCompressedServerKey,
  TfheConfigBuilder,
  CompressedFheUint8,
  FheUint8,
  FheUint32,
  CompressedFheUint128,
  FheUint128,
  CompressedFheUint256,
  FheUint256,
  ShortintParameters,
  ShortintParametersName,
} = require("../pkg/tfhe.js");
const { randomBytes } = require("node:crypto");

const U256_MAX = BigInt(
  "115792089237316195423570985008687907853269984665640564039457584007913129639935",
);
const U128_MAX = BigInt("340282366920938463463374607431768211455");
const U32_MAX = 4294967295;

// This is useful to debug test
//
// Note that the test hlapi_panic
// purposefully creates a panic, to some panic message
// will be printed and test will be ok
init_panic_hook();
function generateRandomBigInt(bitLength) {
  const bytesNeeded = Math.ceil(bitLength / 8);
  const randomBytesBuffer = randomBytes(bytesNeeded);

  // Convert random bytes to BigInt
  return BigInt(`0x${randomBytesBuffer.toString("hex")}`);
}

// Here integers are not enabled
// but we try to use them, so an error should be returned
// as the underlying panic should have been trapped
test("hlapi_panic", (t) => {
  let config = TfheConfigBuilder.default().build();

  let clientKey = TfheClientKey.generate(config);

  let clear = 73;

  console.log(
    "\nThe following log is an expected error log:\n=======================\n",
  );

  try {
    let _ = FheUint8.encrypt_with_client_key(clear, clientKey);
    assert(false);
  } catch (e) {
    assert(true);
  }
});

test("hlapi_key_gen_big", (t) => {
  let config = TfheConfigBuilder.default().build();

  let clientKey = TfheClientKey.generate(config);
  let compressedServerKey = TfheCompressedServerKey.new(clientKey);
  try {
    let publicKey = TfhePublicKey.new(clientKey);
    assert(false);
  } catch (e) {
    assert(true);
  }

  let serializedClientKey = clientKey.serialize();
  let serializedCompressedServerKey = compressedServerKey.serialize();
});

test("hlapi_key_gen_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);
  let compressedServerKey = TfheCompressedServerKey.new(clientKey);
  let publicKey = TfhePublicKey.new(clientKey);

  let serializedClientKey = clientKey.serialize();
  let serializedCompressedServerKey = compressedServerKey.serialize();
  let serializedPublicKey = publicKey.serialize();
});

test("hlapi_client_key_encrypt_decrypt_uint8_big", (t) => {
  let config = TfheConfigBuilder.default().build();

  let clientKey = TfheClientKey.generate(config);

  let clear = 73;
  let encrypted = FheUint8.encrypt_with_client_key(clear, clientKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, clear);

  let serialized = encrypted.serialize();
  let deserialized = FheUint8.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, clear);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint8.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, clear);
});

test("hlapi_compressed_public_client_uint8_big", (t) => {
  let config = TfheConfigBuilder.default().build();

  let clientKey = TfheClientKey.generate(config);

  let clear = 73;
  let compressed_encrypted = CompressedFheUint8.encrypt_with_client_key(
    clear,
    clientKey,
  );
  let compressed_serialized = compressed_encrypted.serialize();
  let compressed_deserialized = CompressedFheUint8.deserialize(
    compressed_serialized,
  );
  let decompressed = compressed_deserialized.decompress();

  let decrypted = decompressed.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, clear);

  let compressed_safe_serialized = compressed_encrypted.safe_serialize(
    BigInt(10000000),
  );
  let compressed_safe_deserialized = CompressedFheUint8.safe_deserialize(
    compressed_safe_serialized,
    BigInt(10000000),
  );
  let safe_decompressed = compressed_safe_deserialized.decompress();

  let safe_decrypted = safe_decompressed.decrypt(clientKey);
  assert.deepStrictEqual(safe_decrypted, clear);
});

test("hlapi_public_key_encrypt_decrypt_uint32_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);
  let publicKey = TfhePublicKey.new(clientKey);

  let encrypted = FheUint32.encrypt_with_public_key(U32_MAX, publicKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U32_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint32.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U32_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(1000000));
  let safe_deserialized = FheUint32.safe_deserialize(
    safe_serialized,
    BigInt(1000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U32_MAX);
});

test("hlapi_decompress_public_key_then_encrypt_decrypt_uint32_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);
  var startTime = performance.now();
  let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
  var endTime = performance.now();

  let data = compressedPublicKey.serialize();

  let publicKey = compressedPublicKey.decompress();

  var startTime = performance.now();
  let encrypted = FheUint32.encrypt_with_public_key(U32_MAX, publicKey);
  var endTime = performance.now();

  let ser = encrypted.serialize();
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U32_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint32.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U32_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint32.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U32_MAX);
});

test("hlapi_client_key_encrypt_decrypt_uint128_big", (t) => {
  let config = TfheConfigBuilder.default().build();

  let clientKey = TfheClientKey.generate(config);

  let encrypted = FheUint128.encrypt_with_client_key(U128_MAX, clientKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U128_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint128.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U128_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint128.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U128_MAX);

  // Compressed
  let compressed_encrypted = CompressedFheUint128.encrypt_with_client_key(
    U128_MAX,
    clientKey,
  );
  let compressed_serialized = compressed_encrypted.serialize();
  let compressed_deserialized = CompressedFheUint128.deserialize(
    compressed_serialized,
  );
  let decompressed = compressed_deserialized.decompress();

  decrypted = decompressed.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U128_MAX);

  let compressed_safe_serialized = compressed_encrypted.safe_serialize(
    BigInt(10000000),
  );
  let compressed_safe_deserialized = CompressedFheUint128.safe_deserialize(
    compressed_safe_serialized,
    BigInt(10000000),
  );
  let safe_decompressed = compressed_safe_deserialized.decompress();

  safe_decrypted = safe_decompressed.decrypt(clientKey);
  assert.deepStrictEqual(safe_decrypted, U128_MAX);
});

test("hlapi_client_key_encrypt_decrypt_uint128_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);

  let encrypted = FheUint128.encrypt_with_client_key(U128_MAX, clientKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U128_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint128.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U128_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint128.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U128_MAX);

  // Compressed
  let compressed_encrypted = CompressedFheUint128.encrypt_with_client_key(
    U128_MAX,
    clientKey,
  );
  let compressed_serialized = compressed_encrypted.serialize();
  let compressed_deserialized = CompressedFheUint128.deserialize(
    compressed_serialized,
  );
  let decompressed = compressed_deserialized.decompress();

  decrypted = decompressed.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U128_MAX);

  let compressed_safe_serialized = compressed_encrypted.safe_serialize(
    BigInt(10000000),
  );
  let compressed_safe_deserialized = CompressedFheUint128.safe_deserialize(
    compressed_safe_serialized,
    BigInt(10000000),
  );
  let safe_decompressed = compressed_safe_deserialized.decompress();

  safe_decrypted = safe_decompressed.decrypt(clientKey);
  assert.deepStrictEqual(safe_decrypted, U128_MAX);
});

test("hlapi_client_key_encrypt_decrypt_uint256_big", (t) => {
  let config = TfheConfigBuilder.default().build();

  let clientKey = TfheClientKey.generate(config);

  let encrypted = FheUint256.encrypt_with_client_key(U256_MAX, clientKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U256_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint256.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U256_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint256.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U256_MAX);

  // Compressed
  let compressed_encrypted = CompressedFheUint256.encrypt_with_client_key(
    U256_MAX,
    clientKey,
  );
  let compressed_serialized = compressed_encrypted.serialize();
  let compressed_deserialized = CompressedFheUint256.deserialize(
    compressed_serialized,
  );
  let decompressed = compressed_deserialized.decompress();

  decrypted = decompressed.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U256_MAX);

  let compressed_safe_serialized = compressed_encrypted.safe_serialize(
    BigInt(10000000),
  );
  let compressed_safe_deserialized = CompressedFheUint256.safe_deserialize(
    compressed_safe_serialized,
    BigInt(10000000),
  );
  let safe_decompressed = compressed_safe_deserialized.decompress();

  safe_decrypted = safe_decompressed.decrypt(clientKey);
  assert.deepStrictEqual(safe_decrypted, U256_MAX);
});

test("hlapi_client_key_encrypt_decrypt_uint256_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);

  let encrypted = FheUint256.encrypt_with_client_key(U256_MAX, clientKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U256_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint256.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U256_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint256.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U256_MAX);

  // Compressed
  let compressed_encrypted = CompressedFheUint256.encrypt_with_client_key(
    U256_MAX,
    clientKey,
  );
  let compressed_serialized = compressed_encrypted.serialize();
  let compressed_deserialized = CompressedFheUint256.deserialize(
    compressed_serialized,
  );
  let decompressed = compressed_deserialized.decompress();

  decrypted = decompressed.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U256_MAX);

  let compressed_safe_serialized = compressed_encrypted.safe_serialize(
    BigInt(10000000),
  );
  let compressed_safe_deserialized = CompressedFheUint256.safe_deserialize(
    compressed_safe_serialized,
    BigInt(10000000),
  );
  let safe_decompressed = compressed_safe_deserialized.decompress();

  safe_decrypted = safe_decompressed.decrypt(clientKey);
  assert.deepStrictEqual(safe_decrypted, U256_MAX);
});

test("hlapi_decompress_public_key_then_encrypt_decrypt_uint256_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);
  let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
  let publicKey = compressedPublicKey.decompress();

  let encrypted = FheUint256.encrypt_with_public_key(U256_MAX, publicKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U256_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint256.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U256_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint256.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U256_MAX);
});

test("hlapi_public_key_encrypt_decrypt_uint256_small", (t) => {
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let config = TfheConfigBuilder.with_custom_parameters(params_small).build();

  let clientKey = TfheClientKey.generate(config);
  let publicKey = TfhePublicKey.new(clientKey);

  let encrypted = FheUint256.encrypt_with_public_key(U256_MAX, publicKey);
  let decrypted = encrypted.decrypt(clientKey);
  assert.deepStrictEqual(decrypted, U256_MAX);

  let serialized = encrypted.serialize();
  let deserialized = FheUint256.deserialize(serialized);
  let deserialized_decrypted = deserialized.decrypt(clientKey);
  assert.deepStrictEqual(deserialized_decrypted, U256_MAX);

  let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
  let safe_deserialized = FheUint256.safe_deserialize(
    safe_serialized,
    BigInt(10000000),
  );
  let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
  assert.deepStrictEqual(safe_deserialized_decrypted, U256_MAX);
});
