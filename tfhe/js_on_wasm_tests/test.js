const crypto = require("crypto");
const test = require("node:test");
const assert = require("node:assert").strict;
const {
  Boolean,
  Shortint,
  BooleanParameterSet,
  ShortintParametersName,
  ShortintParameters,
} = require("../pkg");

function genRandomBigIntWithBytes(byteCount) {
  return BigInt("0x" + crypto.randomBytes(byteCount).toString("hex"));
}

// Boolean tests
test("boolean_encrypt_decrypt", (t) => {
  let params = Boolean.get_parameters(BooleanParameterSet.Default);
  let cks = Boolean.new_client_key(params);
  let ct = Boolean.encrypt(cks, true);

  let serialized_cks = Boolean.serialize_client_key(cks);
  let deserialized_cks = Boolean.deserialize_client_key(serialized_cks);

  let serialized_ct = Boolean.serialize_ciphertext(ct);
  let deserialized_ct = Boolean.deserialize_ciphertext(serialized_ct);

  let decrypted = Boolean.decrypt(deserialized_cks, deserialized_ct);
  assert.deepStrictEqual(decrypted, true);

  let sks = Boolean.new_compressed_server_key(cks);

  let serialized_sks = Boolean.serialize_compressed_server_key(sks);
  let deserialized_sks =
    Boolean.deserialize_compressed_server_key(serialized_sks);

  // No equality tests here, as wasm stores pointers which will always differ
});

test("boolean_compressed_encrypt_decrypt", (t) => {
  let params = Boolean.get_parameters(BooleanParameterSet.Default);
  let cks = Boolean.new_client_key(params);
  let ct = Boolean.encrypt_compressed(cks, true);

  let serialized_cks = Boolean.serialize_client_key(cks);
  let deserialized_cks = Boolean.deserialize_client_key(serialized_cks);

  let serialized_ct = Boolean.serialize_compressed_ciphertext(ct);
  let deserialized_ct =
    Boolean.deserialize_compressed_ciphertext(serialized_ct);

  let decompressed_ct = Boolean.decompress_ciphertext(deserialized_ct);

  let decrypted = Boolean.decrypt(deserialized_cks, decompressed_ct);
  assert.deepStrictEqual(decrypted, true);
});

test("boolean_public_encrypt_decrypt", (t) => {
  let params = Boolean.get_parameters(BooleanParameterSet.Default);
  let cks = Boolean.new_client_key(params);
  let pk = Boolean.new_public_key(cks);

  let serialized_pk = Boolean.serialize_public_key(pk);
  let deserialized_pk = Boolean.deserialize_public_key(serialized_pk);

  let ct = Boolean.encrypt_with_public_key(deserialized_pk, true);

  let serialized_ct = Boolean.serialize_ciphertext(ct);
  let deserialized_ct = Boolean.deserialize_ciphertext(serialized_ct);

  let decrypted = Boolean.decrypt(cks, deserialized_ct);
  assert.deepStrictEqual(decrypted, true);
});

test("boolean_deterministic_keygen", (t) => {
  const TEST_LOOP_COUNT = 128;

  let seed_high_bytes = genRandomBigIntWithBytes(8);
  let seed_low_bytes = genRandomBigIntWithBytes(8);

  let params = Boolean.get_parameters(BooleanParameterSet.Default);
  let cks = Boolean.new_client_key_from_seed_and_parameters(
    seed_high_bytes,
    seed_low_bytes,
    params,
  );
  let other_cks = Boolean.new_client_key_from_seed_and_parameters(
    seed_high_bytes,
    seed_low_bytes,
    params,
  );

  for (let i = 0; i < TEST_LOOP_COUNT; i++) {
    let ct_true = Boolean.encrypt(cks, true);
    let decrypt_true_other = Boolean.decrypt(other_cks, ct_true);
    assert.deepStrictEqual(decrypt_true_other, true);

    let ct_false = Boolean.encrypt(cks, false);
    let decrypt_false_other = Boolean.decrypt(other_cks, ct_false);
    assert.deepStrictEqual(decrypt_false_other, false);
  }
});

// Shortint tests
test("shortint_encrypt_decrypt", (t) => {
  let params_name =
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
  let params = new ShortintParameters(params_name);
  let cks = Shortint.new_client_key(params);
  let ct = Shortint.encrypt(cks, BigInt(3));

  let serialized_cks = Shortint.serialize_client_key(cks);
  let deserialized_cks = Shortint.deserialize_client_key(serialized_cks);

  let serialized_ct = Shortint.serialize_ciphertext(ct);
  let deserialized_ct = Shortint.deserialize_ciphertext(serialized_ct);

  let decrypted = Shortint.decrypt(deserialized_cks, deserialized_ct);
  assert.deepStrictEqual(decrypted, BigInt(3));

  let sks = Shortint.new_compressed_server_key(cks);

  let serialized_sks = Shortint.serialize_compressed_server_key(sks);
  let deserialized_sks =
    Shortint.deserialize_compressed_server_key(serialized_sks);

  // No equality tests here, as wasm stores pointers which will always differ

  // Encryption using small keys
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let cks_small = Shortint.new_client_key(params_small);

  let ct_small = Shortint.encrypt(cks_small, BigInt(3));

  let serialized_ct_small = Shortint.serialize_ciphertext(ct_small);
  let deserialized_ct_small =
    Shortint.deserialize_ciphertext(serialized_ct_small);

  let decrypted_small = Shortint.decrypt(cks_small, deserialized_ct_small);
  assert.deepStrictEqual(decrypted_small, BigInt(3));
});

test("shortint_compressed_encrypt_decrypt", (t) => {
  let params_name =
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
  let params = new ShortintParameters(params_name);
  let cks = Shortint.new_client_key(params);
  let ct = Shortint.encrypt_compressed(cks, BigInt(3));

  let serialized_cks = Shortint.serialize_client_key(cks);
  let deserialized_cks = Shortint.deserialize_client_key(serialized_cks);

  let serialized_ct = Shortint.serialize_compressed_ciphertext(ct);
  let deserialized_ct =
    Shortint.deserialize_compressed_ciphertext(serialized_ct);

  let decompressed_ct = Shortint.decompress_ciphertext(deserialized_ct);

  let decrypted = Shortint.decrypt(deserialized_cks, decompressed_ct);
  assert.deepStrictEqual(decrypted, BigInt(3));

  // Encryption using small keys
  // We don't have TUniform small params so use previous gaussian ones.
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let cks_small = Shortint.new_client_key(params_small);

  let ct_small = Shortint.encrypt_compressed(cks_small, BigInt(3));

  let serialized_ct_small = Shortint.serialize_compressed_ciphertext(ct_small);
  let deserialized_ct_small =
    Shortint.deserialize_compressed_ciphertext(serialized_ct_small);

  let decompressed_ct_small = Shortint.decompress_ciphertext(
    deserialized_ct_small,
  );

  let decrypted_small = Shortint.decrypt(cks_small, decompressed_ct_small);
  assert.deepStrictEqual(decrypted_small, BigInt(3));
});

test("shortint_public_encrypt_decrypt", (t) => {
  let params_name_2_0 =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64;
  let params_2_0 = new ShortintParameters(params_name_2_0);
  let cks = Shortint.new_client_key(params_2_0);
  let pk = Shortint.new_public_key(cks);

  let ct = Shortint.encrypt_with_public_key(pk, BigInt(3));

  let serialized_ct = Shortint.serialize_ciphertext(ct);
  let deserialized_ct = Shortint.deserialize_ciphertext(serialized_ct);

  let decrypted = Shortint.decrypt(cks, deserialized_ct);
  assert.deepStrictEqual(decrypted, BigInt(3));

  // Small
  let params_name_2_2_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_2_2_small = new ShortintParameters(params_name_2_2_small);
  let cks_small = Shortint.new_client_key(params_2_2_small);

  let pk_small = Shortint.new_public_key(cks_small);

  let ct_small = Shortint.encrypt_with_public_key(pk_small, BigInt(3));

  let serialized_ct_small = Shortint.serialize_ciphertext(ct_small);
  let deserialized_ct_small =
    Shortint.deserialize_ciphertext(serialized_ct_small);

  let decrypted_small = Shortint.decrypt(cks_small, deserialized_ct_small);
  assert.deepStrictEqual(decrypted_small, BigInt(3));
});

test("shortint_compressed_public_encrypt_decrypt", (t) => {
  let params_name = ShortintParametersName.PARAM_MESSAGE_1_CARRY_1_KS_PBS;
  let params = new ShortintParameters(params_name);
  let cks = Shortint.new_client_key(params);
  let pk = Shortint.new_compressed_public_key(cks);

  let serialized_pk = Shortint.serialize_compressed_public_key(pk);
  let deserialized_pk =
    Shortint.deserialize_compressed_public_key(serialized_pk);

  let ct = Shortint.encrypt_with_compressed_public_key(
    deserialized_pk,
    BigInt(1),
  );

  let serialized_ct = Shortint.serialize_ciphertext(ct);
  let deserialized_ct = Shortint.deserialize_ciphertext(serialized_ct);

  let decrypted = Shortint.decrypt(cks, deserialized_ct);
  assert.deepStrictEqual(decrypted, BigInt(1));

  // Small
  let params_name_small =
    ShortintParametersName.V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64;
  let params_small = new ShortintParameters(params_name_small);
  let cks_small = Shortint.new_client_key(params_small);

  let pk_small = Shortint.new_compressed_public_key(cks_small);

  let serialized_pk_small = Shortint.serialize_compressed_public_key(pk_small);
  let deserialized_pk_small =
    Shortint.deserialize_compressed_public_key(serialized_pk_small);

  let ct_small = Shortint.encrypt_with_compressed_public_key(
    deserialized_pk_small,
    BigInt(1),
  );

  let serialized_ct_small = Shortint.serialize_ciphertext(ct_small);
  let deserialized_ct_small =
    Shortint.deserialize_ciphertext(serialized_ct_small);

  let decrypted_small = Shortint.decrypt(cks_small, deserialized_ct_small);
  assert.deepStrictEqual(decrypted_small, BigInt(1));
});

test("shortint_deterministic_keygen", (t) => {
  const TEST_LOOP_COUNT = 128;

  let seed_high_bytes = genRandomBigIntWithBytes(8);
  let seed_low_bytes = genRandomBigIntWithBytes(8);

  let params_name =
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
  let params = new ShortintParameters(params_name);
  let cks = Shortint.new_client_key_from_seed_and_parameters(
    seed_high_bytes,
    seed_low_bytes,
    params,
  );
  let other_cks = Shortint.new_client_key_from_seed_and_parameters(
    seed_high_bytes,
    seed_low_bytes,
    params,
  );

  for (let i = 0; i < TEST_LOOP_COUNT; i++) {
    let random_message = genRandomBigIntWithBytes(4) % BigInt(4);
    let ct = Shortint.encrypt(cks, random_message);
    let decrypt_other = Shortint.decrypt(other_cks, ct);
    assert.deepStrictEqual(decrypt_other, random_message);
  }
});
