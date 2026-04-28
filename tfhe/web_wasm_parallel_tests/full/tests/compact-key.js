import {
  CompactCiphertextList,
  set_server_key,
  ShortintCompactPublicKeyEncryptionParametersName,
  ShortintParametersName,
  TfheClientKey,
  TfheCompactPublicKey,
  TfheCompressedCompactPublicKey,
  TfheServerKey,
} from "../../pkg/tfhe.js";
import {
  assertEq,
  generateRandomBigInt,
  SIZE_LIMIT,
} from "../../shared/helper.js";
import { get_tfhe_config, get_tfhe_config_with_casting } from "../config.js";

async function compressedCompactPublicKeyTest256BitOnConfig(params_name) {
  const config = get_tfhe_config(params_name);

  console.time("ClientKey Gen");
  const clientKey = TfheClientKey.generate(config);
  console.timeEnd("ClientKey Gen");

  console.time("CompressedCompactPublicKey Gen");
  let publicKey = TfheCompressedCompactPublicKey.new(clientKey);
  console.timeEnd("CompressedCompactPublicKey Gen");

  const serialized_pk = publicKey.safe_serialize(SIZE_LIMIT);
  console.log(
    "Serialized CompressedCompactPublicKey size: ",
    serialized_pk.length,
  );

  console.time("CompressedCompactPublicKey Decompression");
  publicKey = publicKey.decompress();
  console.timeEnd("CompressedCompactPublicKey Decompression");

  const clear_u2 = 3;
  const clear_i32 = -3284;
  const clear_bool = true;
  const clear_u256 = generateRandomBigInt(256);

  const builder = CompactCiphertextList.builder(publicKey);
  builder.push_u2(clear_u2);
  builder.push_i32(clear_i32);
  builder.push_boolean(clear_bool);
  builder.push_u256(clear_u256);

  const num_bits_encrypted = 2 + 4 + 1 + 256;
  console.log("Numb bits in compact list: ", num_bits_encrypted);

  console.time("CompactCiphertextList Encrypt");
  const list = builder.build();
  console.timeEnd("CompactCiphertextList Encrypt");

  const serialized = list.safe_serialize(SIZE_LIMIT);
  console.log("Serialized CompactCiphertextList size: ", serialized.length);
  const deserialized = CompactCiphertextList.safe_deserialize(
    serialized,
    SIZE_LIMIT,
  );

  const expander = deserialized.expand();
  assertEq(expander.get_uint2(0).decrypt(clientKey), clear_u2);
  assertEq(expander.get_int32(1).decrypt(clientKey), clear_i32);
  assertEq(expander.get_bool(2).decrypt(clientKey), clear_bool);
  assertEq(expander.get_uint256(3).decrypt(clientKey), clear_u256);
}

export async function compressedCompactPublicKeyTest256BitBig() {
  await compressedCompactPublicKeyTest256BitOnConfig(
    ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
  );
}

export async function compressedCompactPublicKeyTest256BitSmall() {
  await compressedCompactPublicKeyTest256BitOnConfig(
    ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
  );
}

export async function compactPublicKeyWithCastingTest256Bit() {
  const config = get_tfhe_config_with_casting(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
  );

  const clientKey = TfheClientKey.generate(config);
  const serverKey = TfheServerKey.new(clientKey);
  const publicKey = TfheCompactPublicKey.new(clientKey);
  set_server_key(serverKey);

  const clear_u2 = 3;
  const clear_i32 = -3284;
  const clear_bool = true;
  const clear_u256 = generateRandomBigInt(256);

  const builder = CompactCiphertextList.builder(publicKey);
  builder.push_u2(clear_u2);
  builder.push_i32(clear_i32);
  builder.push_boolean(clear_bool);
  builder.push_u256(clear_u256);

  const num_bits_encrypted = 2 + 4 + 1 + 256;
  console.log("Numb bits in compact list: ", num_bits_encrypted);

  console.time("CompactCiphertextList Encrypt");
  const list = builder.build_packed();
  console.timeEnd("CompactCiphertextList Encrypt");

  const serialized = list.safe_serialize(SIZE_LIMIT);
  console.log("Serialized CompactCiphertextList size: ", serialized.length);
  const deserialized = CompactCiphertextList.safe_deserialize(
    serialized,
    SIZE_LIMIT,
  );

  const expander = deserialized.expand();
  assertEq(expander.get_uint2(0).decrypt(clientKey), clear_u2);
  assertEq(expander.get_int32(1).decrypt(clientKey), clear_i32);
  assertEq(expander.get_bool(2).decrypt(clientKey), clear_bool);
  assertEq(expander.get_uint256(3).decrypt(clientKey), clear_u256);
}

export async function compressedCompactPublicKeyWithCastingTest256Bit() {
  const config = get_tfhe_config_with_casting(
    ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
  );

  const clientKey = TfheClientKey.generate(config);
  const serverKey = TfheServerKey.new(clientKey);
  const compressedPublicKey = TfheCompressedCompactPublicKey.new(clientKey);
  const publicKey = compressedPublicKey.decompress();
  set_server_key(serverKey);

  const clear_u2 = 3;
  const clear_i32 = -3284;
  const clear_bool = true;
  const clear_u256 = generateRandomBigInt(256);

  const builder = CompactCiphertextList.builder(publicKey);
  builder.push_u2(clear_u2);
  builder.push_i32(clear_i32);
  builder.push_boolean(clear_bool);
  builder.push_u256(clear_u256);

  const num_bits_encrypted = 2 + 4 + 1 + 256;
  console.log("Numb bits in compact list: ", num_bits_encrypted);

  console.time("CompactCiphertextList Encrypt");
  const list = builder.build_packed();
  console.timeEnd("CompactCiphertextList Encrypt");

  const serialized = list.safe_serialize(SIZE_LIMIT);
  console.log("Serialized CompactCiphertextList size: ", serialized.length);
  const deserialized = CompactCiphertextList.safe_deserialize(
    serialized,
    SIZE_LIMIT,
  );

  const expander = deserialized.expand();
  assertEq(expander.get_uint2(0).decrypt(clientKey), clear_u2);
  assertEq(expander.get_int32(1).decrypt(clientKey), clear_i32);
  assertEq(expander.get_bool(2).decrypt(clientKey), clear_bool);
  assertEq(expander.get_uint256(3).decrypt(clientKey), clear_u256);
}
