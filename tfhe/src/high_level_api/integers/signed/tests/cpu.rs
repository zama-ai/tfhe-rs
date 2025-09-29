use crate::high_level_api::tests::{setup_cpu, setup_default_cpu};
use crate::integer::I256;
use crate::prelude::{
    CiphertextList, FheDecrypt, FheEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
    ParameterSetConformant,
};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128,
    TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
};
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::{
    generate_keys, set_server_key, CompactCiphertextList, CompactPublicKey, CompressedFheInt16,
    CompressedFheInt32, ConfigBuilder, DeserializationConfig, FheInt256, FheInt32,
    FheInt32ConformanceParams, FheInt8, SerializationConfig,
};
use rand::{random, thread_rng, Rng};

#[test]
fn test_signed_integer_compressed() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let clear = -1234i16;
    let compressed = CompressedFheInt16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = compressed.decompress();
    let clear_decompressed: i16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_integer_compressed_small() {
    let mut rng = thread_rng();

    let config =
        ConfigBuilder::with_custom_parameters(TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128)
            .build();
    let (client_key, _) = generate_keys(config);

    let clear = rng.gen::<i16>();
    let compressed = CompressedFheInt16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = compressed.decompress();
    let clear_decompressed: i16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_int32_compare() {
    let client_key = setup_default_cpu();
    super::test_case_int32_compare(&client_key);
}

#[test]
fn test_int32_bitwise() {
    let client_key = setup_default_cpu();
    super::test_case_int32_bitwise(&client_key);
}

#[test]
fn test_int64_rotate() {
    let client_key = setup_default_cpu();
    super::test_case_int64_rotate(&client_key);
}

#[test]
fn test_multi_bit_rotate() {
    let client_key = setup_cpu(Some(
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    ));
    super::test_case_int64_rotate(&client_key);
}

#[test]
fn test_int32_div_rem() {
    let client_key = setup_default_cpu();
    super::test_case_int32_div_rem(&client_key);
}

#[test]
fn test_multi_div_rem() {
    let client_key = setup_cpu(Some(
        TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    ));
    super::test_case_int32_div_rem(&client_key);
}

#[test]
fn test_integer_casting() {
    let client_key = setup_default_cpu();
    super::test_case_integer_casting(&client_key);
}

#[test]
fn test_if_then_else() {
    let client_key = setup_default_cpu();
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_flip() {
    let client_key = setup_default_cpu();
    super::test_case_flip(&client_key);
}

#[test]
fn test_scalar_flip() {
    let client_key = setup_default_cpu();
    super::test_case_scalar_flip(&client_key);
}

#[test]
fn test_abs() {
    let client_key = setup_default_cpu();
    super::test_case_abs(&client_key);
}

#[test]
fn test_integer_compress_decompress() {
    let client_key = setup_default_cpu();
    super::test_case_integer_compress_decompress(&client_key);
}

#[test]
fn test_min_max() {
    let client_key = setup_default_cpu();
    super::test_case_min_max(&client_key);
}

#[test]
fn test_trivial_fhe_int8() {
    let config = ConfigBuilder::default().build();
    let (client_key, sks) = generate_keys(config);

    set_server_key(sks);

    let a = FheInt8::try_encrypt_trivial(-1i8).unwrap();

    let clear: i8 = a.decrypt(&client_key);
    assert_eq!(clear, -1i8);
}

#[test]
fn test_trivial_fhe_int256_small() {
    let config =
        ConfigBuilder::with_custom_parameters(TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128)
            .build();
    let (client_key, sks) = generate_keys(config);

    set_server_key(sks);

    let clear_a = I256::MIN;
    let a = FheInt256::try_encrypt_trivial(clear_a).unwrap();
    let clear: I256 = a.decrypt(&client_key);
    assert_eq!(clear, clear_a);
}
#[test]
fn test_compact_public_key_big() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128)
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);
    let compact_list = CompactCiphertextList::builder(&public_key)
        .push(-1i8)
        .build();
    let expanded = compact_list.expand().unwrap();
    let a: FheInt8 = expanded.get(0).unwrap().unwrap();

    let clear: i8 = a.decrypt(&client_key);
    assert_eq!(clear, -1i8);
}

#[test]
fn test_compact_public_key_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128)
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);
    let compact_list = CompactCiphertextList::builder(&public_key)
        .push(-123i8)
        .build();
    let expanded = compact_list.expand().unwrap();
    let a: FheInt8 = expanded.get(0).unwrap().unwrap();

    let clear: i8 = a.decrypt(&client_key);
    assert_eq!(clear, -123i8);
}

#[test]
fn test_ilog2() {
    let client_key = setup_default_cpu();
    super::test_case_ilog2(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones() {
    let client_key = setup_default_cpu();
    super::test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_safe_deserialize_conformant_fhe_int32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params));
    set_server_key(server_key.clone());

    let clear_a = random::<i32>();
    let a = FheInt32::encrypt(clear_a, &client_key);
    let mut serialized = vec![];
    SerializationConfig::new(1 << 20)
        .serialize_into(&a, &mut serialized)
        .unwrap();

    let params = FheInt32ConformanceParams::from(&server_key);
    let deserialized_a = DeserializationConfig::new(1 << 20)
        .deserialize_from::<FheInt32>(serialized.as_slice(), &params)
        .unwrap();
    let decrypted: i32 = deserialized_a.decrypt(&client_key);
    assert_eq!(decrypted, clear_a);

    let params = FheInt32ConformanceParams::from(block_params);
    assert!(deserialized_a.is_conformant(&params));
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_int32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params));
    set_server_key(server_key.clone());

    let clear_a = random::<i32>();
    let a = CompressedFheInt32::encrypt(clear_a, &client_key);
    let mut serialized = vec![];
    SerializationConfig::new(1 << 20)
        .serialize_into(&a, &mut serialized)
        .unwrap();

    let params = FheInt32ConformanceParams::from(&server_key);
    let deserialized_a = DeserializationConfig::new(1 << 20)
        .deserialize_from::<CompressedFheInt32>(serialized.as_slice(), &params)
        .unwrap();

    let params = FheInt32ConformanceParams::from(block_params);
    assert!(deserialized_a.is_conformant(&params));

    let decrypted: i32 = deserialized_a.decompress().decrypt(&client_key);
    assert_eq!(decrypted, clear_a);
}
