use super::{
    test_case_abs, test_case_flip, test_case_if_then_else, test_case_ilog2,
    test_case_int32_bitwise, test_case_int32_compare, test_case_int32_div_rem,
    test_case_int64_rotate, test_case_integer_casting, test_case_integer_compress_decompress,
    test_case_leading_trailing_zeros_ones, test_case_min_max, test_case_scalar_flip,
};
use crate::high_level_api::tests::create_parameterized_test;
use crate::integer::I256;
use crate::prelude::{
    CiphertextList, FheDecrypt, FheEncrypt, FheTryEncrypt, FheTryTrivialEncrypt,
    ParameterSetConformant,
};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128,
    TEST_PARAM_PROD_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::{
    generate_keys, set_server_key, ClientKey, CompactCiphertextList, CompactPublicKey,
    CompressedFheInt16, CompressedFheInt32, CompressedFheInt32ConformanceParams, ConfigBuilder,
    DeserializationConfig, FheInt256, FheInt32, FheInt32ConformanceParams, FheInt8,
    SerializationConfig, ServerKey,
};
use rand::{random, thread_rng, Rng};

create_parameterized_test!(test_case_int32_compare);
create_parameterized_test!(test_case_int32_bitwise);
create_parameterized_test!(test_case_int64_rotate);
create_parameterized_test!(test_case_int32_div_rem);
create_parameterized_test!(test_case_integer_casting);
create_parameterized_test!(test_case_if_then_else);
create_parameterized_test!(test_case_flip);
create_parameterized_test!(test_case_scalar_flip);
create_parameterized_test!(test_case_abs);
create_parameterized_test!(test_case_min_max);
create_parameterized_test!(test_case_ilog2);
create_parameterized_test!(test_case_leading_trailing_zeros_ones);
create_parameterized_test!(test_case_integer_compress_decompress);

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

fn test_case_safe_deserialize_conformant_fhe_int32(client_key: &ClientKey, server_key: &ServerKey) {
    let clear_a = random::<i32>();
    let a = FheInt32::encrypt(clear_a, client_key);
    let mut serialized = vec![];
    SerializationConfig::new(1 << 20)
        .serialize_into(&a, &mut serialized)
        .unwrap();

    let params = FheInt32ConformanceParams::from(server_key);
    let deserialized_a = DeserializationConfig::new(1 << 20)
        .deserialize_from::<FheInt32>(serialized.as_slice(), &params)
        .unwrap();
    let decrypted: i32 = deserialized_a.decrypt(client_key);
    assert_eq!(decrypted, clear_a);

    assert!(deserialized_a.is_conformant(&params));
}

#[test]
fn test_safe_deserialize_conformant_fhe_int32_default() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key.clone());
    test_case_safe_deserialize_conformant_fhe_int32(&client_key, &server_key);
}

#[test]
fn test_safe_deserialize_conformant_fhe_int32_prod_param() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::with_custom_parameters(
        TEST_PARAM_PROD_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ));
    set_server_key(server_key.clone());
    test_case_safe_deserialize_conformant_fhe_int32(&client_key, &server_key);
}

fn test_case_safe_deserialize_conformant_compressed_fhe_int32(
    client_key: &ClientKey,
    server_key: &ServerKey,
) {
    let clear_a = random::<i32>();
    let a = CompressedFheInt32::encrypt(clear_a, client_key);
    let mut serialized = vec![];
    SerializationConfig::new(1 << 20)
        .serialize_into(&a, &mut serialized)
        .unwrap();

    let params = CompressedFheInt32ConformanceParams::from(server_key);
    let deserialized_a = DeserializationConfig::new(1 << 20)
        .deserialize_from::<CompressedFheInt32>(serialized.as_slice(), &params)
        .unwrap();
    assert!(deserialized_a.is_conformant(&params));

    let decrypted: i32 = deserialized_a.decompress().decrypt(client_key);
    assert_eq!(decrypted, clear_a);
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_int32_default() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key.clone());
    test_case_safe_deserialize_conformant_compressed_fhe_int32(&client_key, &server_key);
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_int32_prod_param() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::with_custom_parameters(
        TEST_PARAM_PROD_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ));
    set_server_key(server_key.clone());
    test_case_safe_deserialize_conformant_compressed_fhe_int32(&client_key, &server_key);
}
