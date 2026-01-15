use crate::high_level_api::prelude::*;
use crate::high_level_api::tests::create_parameterized_test;
use crate::high_level_api::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use crate::integer::U256;
use crate::shortint::parameters::test_params::*;
use crate::{CompressedFheUint256, CompressedPublicKey, FheUint256};

use super::{
    test_case_bitslice, test_case_clone, test_case_flip, test_case_if_then_else,
    test_case_if_then_zero, test_case_ilog2, test_case_integer_casting, test_case_is_even_is_odd,
    test_case_leading_trailing_zeros_ones, test_case_match_value, test_case_match_value_or,
    test_case_min_max, test_case_scalar_flip, test_case_sum, test_case_uint256_trivial,
    test_case_uint32_arith, test_case_uint32_arith_assign, test_case_uint32_bitwise,
    test_case_uint32_bitwise_assign, test_case_uint32_div_rem, test_case_uint32_quickstart,
    test_case_uint32_rotate, test_case_uint32_scalar_arith, test_case_uint32_scalar_arith_assign,
    test_case_uint32_scalar_bitwise, test_case_uint32_shift, test_case_uint64_quickstart,
    test_case_uint8_compare, test_case_uint8_compare_scalar, test_case_uint8_quickstart,
    test_case_uint8_trivial, test_dedicated_compact_public_key,
    test_dedicated_compressed_compact_public_key, test_integer_compress_decompress,
    test_integer_compressed, test_safe_deserialize_conformant_compact_fhe_uint32,
    test_safe_deserialize_conformant_compressed_fhe_uint32,
    test_safe_deserialize_conformant_fhe_uint32, test_scalar_shift_when_clear_type_is_small,
};

create_parameterized_test!(test_case_match_value_or);
create_parameterized_test!(test_case_uint8_quickstart);
create_parameterized_test!(test_case_uint32_quickstart);
create_parameterized_test!(test_case_uint64_quickstart);
create_parameterized_test!(test_case_uint32_arith);
create_parameterized_test!(test_case_uint32_arith_assign);
create_parameterized_test!(test_case_uint32_scalar_arith);
create_parameterized_test!(test_case_uint32_scalar_arith_assign);
create_parameterized_test!(test_case_clone);
create_parameterized_test!(test_case_uint8_compare);
create_parameterized_test!(test_case_uint8_compare_scalar);
create_parameterized_test!(test_case_uint32_shift);
create_parameterized_test!(test_case_uint32_bitwise);
create_parameterized_test!(test_case_uint32_bitwise_assign);
create_parameterized_test!(test_case_uint32_scalar_bitwise);
create_parameterized_test!(test_case_uint32_rotate);
create_parameterized_test!(test_case_uint32_div_rem);
create_parameterized_test!(test_case_if_then_else);
create_parameterized_test!(test_case_flip);
create_parameterized_test!(test_case_scalar_flip);
create_parameterized_test!(test_case_ilog2);
create_parameterized_test!(test_case_is_even_is_odd);
create_parameterized_test!(test_case_bitslice);
create_parameterized_test!(test_case_leading_trailing_zeros_ones);
create_parameterized_test!(test_case_sum);
create_parameterized_test!(test_case_min_max);
create_parameterized_test!(test_case_match_value);
create_parameterized_test!(test_case_uint8_trivial);
create_parameterized_test!(test_case_uint256_trivial);
create_parameterized_test!(test_case_integer_casting);
create_parameterized_test!(test_scalar_shift_when_clear_type_is_small);
create_parameterized_test!(test_integer_compress_decompress);
create_parameterized_test!(test_safe_deserialize_conformant_compact_fhe_uint32);
create_parameterized_test!(test_integer_compressed);
create_parameterized_test!(test_case_if_then_zero);

#[test]
fn test_safe_deserialize_conformant_fhe_uint32_default() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    test_safe_deserialize_conformant_fhe_uint32(&client_key, &server_key);
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_uint32_default() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    test_safe_deserialize_conformant_compressed_fhe_uint32(&client_key, &server_key);
}

#[test]
fn test_integer_compressed_small() {
    let config =
        ConfigBuilder::with_custom_parameters(TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128)
            .build();
    let (client_key, _) = generate_keys(config);
    test_integer_compressed(&client_key);
}

#[test]
fn test_dedicated_compact_public_default() {
    let param_fhe = TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    let param_pke_only = TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    let param_ksk = TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param_fhe)
        .use_dedicated_compact_public_key_parameters((param_pke_only, param_ksk))
        .build();
    let (client_key, sks) = generate_keys(config);
    set_server_key(sks);
    test_dedicated_compact_public_key(&client_key);
}

#[test]
fn test_dedicated_compressed_compact_public_default() {
    let param_fhe = TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128;
    let param_pke_only = TEST_PARAM_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2;
    let param_ksk = TEST_PARAM_KEYSWITCH_PKE_TO_BIG_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(param_fhe)
        .use_dedicated_compact_public_key_parameters((param_pke_only, param_ksk))
        .build();
    let (client_key, sks) = generate_keys(config);

    set_server_key(sks);
    test_dedicated_compressed_compact_public_key(&client_key);
}

#[test]
fn test_integer_compressed_can_be_serialized() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let clear = U256::from(u64::MAX);
    let compressed = CompressedFheUint256::try_encrypt(clear, &client_key).unwrap();

    let bytes = bincode::serialize(&compressed).unwrap();
    let deserialized: CompressedFheUint256 = bincode::deserialize_from(bytes.as_slice()).unwrap();

    let decompressed = FheUint256::from(deserialized.decompress());
    let clear_decompressed: U256 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_case_uint64_quickstart_small() {
    let config =
        ConfigBuilder::with_custom_parameters(TEST_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128)
            .build();

    let (cks, sks) = generate_keys(config);
    set_server_key(sks);

    test_case_uint64_quickstart(&cks);
}

#[test]
fn test_integer_compressed_public_key() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompressedPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(213u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 213u8);
}

#[test]
fn test_decompressed_public_key_encrypt() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let compressed_public_key = CompressedPublicKey::new(&client_key);
    let public_key = compressed_public_key.decompress();

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}
