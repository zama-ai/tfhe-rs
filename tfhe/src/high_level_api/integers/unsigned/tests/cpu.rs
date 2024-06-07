use crate::conformance::ListSizeConstraint;
use crate::high_level_api::prelude::*;
use crate::high_level_api::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use crate::integer::U256;
use crate::safe_deserialization::safe_deserialize_conformant;
use crate::shortint::parameters::classic::compact_pk::*;
use crate::shortint::parameters::*;
use crate::{
    ClientKey, CompactCiphertextList, CompactCiphertextListConformanceParams, CompactPublicKey,
    CompressedFheUint16, CompressedFheUint256, CompressedFheUint32, CompressedPublicKey, FheInt16,
    FheInt32, FheInt8, FheUint128, FheUint16, FheUint256, FheUint32, FheUint32ConformanceParams,
};
use rand::prelude::*;

fn setup_cpu(params: Option<impl Into<PBSParameters>>) -> ClientKey {
    let config = params
        .map_or_else(ConfigBuilder::default, |p| {
            ConfigBuilder::with_custom_parameters(p.into(), None)
        })
        .build();

    let client_key = ClientKey::generate(config);
    let csks = crate::CompressedServerKey::new(&client_key);
    let server_key = csks.decompress();

    set_server_key(server_key);

    client_key
}

fn setup_default_cpu() -> ClientKey {
    setup_cpu(Option::<ClassicPBSParameters>::None)
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
fn test_integer_compressed() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let clear = 12_837u16;
    let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = FheUint16::from(compressed.decompress());
    let clear_decompressed: u16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_integer_compressed_small() {
    let config = ConfigBuilder::default_with_small_encryption().build();
    let (client_key, _) = generate_keys(config);

    let clear = 12_837u16;
    let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = FheUint16::from(compressed.decompress());
    let clear_decompressed: u16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_uint8_quickstart() {
    let client_key = setup_default_cpu();
    super::test_case_uint8_quickstart(&client_key);
}

#[test]
fn test_uint32_quickstart() {
    let client_key = setup_default_cpu();
    super::test_case_uint32_quickstart(&client_key);
}

#[test]
fn test_uint64_quickstart() {
    let client_key = setup_default_cpu();
    super::test_case_uint64_quickstart(&client_key);
}

#[test]
fn test_uint8_compare() {
    let client_key = setup_default_cpu();
    super::test_case_uint8_compare(&client_key);
}

#[test]
fn test_uint32_shift() {
    let client_key = setup_default_cpu();
    super::test_case_uint32_shift(&client_key);
}

#[test]
fn test_uint32_shift_multibit() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS, None)
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
    super::test_case_uint32_shift(&client_key);
}

#[test]
fn test_uint32_bitwise() {
    let client_key = setup_default_cpu();
    super::test_case_uint32_bitwise(&client_key);
}

#[test]
fn test_uint32_rotate() {
    let client_key = setup_default_cpu();
    super::test_case_uint32_rotate(&client_key);
}

#[test]
fn test_multi_bit_rotate() {
    let client_key = setup_cpu(Some(PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS));
    super::test_case_uint32_rotate(&client_key);
}

#[test]
fn test_uint32_div_rem() {
    let client_key = setup_default_cpu();
    super::test_case_uint32_div_rem(&client_key);
}

#[test]
fn test_multi_div_rem() {
    let client_key = setup_cpu(Some(PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS));
    super::test_case_uint32_div_rem(&client_key);
}

#[test]
fn test_small_uint128() {
    let config = ConfigBuilder::default_with_small_encryption().build();

    let (cks, sks) = generate_keys(config);

    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u128>();
    let clear_b = rng.gen::<u128>();

    let a = FheUint128::try_encrypt(clear_a, &cks).unwrap();
    let b = FheUint128::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    let c = a + b;

    let decrypted: u128 = c.decrypt(&cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
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

#[test]
fn test_compact_public_key_big() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS, None)
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);
    let compact_list = CompactCiphertextList::builder(&public_key)
        .push(255u8)
        .build();
    let expanded = compact_list.expand().unwrap();
    let a: FheUint8 = expanded.get(0).unwrap().unwrap();

    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}

#[test]
fn test_compact_public_key_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS, None)
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);
    let compact_list = CompactCiphertextList::builder(&public_key)
        .push(255u8)
        .build();
    let expanded = compact_list.expand().unwrap();
    let a: FheUint8 = expanded.get(0).unwrap().unwrap();

    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}

#[test]
fn test_integer_compress_decompress() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let a = FheUint8::try_encrypt(213u8, &client_key).unwrap();

    let clear: u8 = a.compress().decompress().decrypt(&client_key);

    assert_eq!(clear, 213u8);
}

#[test]
fn test_trivial_uint8() {
    let client_key = setup_default_cpu();
    super::test_case_uint8_trivial(&client_key);
}

#[test]
fn test_trivial_uint256_small() {
    let client_key = setup_default_cpu();
    super::test_case_uint256_trivial(&client_key);
}

#[test]
fn test_integer_casting() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let mut rng = rand::thread_rng();
    let clear = rng.gen::<u16>();

    // Downcasting then Upcasting
    {
        let a = FheUint16::encrypt(clear, &client_key);

        // Downcasting
        let a: FheUint8 = a.cast_into();
        let da: u8 = a.decrypt(&client_key);
        assert_eq!(da, clear as u8);

        // Upcasting
        let a: FheUint32 = a.cast_into();
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, (clear as u8) as u32);
    }

    // Upcasting then Downcasting
    {
        let a = FheUint16::encrypt(clear, &client_key);

        // Upcasting
        let a = FheUint32::cast_from(a);
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, clear as u32);

        // Downcasting
        let a = FheUint8::cast_from(a);
        let da: u8 = a.decrypt(&client_key);
        assert_eq!(da, (clear as u32) as u8);
    }

    // Casting to self, it not useful but is supported
    {
        let a = FheUint16::encrypt(clear, &client_key);
        let a = FheUint16::cast_from(a);
        let da: u16 = a.decrypt(&client_key);
        assert_eq!(da, clear);
    }

    // Downcasting to smaller signed integer then Upcasting back to unsigned
    {
        let clear = rng.gen_range((i16::MAX) as u16 + 1..u16::MAX);
        let a = FheUint16::encrypt(clear, &client_key);

        // Downcasting
        let a: FheInt8 = a.cast_into();
        let da: i8 = a.decrypt(&client_key);
        assert_eq!(da, clear as i8);

        // Upcasting
        let a: FheUint32 = a.cast_into();
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, (clear as i8) as u32);
    }

    {
        let clear = rng.gen_range(i16::MIN..0);
        let a = FheInt16::encrypt(clear, &client_key);

        // Upcasting
        let a: FheUint32 = a.cast_into();
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, clear as u32);
    }

    // Upcasting to bigger signed integer then downcasting back to unsigned
    {
        let clear = rng.gen_range((i16::MAX) as u16 + 1..u16::MAX);
        let a = FheUint16::encrypt(clear, &client_key);

        // Upcasting
        let a: FheInt32 = a.cast_into();
        let da: i32 = a.decrypt(&client_key);
        assert_eq!(da, clear as i32);

        // Downcasting
        let a: FheUint16 = a.cast_into();
        let da: u16 = a.decrypt(&client_key);
        assert_eq!(da, (clear as i32) as u16);
    }
}

#[test]
fn test_if_then_else() {
    let client_key = setup_default_cpu();
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_scalar_shift_when_clear_type_is_small() {
    // This is a regression tests
    // The goal is to make sure that doing a scalar shift / rotate
    // with a clear type that does not have enough bits to represent
    // the number of bits of the fhe type correctly works.

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let mut a = FheUint256::encrypt(U256::ONE, &client_key);
    // The fhe type has 256 bits, the clear type is u8,
    // a u8 cannot represent the value '256'.
    // This used to result in the shift/rotate panicking
    let clear = 1u8;

    let _ = &a << clear;
    let _ = &a >> clear;
    let _ = (&a).rotate_left(clear);
    let _ = (&a).rotate_right(clear);

    a <<= clear;
    a >>= clear;
    a.rotate_left_assign(clear);
    a.rotate_right_assign(clear);
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
fn test_sum() {
    let client_key = setup_default_cpu();
    super::test_case_sum(&client_key);
}

#[test]
fn test_safe_deserialize_conformant_fhe_uint32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());

    let clear_a = random::<u32>();
    let a = FheUint32::encrypt(clear_a, &client_key);
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = FheUint32ConformanceParams::from(&server_key);
    let deserialized_a =
        safe_deserialize_conformant::<FheUint32>(serialized.as_slice(), 1 << 20, &params).unwrap();
    let decrypted: u32 = deserialized_a.decrypt(&client_key);
    assert_eq!(decrypted, clear_a);

    assert!(deserialized_a.is_conformant(&FheUint32ConformanceParams::from(block_params)));
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_uint32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());

    let clear_a = random::<u32>();
    let a = CompressedFheUint32::encrypt(clear_a, &client_key);
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = FheUint32ConformanceParams::from(&server_key);
    let deserialized_a =
        safe_deserialize_conformant::<CompressedFheUint32>(serialized.as_slice(), 1 << 20, &params)
            .unwrap();

    assert!(deserialized_a.is_conformant(&FheUint32ConformanceParams::from(block_params)));

    let decrypted: u32 = deserialized_a.decompress().decrypt(&client_key);
    assert_eq!(decrypted, clear_a);
}

#[test]
fn test_safe_deserialize_conformant_compact_fhe_uint32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key);
    let pk = CompactPublicKey::new(&client_key);

    let clears = [random::<u32>(), random::<u32>(), random::<u32>()];
    let a = CompactCiphertextList::builder(&pk)
        .extend(clears.iter().copied())
        .build();
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = CompactCiphertextListConformanceParams {
        shortint_params: block_params.to_shortint_conformance_param(),
        num_elements_constraint: ListSizeConstraint::exact_size(clears.len()),
    };
    let deserialized_a = safe_deserialize_conformant::<CompactCiphertextList>(
        serialized.as_slice(),
        1 << 20,
        &params,
    )
    .unwrap();

    let expander = deserialized_a.expand().unwrap();
    for (i, clear) in clears.into_iter().enumerate() {
        let encrypted: FheUint32 = expander.get(i).unwrap().unwrap();
        let decrypted: u32 = encrypted.decrypt(&client_key);
        assert_eq!(decrypted, clear);
    }

    assert!(deserialized_a.is_conformant(&params));
}
