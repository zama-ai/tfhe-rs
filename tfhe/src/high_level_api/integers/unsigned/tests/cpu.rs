use crate::conformance::ListSizeConstraint;
use crate::high_level_api::prelude::*;
use crate::high_level_api::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use crate::integer::U256;
use crate::safe_deserialization::safe_deserialize_conformant;
use crate::shortint::parameters::classic::compact_pk::*;
use crate::shortint::parameters::*;
use crate::{
    ClientKey, CompactFheUint32, CompactFheUint32List, CompactFheUint32ListConformanceParams,
    CompactPublicKey, CompressedFheUint16, CompressedFheUint256, CompressedFheUint32,
    CompressedPublicKey, Config, FheInt16, FheInt32, FheInt8, FheUint128, FheUint16, FheUint256,
    FheUint32, FheUint32ConformanceParams,
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

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}

#[test]
fn test_compact_public_key_list_big() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS, None)
        .build();
    test_compact_public_key_list(config);
}

#[test]
fn test_compact_public_key_list_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS, None)
        .build();
    test_compact_public_key_list(config);
}

fn test_compact_public_key_list(config: Config) {
    let (client_key, server_key) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let mut rng = rand::thread_rng();

    let clear_xs = (0..50).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    let clear_ys = (0..50).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();

    let compacted_xs = CompactFheUint32List::encrypt(&clear_xs, &public_key);
    let compacted_ys = CompactFheUint32List::encrypt(&clear_ys, &public_key);

    let exs = compacted_xs.expand();
    let eys = compacted_ys.expand();

    set_server_key(server_key);

    let encrypted_results = exs.iter().zip(eys).map(|(x, y)| x + y).collect::<Vec<_>>();
    let clear_results = clear_xs
        .iter()
        .zip(clear_ys)
        .map(|(x, y)| x + y)
        .collect::<Vec<_>>();

    for (encrypted, clear) in encrypted_results.iter().zip(clear_results) {
        let decrypted: u32 = encrypted.decrypt(&client_key);
        assert_eq!(clear, decrypted);
    }

    let compact_single = CompactFheUint32::encrypt(clear_xs[0], &public_key);
    let a = compact_single.expand();
    let decrypted: u32 = a.decrypt(&client_key);
    assert_eq!(clear_xs[0], decrypted);
}

#[test]
fn test_compact_public_key_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS, None)
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
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
    set_server_key(server_key.clone());
    let pk = CompactPublicKey::new(&client_key);

    let clear_a = random::<u32>();
    let a = CompactFheUint32::encrypt(clear_a, &pk);
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = FheUint32ConformanceParams::from(&server_key);
    let deserialized_a =
        safe_deserialize_conformant::<CompactFheUint32>(serialized.as_slice(), 1 << 20, &params)
            .unwrap();
    let decrypted: u32 = deserialized_a.expand().decrypt(&client_key);
    assert_eq!(decrypted, clear_a);

    assert!(deserialized_a.is_conformant(&FheUint32ConformanceParams::from(block_params)));
}

#[test]
fn test_safe_deserialize_conformant_compact_fhe_uint32_list() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());
    let pk = CompactPublicKey::new(&client_key);

    let clears = [random::<u32>(), random::<u32>(), random::<u32>()];
    let compact_list = CompactFheUint32List::encrypt(&clears, &pk);

    let mut serialized = vec![];
    assert!(crate::safe_serialize(&compact_list, &mut serialized, 1 << 20).is_ok());

    let params = CompactFheUint32ListConformanceParams::from((
        &server_key,
        ListSizeConstraint::exact_size(3),
    ));
    let deserialized_list = safe_deserialize_conformant::<CompactFheUint32List>(
        serialized.as_slice(),
        1 << 20,
        &params,
    )
    .unwrap();

    assert!(
        deserialized_list.is_conformant(&CompactFheUint32ListConformanceParams::from((
            block_params,
            ListSizeConstraint::exact_size(3)
        )))
    );

    let expanded_list = deserialized_list.expand();
    for (fhe_uint, expected) in expanded_list.iter().zip(clears.into_iter()) {
        let decrypted: u32 = fhe_uint.decrypt(&client_key);
        assert_eq!(decrypted, expected);
    }
}

#[cfg(feature = "zk-pok-experimental")]
#[test]
fn test_fhe_uint_zk() {
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};

    let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;

    let config = ConfigBuilder::with_custom_parameters(params, None).build();
    let crs = CompactPkeCrs::from_config(config, 32).unwrap();
    let ck = ClientKey::generate(config);
    let pk = CompactPublicKey::new(&ck);

    let msg = random::<u32>();

    let proven_compact_fhe_uint = crate::ProvenCompactFheUint32::try_encrypt(
        msg,
        crs.public_params(),
        &pk,
        ZkComputeLoad::Proof,
    )
    .unwrap();
    let fhe_uint = proven_compact_fhe_uint
        .verify_and_expand(crs.public_params(), &pk)
        .unwrap();
    let decrypted: u32 = fhe_uint.decrypt(&ck);
    assert_eq!(decrypted, msg);

    let messages = (0..4).map(|_| random()).collect::<Vec<u32>>();
    let proven_compact_fhe_uint_list = crate::ProvenCompactFheUint32List::try_encrypt(
        &messages,
        crs.public_params(),
        &pk,
        ZkComputeLoad::Proof,
    )
    .unwrap();
    let fhe_uints = proven_compact_fhe_uint_list
        .verify_and_expand(crs.public_params(), &pk)
        .unwrap();
    let decrypted = fhe_uints
        .iter()
        .map(|fb| fb.decrypt(&ck))
        .collect::<Vec<u32>>();
    assert_eq!(decrypted.as_slice(), &messages);
}
