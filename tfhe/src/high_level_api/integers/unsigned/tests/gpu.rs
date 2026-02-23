use crate::conformance::{ListSizeConstraint, ParameterSetConformant};
pub use crate::core_crypto::prelude::{CastFrom, CastInto};
use crate::integer::U256;
use crate::prelude::{
    check_valid_cuda_malloc_assert_oom, AddSizeOnGpu, BitAndSizeOnGpu, BitNotSizeOnGpu,
    BitOrSizeOnGpu, BitXorSizeOnGpu, CiphertextList, DivRemSizeOnGpu, DivSizeOnGpu, FheDecrypt,
    FheEncrypt, FheEqSizeOnGpu, FheMaxSizeOnGpu, FheMinSizeOnGpu, FheOrdSizeOnGpu, FheTryEncrypt,
    IfThenElseSizeOnGpu, MulSizeOnGpu, NegSizeOnGpu, RemSizeOnGpu, RotateLeft, RotateLeftAssign,
    RotateLeftSizeOnGpu, RotateRight, RotateRightAssign, RotateRightSizeOnGpu, ShlSizeOnGpu,
    ShrSizeOnGpu, SubSizeOnGpu,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::{
    set_server_key, ClientKey, CompactCiphertextList, CompactCiphertextListConformanceParams,
    CompactPublicKey, CompressedCompactPublicKey, CompressedFheUint16, CompressedFheUint256,
    CompressedFheUint32, CompressedFheUint32ConformanceParams, ConfigBuilder,
    DeserializationConfig, FheBool, FheInt16, FheInt32, FheInt8, FheUint128, FheUint16, FheUint256,
    FheUint32, FheUint32ConformanceParams, FheUint8, GpuIndex, MatchValues, SerializationConfig,
};
use rand::{random, Rng};

/// GPU setup for tests
///
/// Crates a client key, with the given parameters or default params in None were given
/// and sets the gpu server key for the current thread
pub(crate) fn setup_gpu(params: Option<impl Into<TestParameters>>) -> ClientKey {
    let config = params
        .map_or_else(ConfigBuilder::default, |p| {
            ConfigBuilder::with_custom_parameters(p.into())
        })
        .build();

    let client_key = ClientKey::generate(config);
    let csks = crate::CompressedServerKey::new(&client_key);
    let server_key = csks.decompress_to_gpu();

    set_server_key(server_key);

    client_key
}

pub(crate) fn setup_classical_gpu() -> ClientKey {
    setup_gpu(Some(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128))
}

pub(crate) fn setup_multibit_gpu() -> ClientKey {
    setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ))
}

pub(crate) const GPU_SETUP_FN: [&dyn Fn() -> ClientKey; 2] =
    [&setup_classical_gpu, &setup_multibit_gpu];

#[test]
fn test_integer_compressed_can_be_serialized_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        let clear = U256::from(u64::MAX);
        let compressed = CompressedFheUint256::try_encrypt(clear, &client_key).unwrap();

        let bytes = bincode::serialize(&compressed).unwrap();
        let deserialized: CompressedFheUint256 =
            bincode::deserialize_from(bytes.as_slice()).unwrap();

        let decompressed = FheUint256::from(deserialized.decompress());
        let clear_decompressed: U256 = decompressed.decrypt(&client_key);
        assert_eq!(clear_decompressed, clear);
    }
}

#[test]
fn test_integer_compressed_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        let clear = 12_837u16;
        let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
        let decompressed = FheUint16::from(compressed.decompress());
        let clear_decompressed: u16 = decompressed.decrypt(&client_key);
        assert_eq!(clear_decompressed, clear);
    }
}

#[test]
fn test_integer_compressed_small_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        let clear = 12_837u16;
        let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
        let decompressed = FheUint16::from(compressed.decompress());
        let clear_decompressed: u16 = decompressed.decrypt(&client_key);
        assert_eq!(clear_decompressed, clear);
    }
}

#[test]
fn test_uint8_quickstart_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_uint8_quickstart(&client_key);
}

#[test]
fn test_uint8_quickstart_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_uint8_quickstart(&client_key);
}

#[test]
fn test_uint32_quickstart_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_uint32_quickstart(&client_key);
}

#[test]
fn test_uint32_quickstart_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_uint32_quickstart(&client_key);
}

#[test]
fn test_uint64_quickstart_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_uint64_quickstart(&client_key);
}

#[test]
fn test_uint64_quickstart_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_uint64_quickstart(&client_key);
}

#[test]
fn test_uint32_arith_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_arith(&client_key);
    }
}

#[test]
fn test_uint32_arith_assign_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_arith_assign(&client_key);
    }
}

#[test]
fn test_uint32_scalar_arith_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_scalar_arith(&client_key);
    }
}

#[test]
fn test_uint32_scalar_arith_assign_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_scalar_arith_assign(&client_key);
    }
}

#[test]
fn test_uint32_clone_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_clone(&client_key);
    }
}

#[test]
fn test_uint8_compare_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint8_compare(&client_key);
    }
}

#[test]
fn test_uint8_compare_scalar_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint8_compare_scalar(&client_key);
    }
}

#[test]
fn test_uint32_shift_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_shift(&client_key);
    }
}

#[test]
fn test_uint32_bitwise_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_bitwise(&client_key);
    }
}

#[test]
fn test_uint32_bitwise_assign_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_bitwise_assign(&client_key);
    }
}

#[test]
fn test_uint32_scalar_bitwise_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_scalar_bitwise(&client_key);
    }
}

#[test]
fn test_uint32_rotate_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_rotate(&client_key);
    }
}

#[test]
fn test_uint32_div_rem_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_uint32_div_rem(&client_key);
    }
}

#[test]
fn test_small_uint128_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen::<u128>();
        let clear_b = rng.gen::<u128>();

        let a = FheUint128::try_encrypt(clear_a, &cks).unwrap();
        let b = FheUint128::try_encrypt(clear_b, &cks).unwrap();

        let c = a + b;

        let decrypted: u128 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
    }
}

#[test]
fn test_compact_public_key_big_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        let public_key = CompactPublicKey::new(&client_key);
        let compact_list = CompactCiphertextList::builder(&public_key)
            .push(255u8)
            .build();
        let expanded = compact_list.expand().unwrap();
        let a: FheUint8 = expanded.get(0).unwrap().unwrap();

        let clear: u8 = a.decrypt(&client_key);
        assert_eq!(clear, 255u8);
    }
}

#[test]
fn test_compact_public_key_small_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
        let public_key = CompactPublicKey::new(&client_key);
        let compact_list = CompactCiphertextList::builder(&public_key)
            .push(255u8)
            .build();
        let expanded = compact_list.expand().unwrap();
        let a: FheUint8 = expanded.get(0).unwrap().unwrap();

        let clear: u8 = a.decrypt(&client_key);
        assert_eq!(clear, 255u8);
    }
}

#[test]
fn test_trivial_uint8_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_uint8_trivial(&client_key);
}

#[test]
fn test_trivial_uint256_small_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_uint256_trivial(&client_key);
}

#[test]
fn test_integer_casting_gpu() {
    let mut rng = rand::rng();
    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
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
}

#[test]
fn test_if_then_else_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_if_then_else_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_flip() {
    let client_key = setup_classical_gpu();
    super::test_case_flip(&client_key);
}

#[test]
fn test_flip_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_flip(&client_key);
}

#[test]
fn test_sum_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_sum(&client_key);
}

#[test]
fn test_sum_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_sum(&client_key);
}

#[test]
fn test_is_even_is_odd_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_is_even_is_odd(&client_key);
}

#[test]
fn test_is_even_is_odd_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_is_even_is_odd(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_ilog2_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_ilog2(&client_key);
}

#[test]
fn test_ilog2_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_ilog2(&client_key);
}

#[test]
fn test_min_max() {
    let client_key = setup_classical_gpu();
    super::test_case_min_max(&client_key);
}

#[test]
fn test_match_value_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_match_value(&client_key);
}

#[test]
fn test_match_value_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_match_value(&client_key);
}

#[test]
fn test_min_max_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_min_max(&client_key);
}

#[test]
fn test_scalar_shift_when_clear_type_is_small_gpu() {
    // This is a regression tests
    // The goal is to make sure that doing a scalar shift / rotate
    // with a clear type that does not have enough bits to represent
    // the number of bits of the fhe type correctly works.

    for setup_fn in GPU_SETUP_FN {
        let client_key = setup_fn();
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
}

#[test]
fn test_safe_deserialize_conformant_fhe_uint32_gpu() {
    for (i, setup_fn) in GPU_SETUP_FN.into_iter().enumerate() {
        let client_key = setup_fn();
        let clear_a = random::<u32>();
        let a = FheUint32::encrypt(clear_a, &client_key);
        let mut serialized = vec![];
        SerializationConfig::new(1 << 20)
            .serialize_into(&a, &mut serialized)
            .unwrap();

        let params = if i == 0 {
            FheUint32ConformanceParams::from(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
        } else if i == 1 {
            FheUint32ConformanceParams::from(
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
        } else {
            panic!("Unexpected parameter set")
        };
        let deserialized_a = DeserializationConfig::new(1 << 20)
            .deserialize_from::<FheUint32>(serialized.as_slice(), &params)
            .unwrap();
        let decrypted: u32 = deserialized_a.decrypt(&client_key);
        assert_eq!(decrypted, clear_a);

        assert!(deserialized_a.is_conformant(&params));
    }
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_uint32_gpu() {
    for (i, setup_fn) in GPU_SETUP_FN.into_iter().enumerate() {
        let client_key = setup_fn();
        let clear_a = random::<u32>();
        let a = CompressedFheUint32::encrypt(clear_a, &client_key);
        let mut serialized = vec![];
        SerializationConfig::new(1 << 20)
            .serialize_into(&a, &mut serialized)
            .unwrap();

        let params = if i == 0 {
            CompressedFheUint32ConformanceParams::from(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
        } else if i == 1 {
            CompressedFheUint32ConformanceParams::from(
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            )
        } else {
            panic!("Unexpected parameter set")
        };
        let deserialized_a = DeserializationConfig::new(1 << 20)
            .deserialize_from::<CompressedFheUint32>(serialized.as_slice(), &params)
            .unwrap();

        assert!(deserialized_a.is_conformant(&params));

        let decrypted: u32 = deserialized_a.decompress().decrypt(&client_key);
        assert_eq!(decrypted, clear_a);
    }
}

#[test]
fn test_safe_deserialize_conformant_compact_fhe_uint32_gpu() {
    for (i, setup_fn) in GPU_SETUP_FN.into_iter().enumerate() {
        let client_key = setup_fn();
        let pk = CompactPublicKey::new(&client_key);

        let clears = [random::<u32>(), random::<u32>(), random::<u32>()];
        let a = CompactCiphertextList::builder(&pk)
            .extend(clears.iter().copied())
            .build();
        let mut serialized = vec![];
        SerializationConfig::new(1 << 20)
            .serialize_into(&a, &mut serialized)
            .unwrap();

        let params = if i == 0 {
            CompactCiphertextListConformanceParams::from_parameters_and_size_constraint(
                PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                    .try_into()
                    .unwrap(),
                ListSizeConstraint::exact_size(clears.len()),
            )
            .allow_unpacked()
        } else if i == 1 {
            CompactCiphertextListConformanceParams::from_parameters_and_size_constraint(
                PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
                    .try_into()
                    .unwrap(),
                ListSizeConstraint::exact_size(clears.len()),
            )
            .allow_unpacked()
        } else {
            panic!("Unexpected parameter set")
        };
        let deserialized_a = DeserializationConfig::new(1 << 20)
            .deserialize_from::<CompactCiphertextList>(serialized.as_slice(), &params)
            .unwrap();

        let expander = deserialized_a.expand().unwrap();
        for (i, clear) in clears.into_iter().enumerate() {
            let encrypted: FheUint32 = expander.get(i).unwrap().unwrap();
            let decrypted: u32 = encrypted.decrypt(&client_key);
            assert_eq!(decrypted, clear);
        }

        assert!(deserialized_a.is_conformant(&params));
    }
}

#[test]
fn test_cpk_encrypt_cast_compute_hl_gpu() {
    let param_pke_only = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_fhe = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_ksk = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let num_block = 4usize;

    assert_eq!(param_pke_only.message_modulus, param_fhe.message_modulus);
    assert_eq!(param_pke_only.carry_modulus, param_fhe.carry_modulus);

    let modulus = param_fhe.message_modulus.0.pow(num_block as u32);

    let client_key = ClientKey::generate(
        ConfigBuilder::with_custom_parameters(param_fhe)
            .use_dedicated_compact_public_key_parameters((param_pke_only, param_ksk)),
    );
    let compressed_server_key = client_key.generate_compressed_server_key();
    let server_key = compressed_server_key.decompress_to_gpu();
    set_server_key(server_key);

    use rand::Rng;
    let mut rng = rand::rng();

    let input_msg: u64 = rng.gen_range(0..modulus);

    let pk = CompactPublicKey::new(&client_key);

    // Encrypt a value and cast
    let mut builder = CompactCiphertextList::builder(&pk);
    let list = builder
        .push_with_num_bits(input_msg, 8)
        .unwrap()
        .build_packed();

    let expander = list.expand().unwrap();
    let ct1_extracted_and_cast = expander.get::<FheUint8>(0).unwrap().unwrap();

    let sanity_cast: u64 = ct1_extracted_and_cast.decrypt(&client_key);
    assert_eq!(sanity_cast, input_msg);

    let multiplier = rng.gen_range(0..modulus);

    // Classical AP: DP, KS, PBS
    let mul = &ct1_extracted_and_cast * multiplier as u8;

    // High level decryption and test
    let clear: u64 = mul.decrypt(&client_key);
    assert_eq!(clear, (input_msg * multiplier) % modulus);
}

#[test]
fn test_compressed_cpk_encrypt_cast_compute_hl_gpu() {
    let param_pke_only = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_fhe = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let param_ksk = PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let num_block = 4usize;

    assert_eq!(param_pke_only.message_modulus, param_fhe.message_modulus);
    assert_eq!(param_pke_only.carry_modulus, param_fhe.carry_modulus);

    let modulus = param_fhe.message_modulus.0.pow(num_block as u32);

    let config = ConfigBuilder::with_custom_parameters(param_fhe)
        .use_dedicated_compact_public_key_parameters((param_pke_only, param_ksk))
        .build();
    let client_key = ClientKey::generate(config);
    let compressed_server_key = client_key.generate_compressed_server_key();
    let server_key = compressed_server_key.decompress_to_gpu();
    set_server_key(server_key);

    use rand::Rng;
    let mut rng = rand::rng();

    let input_msg: u64 = rng.gen_range(0..modulus);

    let compressed_pk = CompressedCompactPublicKey::new(&client_key);
    let pk = compressed_pk.decompress();

    // Encrypt a value and cast
    let mut builder = CompactCiphertextList::builder(&pk);
    let list = builder
        .push_with_num_bits(input_msg, 8)
        .unwrap()
        .build_packed();

    let expander = list.expand().unwrap();
    let ct1_extracted_and_cast = expander.get::<FheUint8>(0).unwrap().unwrap();

    let sanity_cast: u64 = ct1_extracted_and_cast.decrypt(&client_key);
    assert_eq!(sanity_cast, input_msg);

    let multiplier = rng.gen_range(0..modulus);

    // Classical AP: DP, KS, PBS
    let mul = &ct1_extracted_and_cast * multiplier as u8;

    // High level decryption and test
    let clear: u64 = mul.decrypt(&client_key);
    assert_eq!(clear, (input_msg * multiplier) % modulus);
}

#[test]
fn test_gpu_get_add_and_sub_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();

        let a = &a;
        let b = &b;

        let add_tmp_buffer_size = a.get_add_size_on_gpu(b);
        let sub_tmp_buffer_size = a.get_sub_size_on_gpu(b);
        let scalar_add_tmp_buffer_size = clear_a.get_add_size_on_gpu(b);
        let scalar_sub_tmp_buffer_size = clear_a.get_sub_size_on_gpu(b);
        check_valid_cuda_malloc_assert_oom(add_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(sub_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_add_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_sub_tmp_buffer_size, GpuIndex::new(0));
        assert_eq!(add_tmp_buffer_size, sub_tmp_buffer_size);
        assert_eq!(add_tmp_buffer_size, scalar_add_tmp_buffer_size);
        assert_eq!(add_tmp_buffer_size, scalar_sub_tmp_buffer_size);
        let neg_tmp_buffer_size = a.get_neg_size_on_gpu();
        check_valid_cuda_malloc_assert_oom(neg_tmp_buffer_size, GpuIndex::new(0));
    }
}
#[test]
fn test_gpu_get_bitops_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();

        let a = &a;
        let b = &b;

        let bitand_tmp_buffer_size = a.get_bitand_size_on_gpu(b);
        let scalar_bitand_tmp_buffer_size = clear_a.get_bitand_size_on_gpu(b);
        check_valid_cuda_malloc_assert_oom(bitand_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_bitand_tmp_buffer_size, GpuIndex::new(0));
        let bitor_tmp_buffer_size = a.get_bitor_size_on_gpu(b);
        let scalar_bitor_tmp_buffer_size = clear_a.get_bitor_size_on_gpu(b);
        check_valid_cuda_malloc_assert_oom(bitor_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_bitor_tmp_buffer_size, GpuIndex::new(0));
        let bitxor_tmp_buffer_size = a.get_bitxor_size_on_gpu(b);
        let scalar_bitxor_tmp_buffer_size = clear_a.get_bitxor_size_on_gpu(b);
        check_valid_cuda_malloc_assert_oom(bitxor_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_bitxor_tmp_buffer_size, GpuIndex::new(0));
        let bitnot_tmp_buffer_size = a.get_bitnot_size_on_gpu();
        check_valid_cuda_malloc_assert_oom(bitnot_tmp_buffer_size, GpuIndex::new(0));
    }
}
#[test]
fn test_gpu_get_comparisons_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();
        let a = &a;
        let b = &b;

        let gt_tmp_buffer_size = a.get_gt_size_on_gpu(b);
        let scalar_gt_tmp_buffer_size = a.get_gt_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(gt_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_gt_tmp_buffer_size, GpuIndex::new(0));
        let ge_tmp_buffer_size = a.get_ge_size_on_gpu(b);
        let scalar_ge_tmp_buffer_size = a.get_ge_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(ge_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_ge_tmp_buffer_size, GpuIndex::new(0));
        let lt_tmp_buffer_size = a.get_lt_size_on_gpu(b);
        let scalar_lt_tmp_buffer_size = a.get_lt_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(lt_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_lt_tmp_buffer_size, GpuIndex::new(0));
        let le_tmp_buffer_size = a.get_le_size_on_gpu(b);
        let scalar_le_tmp_buffer_size = a.get_le_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(le_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_le_tmp_buffer_size, GpuIndex::new(0));
        let max_tmp_buffer_size = a.get_max_size_on_gpu(b);
        let scalar_max_tmp_buffer_size = a.get_max_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(max_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_max_tmp_buffer_size, GpuIndex::new(0));
        let min_tmp_buffer_size = a.get_min_size_on_gpu(b);
        let scalar_min_tmp_buffer_size = a.get_min_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(min_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_min_tmp_buffer_size, GpuIndex::new(0));
        let eq_tmp_buffer_size = a.get_eq_size_on_gpu(b);
        let scalar_eq_tmp_buffer_size = a.get_eq_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(eq_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_eq_tmp_buffer_size, GpuIndex::new(0));
        let ne_tmp_buffer_size = a.get_ne_size_on_gpu(b);
        let scalar_ne_tmp_buffer_size = a.get_ne_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(ne_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_ne_tmp_buffer_size, GpuIndex::new(0));
    }
}

#[test]
fn test_gpu_get_shift_rotate_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();
        let a = &a;
        let b = &b;

        let left_shift_tmp_buffer_size = a.get_left_shift_size_on_gpu(b);
        let scalar_left_shift_tmp_buffer_size = a.get_left_shift_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(left_shift_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_left_shift_tmp_buffer_size, GpuIndex::new(0));
        let right_shift_tmp_buffer_size = a.get_right_shift_size_on_gpu(b);
        let scalar_right_shift_tmp_buffer_size = a.get_right_shift_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(right_shift_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_right_shift_tmp_buffer_size, GpuIndex::new(0));
        let rotate_left_tmp_buffer_size = a.get_rotate_left_size_on_gpu(b);
        let scalar_rotate_left_tmp_buffer_size = a.get_rotate_left_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(rotate_left_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_rotate_left_tmp_buffer_size, GpuIndex::new(0));
        let rotate_right_tmp_buffer_size = a.get_rotate_right_size_on_gpu(b);
        let scalar_rotate_right_tmp_buffer_size = a.get_rotate_right_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(rotate_right_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_rotate_right_tmp_buffer_size, GpuIndex::new(0));
    }
}

#[test]
fn test_gpu_get_if_then_else_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let clear_c = rng.gen_range(0..=1);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        let c = FheBool::encrypt(clear_c != 0, &cks);
        a.move_to_current_device();
        b.move_to_current_device();
        let a = &a;
        let b = &b;

        let if_then_else_tmp_buffer_size = c.get_if_then_else_size_on_gpu(a, b);
        check_valid_cuda_malloc_assert_oom(if_then_else_tmp_buffer_size, GpuIndex::new(0));
        let select_tmp_buffer_size = c.get_select_size_on_gpu(a, b);
        check_valid_cuda_malloc_assert_oom(select_tmp_buffer_size, GpuIndex::new(0));
        let cmux_tmp_buffer_size = c.get_cmux_size_on_gpu(a, b);
        check_valid_cuda_malloc_assert_oom(cmux_tmp_buffer_size, GpuIndex::new(0));
    }
}
#[test]
fn test_gpu_get_mul_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();

        let a = &a;
        let b = &b;

        let mul_tmp_buffer_size = a.get_mul_size_on_gpu(b);
        let scalar_mul_tmp_buffer_size = b.get_mul_size_on_gpu(clear_a);
        check_valid_cuda_malloc_assert_oom(mul_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_mul_tmp_buffer_size, GpuIndex::new(0));
    }
}
#[test]
fn test_gpu_get_div_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=u32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();

        let a = &a;
        let b = &b;

        let div_tmp_buffer_size = a.get_div_size_on_gpu(b);
        let rem_tmp_buffer_size = a.get_rem_size_on_gpu(b);
        let div_rem_tmp_buffer_size = a.get_div_rem_size_on_gpu(b);
        check_valid_cuda_malloc_assert_oom(div_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(rem_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(div_rem_tmp_buffer_size, GpuIndex::new(0));
        let scalar_div_tmp_buffer_size = a.get_div_size_on_gpu(clear_b);
        let scalar_rem_tmp_buffer_size = a.get_rem_size_on_gpu(clear_b);
        let scalar_div_rem_tmp_buffer_size = a.get_div_rem_size_on_gpu(clear_b);
        check_valid_cuda_malloc_assert_oom(scalar_div_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_rem_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_div_rem_tmp_buffer_size, GpuIndex::new(0));
    }
}

#[test]
fn test_gpu_get_match_value_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen::<u32>();
        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        a.move_to_current_device();
        let match_values = MatchValues::new(vec![
            (0u32, 10u32),
            (1u32, 20u32),
            (clear_a, 30u32),
            (u32::MAX, 40u32),
        ])
        .unwrap();
        let memory_size = a.get_match_value_size_on_gpu(&match_values).unwrap();
        check_valid_cuda_malloc_assert_oom(memory_size, GpuIndex::new(0));
        assert!(memory_size > 0);
    }
}

#[test]
fn test_match_value_or_gpu() {
    let client_key = setup_classical_gpu();
    super::test_case_match_value_or(&client_key);
}

#[test]
fn test_match_value_or_gpu_multibit() {
    let client_key = setup_multibit_gpu();
    super::test_case_match_value_or(&client_key);
}

#[test]
fn test_gpu_get_match_value_or_size_on_gpu() {
    for setup_fn in GPU_SETUP_FN {
        let cks = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen::<u32>();
        let or_value = rng.gen::<u32>();

        let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
        a.move_to_current_device();

        let match_values = MatchValues::new(vec![
            (0u32, 10u32),
            (1u32, 20u32),
            (clear_a, 30u32),
            (u32::MAX, 40u32),
        ])
        .unwrap();

        let memory_size = a
            .get_match_value_or_size_on_gpu(&match_values, or_value)
            .unwrap();
        check_valid_cuda_malloc_assert_oom(memory_size, GpuIndex::new(0));
        assert!(memory_size > 0);
    }
}
