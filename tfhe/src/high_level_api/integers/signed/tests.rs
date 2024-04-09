use crate::conformance::ListSizeConstraint;
use crate::integer::I256;
use crate::prelude::*;
use crate::safe_deserialization::safe_deserialize_conformant;
use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use crate::{
    generate_keys, set_server_key, ClientKey, CompactFheInt32, CompactFheInt32List,
    CompactFheInt32ListConformanceParams, CompactPublicKey, CompressedFheInt16, CompressedFheInt32,
    Config, ConfigBuilder, FheInt16, FheInt256, FheInt32, FheInt32ConformanceParams, FheInt64,
    FheInt8, FheUint64, FheUint8,
};
use rand::prelude::*;

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

    let config = ConfigBuilder::default_with_small_encryption().build();
    let (client_key, _) = generate_keys(config);

    let clear = rng.gen::<i16>();
    let compressed = CompressedFheInt16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = compressed.decompress();
    let clear_decompressed: i16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_int32_compare() {
    let mut rng = thread_rng();

    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_a = rng.gen::<i32>();
    let clear_b = rng.gen::<i32>();

    let a = FheInt32::encrypt(clear_a, &client_key);
    let b = FheInt32::encrypt(clear_b, &client_key);

    // Test comparing encrypted with encrypted
    {
        let result = &a.eq(&b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a == clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.eq(&a);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a == clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(&b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a != clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(&a);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a != clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.le(&b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a <= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.lt(&b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a < clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ge(&b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a >= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.gt(&b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a > clear_b;
        assert_eq!(decrypted_result, clear_result);
    }

    // Test comparing encrypted with clear
    {
        let result = &a.eq(clear_b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a == clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.eq(clear_a);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a == clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(clear_b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a != clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(clear_a);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a != clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.le(clear_b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a <= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.lt(clear_b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a < clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ge(clear_b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a >= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.gt(clear_b);
        let decrypted_result = result.decrypt(&client_key);
        let clear_result = clear_a > clear_b;
        assert_eq!(decrypted_result, clear_result);
    }
}

#[test]
fn test_int32_bitwise() {
    let config = ConfigBuilder::default().build();

    let (cks, sks) = generate_keys(config);

    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<i32>();
    let clear_b = rng.gen::<i32>();

    let a = FheInt32::try_encrypt(clear_a, &cks).unwrap();
    let b = FheInt32::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    // encrypted bitwise
    {
        let c = &a | &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let c = &a & &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let c = &a ^ &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a ^ clear_b);

        let mut c = a.clone();
        c |= &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let mut c = a.clone();
        c &= &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let mut c = a.clone();
        c ^= &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a ^ clear_b);
    }

    // clear bitwise
    {
        let c = &a | b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let c = &a & clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let c = &a ^ clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a ^ clear_b);

        let mut c = a.clone();
        c |= clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let mut c = a.clone();
        c &= clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let mut c = a;
        c ^= clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a ^ clear_b);
    }
}

fn fhe_int64_rotate(config: Config) {
    let (cks, sks) = generate_keys(config);

    let mut rng = thread_rng();
    let clear_a = rng.gen::<i64>();
    let clear_b = rng.gen_range(0u32..64u32);

    let a = FheInt64::try_encrypt(clear_a, &cks).unwrap();
    let b = FheUint64::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    // encrypted rotate
    {
        let c = (&a).rotate_left(&b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));

        let c = (&a).rotate_right(&b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_right_assign(&b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_left_assign(&b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));
    }

    // clear rotate
    {
        let c = (&a).rotate_left(clear_b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));

        let c = (&a).rotate_right(clear_b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_right_assign(clear_b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a;
        c.rotate_left_assign(clear_b);
        let decrypted: i64 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));
    }
}
#[test]
fn test_int64_rotate() {
    let config = ConfigBuilder::default().build();
    fhe_int64_rotate(config);
}

#[test]
fn test_multi_bit_rotate() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            crate::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
        )
        .build();
    fhe_int64_rotate(config);
}

fn fhe_int32_div_rem(config: Config) {
    let (cks, sks) = generate_keys(config);

    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<i32>();
    let clear_b = loop {
        let value = rng.gen::<i32>();
        if value != 0 {
            break value;
        }
    };

    let a = FheInt32::try_encrypt(clear_a, &cks).unwrap();
    let b = FheInt32::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    // encrypted div/rem
    {
        let c = &a / &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let c = &a % &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a % clear_b);

        let (q, r) = (&a).div_rem(&b);
        let decrypted_q: i32 = q.decrypt(&cks);
        let decrypted_r: i32 = r.decrypt(&cks);
        assert_eq!(decrypted_q, clear_a / clear_b);
        assert_eq!(decrypted_r, clear_a % clear_b);

        let mut c = a.clone();
        c /= &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let mut c = a.clone();
        c %= &b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a % clear_b);
    }

    // clear div/rem
    {
        let c = &a / clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let c = &a % clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a % clear_b);

        let (q, r) = (&a).div_rem(clear_b);
        let decrypted_q: i32 = q.decrypt(&cks);
        let decrypted_r: i32 = r.decrypt(&cks);
        assert_eq!(decrypted_q, clear_a / clear_b);
        assert_eq!(decrypted_r, clear_a % clear_b);

        let mut c = a.clone();
        c /= clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let mut c = a;
        c %= clear_b;
        let decrypted: i32 = c.decrypt(&cks);
        assert_eq!(decrypted, clear_a % clear_b);
    }
}

#[test]
fn test_int32_div_rem() {
    let config = ConfigBuilder::default().build();
    fhe_int32_div_rem(config);
}

#[test]
fn test_multi_div_rem() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            crate::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
        )
        .build();
    fhe_int32_div_rem(config);
}
#[test]
fn test_integer_casting() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let mut rng = rand::thread_rng();

    // Ensure casting works for both negative and positive values
    for clear in [rng.gen_range(i16::MIN..0), rng.gen_range(0..=i16::MAX)] {
        // Downcasting then Upcasting
        {
            let a = FheInt16::encrypt(clear, &client_key);

            // Downcasting
            let a: FheInt8 = a.cast_into();
            let da: i8 = a.decrypt(&client_key);
            assert_eq!(da, clear as i8);

            // Upcasting
            let a: FheInt32 = a.cast_into();
            let da: i32 = a.decrypt(&client_key);
            assert_eq!(da, (clear as i8) as i32);
        }

        // Upcasting then Downcasting
        {
            let a = FheInt16::encrypt(clear, &client_key);

            // Upcasting
            let a = FheInt32::cast_from(a);
            let da: i32 = a.decrypt(&client_key);
            assert_eq!(da, clear as i32);

            // Downcasting
            let a = FheInt8::cast_from(a);
            let da: i8 = a.decrypt(&client_key);
            assert_eq!(da, (clear as i32) as i8);
        }

        // Casting to self, it not useful but is supported
        {
            let a = FheInt16::encrypt(clear, &client_key);
            let a = FheInt16::cast_from(a);
            let da: i16 = a.decrypt(&client_key);
            assert_eq!(da, clear);
        }

        // Casting to a smaller unsigned type, then casting to bigger signed type
        {
            let a = FheInt16::encrypt(clear, &client_key);

            // Downcasting to un
            let a: FheUint8 = a.cast_into();
            let da: u8 = a.decrypt(&client_key);
            assert_eq!(da, clear as u8);

            // Upcasting
            let a: FheInt32 = a.cast_into();
            let da: i32 = a.decrypt(&client_key);
            assert_eq!(da, (clear as u8) as i32);
        }

        // Casting to a bigger unsigned type, then casting to smaller signed type
        {
            let a = FheInt16::encrypt(clear, &client_key);

            // Downcasting to un
            let a: FheUint64 = a.cast_into();
            let da: u64 = a.decrypt(&client_key);
            assert_eq!(da, clear as u64);

            // Upcasting
            let a: FheInt32 = a.cast_into();
            let da: i32 = a.decrypt(&client_key);
            assert_eq!(da, (clear as u64) as i32);
        }
    }
}

#[test]
fn test_if_then_else() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let mut rng = rand::thread_rng();

    let clear_a = rng.gen::<i8>();
    let clear_b = rng.gen::<i8>();

    let a = FheInt8::encrypt(clear_a, &client_key);
    let b = FheInt8::encrypt(clear_b, &client_key);

    let result = a.le(&b).if_then_else(&a, &b);
    let decrypted_result: i8 = result.decrypt(&client_key);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_a } else { clear_b }
    );

    let result = a.le(&b).if_then_else(&b, &a);
    let decrypted_result: i8 = result.decrypt(&client_key);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_b } else { clear_a }
    );
}

#[test]
fn test_abs() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let mut rng = rand::thread_rng();

    for clear in [rng.gen_range(i64::MIN..0), rng.gen_range(0..=i64::MAX)] {
        let a = FheInt64::encrypt(clear, &client_key);
        let abs_a = a.abs();
        let decrypted_result: i64 = abs_a.decrypt(&client_key);
        assert_eq!(decrypted_result, clear.abs());
    }
}

#[test]
fn test_integer_compress_decompress() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let a = FheInt8::try_encrypt(-83i8, &client_key).unwrap();

    let clear: i8 = a.compress().decompress().decrypt(&client_key);

    assert_eq!(clear, -83i8);
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
    let config = ConfigBuilder::default_with_small_encryption().build();
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
        .use_custom_parameters(
            crate::shortint::parameters::classic::compact_pk::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let a = FheInt8::try_encrypt(-1i8, &public_key).unwrap();
    let clear: i8 = a.decrypt(&client_key);
    assert_eq!(clear, -1i8);
}

#[test]
fn test_compact_public_key_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            crate::shortint::parameters::classic::compact_pk
            ::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
            None,
        )
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let a = FheInt8::try_encrypt(-123i8, &public_key).unwrap();
    let clear: i8 = a.decrypt(&client_key);
    assert_eq!(clear, -123i8);
}

#[test]
fn test_compact_public_key_list_big() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(

crate::shortint::parameters::classic::compact_pk::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();
    test_compact_public_key_list(config);
}

#[test]
fn test_compact_public_key_list_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            crate::shortint::parameters::classic::compact_pk
            ::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
            None,
        )
        .build();
    test_compact_public_key_list(config);
}

fn test_compact_public_key_list(config: Config) {
    let (client_key, server_key) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let mut rng = rand::thread_rng();

    let clear_xs = (0..50).map(|_| rng.gen::<i32>()).collect::<Vec<_>>();
    let clear_ys = (0..50).map(|_| rng.gen::<i32>()).collect::<Vec<_>>();

    let compacted_xs = CompactFheInt32List::encrypt(&clear_xs, &public_key);
    let compacted_ys = CompactFheInt32List::encrypt(&clear_ys, &public_key);

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
        let decrypted: i32 = encrypted.decrypt(&client_key);
        assert_eq!(clear, decrypted);
    }

    let compact_single = CompactFheInt32::encrypt(clear_xs[0], &public_key);
    let a = compact_single.expand();
    let decrypted: i32 = a.decrypt(&client_key);
    assert_eq!(clear_xs[0], decrypted);
}

fn test_case_leading_trailing_zeros_ones(cks: &ClientKey) {
    let mut rng = thread_rng();
    for _ in 0..5 {
        let clear_a = rng.gen::<i32>();
        let a = FheInt32::try_encrypt(clear_a, cks).unwrap();

        let leading_zeros: u32 = a.leading_zeros().decrypt(cks);
        assert_eq!(leading_zeros, clear_a.leading_zeros());

        let leading_ones: u32 = a.leading_ones().decrypt(cks);
        assert_eq!(leading_ones, clear_a.leading_ones());

        let trailing_zeros: u32 = a.trailing_zeros().decrypt(cks);
        assert_eq!(trailing_zeros, clear_a.trailing_zeros());

        let trailing_ones: u32 = a.trailing_ones().decrypt(cks);
        assert_eq!(trailing_ones, clear_a.trailing_ones());
    }
}

fn test_case_ilog2(cks: &ClientKey) {
    let mut rng = thread_rng();
    for _ in 0..5 {
        let clear_a = rng.gen_range(1..=i32::MAX);
        let a = FheInt32::try_encrypt(clear_a, cks).unwrap();

        let ilog2: u32 = a.ilog2().decrypt(cks);
        assert_eq!(ilog2, clear_a.ilog2());

        let (ilog2, is_ok) = a.checked_ilog2();
        let ilog2: u32 = ilog2.decrypt(cks);
        let is_ok = is_ok.decrypt(cks);
        assert!(is_ok);
        assert_eq!(ilog2, clear_a.ilog2());
    }

    for _ in 0..5 {
        let a = FheInt32::try_encrypt(rng.gen_range(i32::MIN..=0), cks).unwrap();

        let (_ilog2, is_ok) = a.checked_ilog2();
        let is_ok = is_ok.decrypt(cks);
        assert!(!is_ok);
    }
}

#[test]
fn test_ilog2() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key);
    test_case_ilog2(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key);
    test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_safe_deserialize_conformant_fhe_int32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());

    let clear_a = random::<i32>();
    let a = FheInt32::encrypt(clear_a, &client_key);
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = FheInt32ConformanceParams::from(&server_key);
    let deserialized_a =
        safe_deserialize_conformant::<FheInt32>(serialized.as_slice(), 1 << 20, &params).unwrap();
    let decrypted: i32 = deserialized_a.decrypt(&client_key);
    assert_eq!(decrypted, clear_a);

    let params = FheInt32ConformanceParams::from(block_params);
    assert!(deserialized_a.is_conformant(&params));
}

#[test]
fn test_safe_deserialize_conformant_compressed_fhe_int32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());

    let clear_a = random::<i32>();
    let a = CompressedFheInt32::encrypt(clear_a, &client_key);
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = FheInt32ConformanceParams::from(&server_key);
    let deserialized_a =
        safe_deserialize_conformant::<CompressedFheInt32>(serialized.as_slice(), 1 << 20, &params)
            .unwrap();

    let params = FheInt32ConformanceParams::from(block_params);
    assert!(deserialized_a.is_conformant(&params));

    let decrypted: i32 = deserialized_a.decompress().decrypt(&client_key);
    assert_eq!(decrypted, clear_a);
}

#[test]
fn test_safe_deserialize_conformant_compact_fhe_int32() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());
    let pk = CompactPublicKey::new(&client_key);

    let clear_a = random::<i32>();
    let a = CompactFheInt32::encrypt(clear_a, &pk);
    let mut serialized = vec![];
    assert!(crate::safe_serialize(&a, &mut serialized, 1 << 20).is_ok());

    let params = FheInt32ConformanceParams::from(&server_key);
    let deserialized_a =
        safe_deserialize_conformant::<CompactFheInt32>(serialized.as_slice(), 1 << 20, &params)
            .unwrap();
    let decrypted: i32 = deserialized_a.expand().decrypt(&client_key);
    assert_eq!(decrypted, clear_a);

    let params = FheInt32ConformanceParams::from(block_params);
    assert!(deserialized_a.is_conformant(&params));
}

#[test]
fn test_safe_deserialize_conformant_compact_fhe_int32_list() {
    let block_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let (client_key, server_key) =
        generate_keys(ConfigBuilder::with_custom_parameters(block_params, None));
    set_server_key(server_key.clone());
    let pk = CompactPublicKey::new(&client_key);

    let clears = [random::<i32>(), random::<i32>(), random::<i32>()];
    let compact_list = CompactFheInt32List::encrypt(&clears, &pk);

    let mut serialized = vec![];
    assert!(crate::safe_serialize(&compact_list, &mut serialized, 1 << 20).is_ok());

    let params = CompactFheInt32ListConformanceParams::from((
        &server_key,
        ListSizeConstraint::exact_size(3),
    ));
    let deserialized_list =
        safe_deserialize_conformant::<CompactFheInt32List>(serialized.as_slice(), 1 << 20, &params)
            .unwrap();

    let expanded_list = deserialized_list.expand();
    for (fhe_uint, expected) in expanded_list.iter().zip(clears.into_iter()) {
        let decrypted: i32 = fhe_uint.decrypt(&client_key);
        assert_eq!(decrypted, expected);
    }

    let params = CompactFheInt32ListConformanceParams::from((
        block_params,
        ListSizeConstraint::exact_size(3),
    ));
    assert!(deserialized_list.is_conformant(&params));
}

#[cfg(feature = "zk-pok-experimental")]
#[test]
fn test_fhe_int_zk() {
    use crate::zk::{CompactPkeCrs, ZkComputeLoad};

    let params =
        crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;

    let config = ConfigBuilder::with_custom_parameters(params, None).build();
    let crs = CompactPkeCrs::from_config(config, 32).unwrap();
    let ck = ClientKey::generate(config);
    let pk = CompactPublicKey::new(&ck);

    let msg = random::<i32>();

    let proven_compact_fhe_uint = crate::ProvenCompactFheInt32::try_encrypt(
        msg,
        crs.public_params(),
        &pk,
        ZkComputeLoad::Proof,
    )
    .unwrap();
    let fhe_uint = proven_compact_fhe_uint
        .verify_and_expand(crs.public_params(), &pk)
        .unwrap();
    let decrypted: i32 = fhe_uint.decrypt(&ck);
    assert_eq!(decrypted, msg);

    let messages = (0..4).map(|_| random()).collect::<Vec<i32>>();
    let proven_compact_fhe_uint_list = crate::ProvenCompactFheInt32List::try_encrypt(
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
        .collect::<Vec<i32>>();
    assert_eq!(decrypted.as_slice(), &messages);
}
