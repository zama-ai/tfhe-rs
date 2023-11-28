use crate::integer::I256;
use crate::prelude::*;
use crate::{
    generate_keys, set_server_key, CompactFheInt32, CompactFheInt32List, CompactPublicKey,
    CompressedFheInt16, Config, ConfigBuilder, FheInt16, FheInt256, FheInt32, FheInt64, FheInt8,
    FheUint64, FheUint8,
};
use rand::prelude::*;

#[test]
fn test_signed_integer_compressed() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let clear = -1234i16;
    let compressed = CompressedFheInt16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = FheInt16::from(compressed);
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
    let decompressed = FheInt16::from(compressed);
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
            crate::shortint::parameters::parameters_compact_pk::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
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
            crate::shortint::parameters::parameters_compact_pk
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

crate::shortint::parameters::parameters_compact_pk::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();
    test_compact_public_key_list(config);
}

#[test]
fn test_compact_public_key_list_small() {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
            crate::shortint::parameters::parameters_compact_pk
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
