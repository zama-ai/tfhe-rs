use crate::prelude::*;
use crate::{ClientKey, FheBool, FheInt16, FheInt32, FheInt64, FheInt8, FheUint64, FheUint8};
use rand::prelude::*;

mod cpu;
#[cfg(feature = "gpu")]
mod gpu;

#[allow(clippy::eq_op)]
fn test_case_int32_compare(cks: &ClientKey) {
    let mut rng = thread_rng();

    let clear_a = rng.gen::<i32>();
    let clear_b = rng.gen::<i32>();

    let a = FheInt32::encrypt(clear_a, cks);
    let b = FheInt32::encrypt(clear_b, cks);

    // Test comparing encrypted with encrypted
    {
        let result = &a.eq(&b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a == clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.eq(&a);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a == clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(&b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a != clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(&a);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a != clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.le(&b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a <= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.lt(&b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a < clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ge(&b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a >= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.gt(&b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a > clear_b;
        assert_eq!(decrypted_result, clear_result);
    }

    // Test comparing encrypted with clear
    {
        let result = &a.eq(clear_b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a == clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.eq(clear_a);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a == clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(clear_b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a != clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ne(clear_a);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a != clear_a;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.le(clear_b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a <= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.lt(clear_b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a < clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.ge(clear_b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a >= clear_b;
        assert_eq!(decrypted_result, clear_result);

        let result = &a.gt(clear_b);
        let decrypted_result = result.decrypt(cks);
        let clear_result = clear_a > clear_b;
        assert_eq!(decrypted_result, clear_result);
    }
}

fn test_case_int32_bitwise(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<i32>();
    let clear_b = rng.gen::<i32>();

    let a = FheInt32::try_encrypt(clear_a, cks).unwrap();
    let b = FheInt32::try_encrypt(clear_b, cks).unwrap();

    // encrypted bitwise
    {
        let c = &a | &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let c = &a & &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let c = &a ^ &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a ^ clear_b);

        let mut c = a.clone();
        c |= &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let mut c = a.clone();
        c &= &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let mut c = a.clone();
        c ^= &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a ^ clear_b);
    }

    // clear bitwise
    {
        let c = &a | b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let c = &a & clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let c = &a ^ clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a ^ clear_b);

        let mut c = a.clone();
        c |= clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let mut c = a.clone();
        c &= clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let mut c = a;
        c ^= clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a ^ clear_b);
    }
}

fn test_case_int64_rotate(cks: &ClientKey) {
    let mut rng = thread_rng();
    let clear_a = rng.gen::<i64>();
    let clear_b = rng.gen_range(0u32..64u32);

    let a = FheInt64::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint64::try_encrypt(clear_b, cks).unwrap();

    // encrypted rotate
    {
        let c = (&a).rotate_left(&b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));

        let c = (&a).rotate_right(&b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_right_assign(&b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_left_assign(&b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));
    }

    // clear rotate
    {
        let c = (&a).rotate_left(clear_b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));

        let c = (&a).rotate_right(clear_b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_right_assign(clear_b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a;
        c.rotate_left_assign(clear_b);
        let decrypted: i64 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));
    }
}

fn test_case_int32_div_rem(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<i32>();
    let clear_b = loop {
        let value = rng.gen::<i32>();
        if value != 0 {
            break value;
        }
    };

    let a = FheInt32::try_encrypt(clear_a, cks).unwrap();
    let b = FheInt32::try_encrypt(clear_b, cks).unwrap();

    // encrypted div/rem
    {
        let c = &a / &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let c = &a % &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);

        let (q, r) = (&a).div_rem(&b);
        let decrypted_q: i32 = q.decrypt(cks);
        let decrypted_r: i32 = r.decrypt(cks);
        assert_eq!(decrypted_q, clear_a / clear_b);
        assert_eq!(decrypted_r, clear_a % clear_b);

        let mut c = a.clone();
        c /= &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let mut c = a.clone();
        c %= &b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);
    }

    // clear div/rem
    {
        let c = &a / clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let c = &a % clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);

        let (q, r) = (&a).div_rem(clear_b);
        let decrypted_q: i32 = q.decrypt(cks);
        let decrypted_r: i32 = r.decrypt(cks);
        assert_eq!(decrypted_q, clear_a / clear_b);
        assert_eq!(decrypted_r, clear_a % clear_b);

        let mut c = a.clone();
        c /= clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let mut c = a;
        c %= clear_b;
        let decrypted: i32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);
    }
}

fn test_case_integer_casting(cks: &ClientKey) {
    let mut rng = rand::rng();

    // Ensure casting works for both negative and positive values
    for clear in [rng.gen_range(i16::MIN..0), rng.gen_range(0..=i16::MAX)] {
        // Downcasting then Upcasting
        {
            let a = FheInt16::encrypt(clear, cks);

            // Downcasting
            let a: FheInt8 = a.cast_into();
            let da: i8 = a.decrypt(cks);
            assert_eq!(da, clear as i8);

            // Upcasting
            let a: FheInt32 = a.cast_into();
            let da: i32 = a.decrypt(cks);
            assert_eq!(da, (clear as i8) as i32);
        }

        // Upcasting then Downcasting
        {
            let a = FheInt16::encrypt(clear, cks);

            // Upcasting
            let a = FheInt32::cast_from(a);
            let da: i32 = a.decrypt(cks);
            assert_eq!(da, clear as i32);

            // Downcasting
            let a = FheInt8::cast_from(a);
            let da: i8 = a.decrypt(cks);
            assert_eq!(da, (clear as i32) as i8);
        }

        // Casting to self, it not useful but is supported
        {
            let a = FheInt16::encrypt(clear, cks);
            let a = FheInt16::cast_from(a);
            let da: i16 = a.decrypt(cks);
            assert_eq!(da, clear);
        }

        // Casting to a smaller unsigned type, then casting to bigger signed type
        {
            let a = FheInt16::encrypt(clear, cks);

            // Downcasting to un
            let a: FheUint8 = a.cast_into();
            let da: u8 = a.decrypt(cks);
            assert_eq!(da, clear as u8);

            // Upcasting
            let a: FheInt32 = a.cast_into();
            let da: i32 = a.decrypt(cks);
            assert_eq!(da, (clear as u8) as i32);
        }

        // Casting to a bigger unsigned type, then casting to smaller signed type
        {
            let a = FheInt16::encrypt(clear, cks);

            // Downcasting to un
            let a: FheUint64 = a.cast_into();
            let da: u64 = a.decrypt(cks);
            assert_eq!(da, clear as u64);

            // Upcasting
            let a: FheInt32 = a.cast_into();
            let da: i32 = a.decrypt(cks);
            assert_eq!(da, (clear as u64) as i32);
        }
    }
}

fn test_case_if_then_else(cks: &ClientKey) {
    let mut rng = rand::rng();

    let clear_a = rng.gen::<i8>();
    let clear_b = rng.gen::<i8>();

    let a = FheInt8::encrypt(clear_a, cks);
    let b = FheInt8::encrypt(clear_b, cks);

    let result = a.le(&b).if_then_else(&a, &b);
    let decrypted_result: i8 = result.decrypt(cks);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_a } else { clear_b }
    );

    let result = a.le(&b).if_then_else(&b, &a);
    let decrypted_result: i8 = result.decrypt(cks);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_b } else { clear_a }
    );
}

fn test_case_flip(client_key: &ClientKey) {
    let clear_a = rand::random::<i32>();
    let clear_b = rand::random::<i32>();

    let a = FheInt32::encrypt(clear_a, client_key);
    let b = FheInt32::encrypt(clear_b, client_key);

    let c = FheBool::encrypt(true, client_key);
    let (ra, rb) = c.flip(&a, &b);
    let decrypted_a: i32 = ra.decrypt(client_key);
    let decrypted_b: i32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_b, clear_a));

    let c = FheBool::encrypt(false, client_key);

    let (ra, rb) = c.flip(&a, &b);
    let decrypted_a: i32 = ra.decrypt(client_key);
    let decrypted_b: i32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_a, clear_b));
}

fn test_case_scalar_flip(client_key: &ClientKey) {
    let clear_a = rand::random::<i32>();
    let clear_b = rand::random::<i32>();

    let a = FheInt32::encrypt(clear_a, client_key);
    let b = FheInt32::encrypt(clear_b, client_key);

    let c = FheBool::encrypt(true, client_key);
    let (ra, rb) = c.flip(&a, clear_b);
    let decrypted_a: i32 = ra.decrypt(client_key);
    let decrypted_b: i32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_b, clear_a));

    let c = FheBool::encrypt(false, client_key);
    let (ra, rb) = c.flip(clear_a, &b);
    let decrypted_a: i32 = ra.decrypt(client_key);
    let decrypted_b: i32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_a, clear_b));
}

fn test_case_abs(cks: &ClientKey) {
    let mut rng = rand::rng();

    for clear in [rng.gen_range(i64::MIN..0), rng.gen_range(0..=i64::MAX)] {
        let a = FheInt64::encrypt(clear, cks);
        let abs_a = a.abs();
        let decrypted_result: i64 = abs_a.decrypt(cks);
        assert_eq!(decrypted_result, clear.abs());
    }
}

fn test_case_integer_compress_decompress(cks: &ClientKey) {
    let a = FheInt8::try_encrypt(-83i8, cks).unwrap();

    let clear: i8 = a.compress().decompress().decrypt(cks);

    assert_eq!(clear, -83i8);
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

fn test_case_min_max(cks: &ClientKey) {
    let mut rng = rand::rng();
    let a_val: i8 = rng.gen();
    let b_val: i8 = rng.gen();

    let a = FheInt8::encrypt(a_val, cks);
    let b = FheInt8::encrypt(b_val, cks);

    // Test by-reference operations
    let encrypted_min = a.min(&b);
    let encrypted_max = a.max(&b);
    let decrypted_min: i8 = encrypted_min.decrypt(cks);
    let decrypted_max: i8 = encrypted_max.decrypt(cks);
    assert_eq!(decrypted_min, a_val.min(b_val));
    assert_eq!(decrypted_max, a_val.max(b_val));

    // Test by-value operations
    let encrypted_min = a.min(b.clone());
    let encrypted_max = a.max(b);
    let decrypted_min: i8 = encrypted_min.decrypt(cks);
    let decrypted_max: i8 = encrypted_max.decrypt(cks);
    assert_eq!(decrypted_min, a_val.min(b_val));
    assert_eq!(decrypted_max, a_val.max(b_val));
}
