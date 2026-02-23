use crate::high_level_api::traits::BitSlice;
use crate::integer::U256;
use crate::prelude::*;
use crate::{ClientKey, FheBool, FheUint256, FheUint32, FheUint64, FheUint8, MatchValues};
use rand::{thread_rng, Rng};
use std::collections::HashMap;

mod cpu;
#[cfg(feature = "gpu")]
pub(crate) mod gpu;
#[cfg(feature = "hpu")]
mod hpu;

fn test_case_uint8_quickstart(client_key: &ClientKey) {
    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, client_key);
    let b = FheUint8::encrypt(clear_b, client_key);

    let result = a + b;

    let decrypted_result: u8 = result.decrypt(client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}

fn test_case_uint32_quickstart(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    let c = a + b;

    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    let clear_c = clear_a.wrapping_add(clear_b);
    let d = !c;
    let decrypted: u32 = d.decrypt(cks);
    assert_eq!(decrypted, !clear_c);
}

// TODO make generic
fn test_case_uint64_quickstart(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();

    let a = FheUint64::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint64::try_encrypt(clear_b, cks).unwrap();

    let c = a + b;

    let decrypted: u64 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

fn test_case_clone(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    let c = &a + &b;

    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    // We expect clones to be full clones and not some incremented ref-count
    let mut cloned_a = a.clone();

    let decrypted: u32 = cloned_a.decrypt(cks);
    assert_eq!(decrypted, clear_a);
    let decrypted: u32 = b.decrypt(cks);
    assert_eq!(decrypted, clear_b);

    let c = &cloned_a + &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    cloned_a += &b;

    let decrypted: u32 = cloned_a.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
    let decrypted: u32 = b.decrypt(cks);
    assert_eq!(decrypted, clear_b);
    let decrypted: u32 = a.decrypt(cks);
    assert_eq!(decrypted, clear_a);
    let decrypted: u32 = b.decrypt(cks);
    assert_eq!(decrypted, clear_b);
}

fn test_case_uint8_trivial(client_key: &ClientKey) {
    let a = FheUint8::try_encrypt_trivial(234u8).unwrap();

    let clear: u8 = a.decrypt(client_key);
    assert_eq!(clear, 234);
}

fn test_case_uint32_arith(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    let c = &a + &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    let c = &a - &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_sub(clear_b));

    let c = &a * &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_mul(clear_b));
}

fn test_case_uint32_arith_assign(cks: &ClientKey) {
    let mut rng = rand::rng();
    let mut clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let mut a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    a += &b;
    clear_a = clear_a.wrapping_add(clear_b);
    let decrypted: u32 = a.decrypt(cks);
    assert_eq!(decrypted, clear_a);

    a -= &b;
    let decrypted: u32 = a.decrypt(cks);
    clear_a = clear_a.wrapping_sub(clear_b);
    assert_eq!(decrypted, clear_a);

    a *= &b;
    let decrypted: u32 = a.decrypt(cks);
    clear_a = clear_a.wrapping_mul(clear_b);
    assert_eq!(decrypted, clear_a);
}

fn test_case_uint32_scalar_arith(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();

    let c = &a + clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));

    let c = &a - clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_sub(clear_b));

    let c = &a * clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_mul(clear_b));
}

fn test_case_uint32_scalar_arith_assign(cks: &ClientKey) {
    let mut rng = rand::rng();
    let mut clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let mut a = FheUint32::try_encrypt(clear_a, cks).unwrap();

    a += clear_b;
    clear_a = clear_a.wrapping_add(clear_b);
    let decrypted: u32 = a.decrypt(cks);
    assert_eq!(decrypted, clear_a);

    a -= clear_b;
    let decrypted: u32 = a.decrypt(cks);
    clear_a = clear_a.wrapping_sub(clear_b);
    assert_eq!(decrypted, clear_a);

    a *= clear_b;
    let decrypted: u32 = a.decrypt(cks);
    clear_a = clear_a.wrapping_mul(clear_b);
    assert_eq!(decrypted, clear_a);
}

fn test_case_uint256_trivial(client_key: &ClientKey) {
    let clear_a = U256::from(u128::MAX);
    let a = FheUint256::try_encrypt_trivial(clear_a).unwrap();
    let clear: U256 = a.decrypt(client_key);
    assert_eq!(clear, clear_a);
}

#[allow(clippy::eq_op)]
fn test_case_uint8_compare(client_key: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u8>();
    let clear_b = rng.gen::<u8>();

    let a = FheUint8::encrypt(clear_a, client_key);
    let b = FheUint8::encrypt(clear_b, client_key);

    let result = &a.eq(&b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a == clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.eq(&a);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a == clear_a;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ne(&b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a != clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ne(&a);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a != clear_a;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.le(&b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a <= clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.lt(&b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a < clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ge(&b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a >= clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.gt(&b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a > clear_b;
    assert_eq!(decrypted_result, clear_result);
}

#[allow(clippy::eq_op)]
fn test_case_uint8_compare_scalar(client_key: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u8>();
    let clear_b = rng.gen::<u8>();

    let a = FheUint8::encrypt(clear_a, client_key);

    let result = &a.eq(clear_b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a == clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.eq(clear_a);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a == clear_a;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ne(clear_b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a != clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ne(clear_a);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a != clear_a;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.le(clear_b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a <= clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.lt(clear_b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a < clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ge(clear_b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a >= clear_b;
    assert_eq!(decrypted_result, clear_result);

    let result = &a.gt(clear_b);
    let decrypted_result = result.decrypt(client_key);
    let clear_result = clear_a > clear_b;
    assert_eq!(decrypted_result, clear_result);
}

fn test_case_uint32_shift(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen_range(0u32..32u32);

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    // encrypted shifts
    #[allow(clippy::redundant_clone)]
    {
        let c = &a << &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a << clear_b);

        let c = &a >> &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a >> clear_b);

        let mut c = a.clone();
        c >>= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a >> clear_b);

        let mut c = a.clone();
        c <<= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a << clear_b);
    }

    // clear shifts
    if cfg!(not(feature = "hpu")) {
        let c = &a << clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a << clear_b);

        let c = &a >> clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a >> clear_b);

        let mut c = a.clone();
        c >>= clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a >> clear_b);

        let mut c = a;
        c <<= clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a << clear_b);
    } else {
        println!("WARN: HPU currently not support Shift by a scalar");
    }
}

fn test_case_uint32_bitwise(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    let c = &a | &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a | clear_b);

    let c = &a & &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a & clear_b);

    let c = &a ^ &b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a ^ clear_b);
}

fn test_case_uint32_bitwise_assign(cks: &ClientKey) {
    let mut rng = rand::rng();
    let mut clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let mut a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    a &= &b;
    clear_a &= clear_b;
    let decrypted: u32 = a.decrypt(cks);
    assert_eq!(decrypted, clear_a);

    a |= &b;
    let decrypted: u32 = a.decrypt(cks);
    clear_a |= clear_b;
    assert_eq!(decrypted, clear_a);

    a ^= &b;
    let decrypted: u32 = a.decrypt(cks);
    clear_a ^= clear_b;
    assert_eq!(decrypted, clear_a);
}

fn test_case_uint32_scalar_bitwise(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();

    let c = &a & clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a & clear_b);

    let c = &a ^ clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a ^ clear_b);

    let mut c = a.clone();
    c |= clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a | clear_b);

    let mut c = a.clone();
    c &= clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a & clear_b);

    let mut c = a;
    c ^= clear_b;
    let decrypted: u32 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a ^ clear_b);
}

fn test_case_uint32_rotate(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen_range(0u32..32u32);

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    // encrypted rotate
    #[allow(clippy::redundant_clone)]
    {
        let c = (&a).rotate_left(&b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));

        let c = (&a).rotate_right(&b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_right_assign(&b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_left_assign(&b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));
    }

    // clear rotate
    if cfg!(not(feature = "hpu")) {
        let c = (&a).rotate_left(clear_b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));

        let c = (&a).rotate_right(clear_b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a.clone();
        c.rotate_right_assign(clear_b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_right(clear_b));

        let mut c = a;
        c.rotate_left_assign(clear_b);
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a.rotate_left(clear_b));
    } else {
        println!("WARN: HPU currently not support Shift by a scalar");
    }
}

fn test_case_uint32_div_rem(cks: &ClientKey) {
    let mut rng = rand::rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen_range(1u32..=u32::MAX);

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    // encrypted div/rem
    {
        let c = &a / &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let c = &a % &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);

        let (q, r) = (&a).div_rem(&b);
        let decrypted_q: u32 = q.decrypt(cks);
        let decrypted_r: u32 = r.decrypt(cks);
        assert_eq!(decrypted_q, clear_a / clear_b);
        assert_eq!(decrypted_r, clear_a % clear_b);

        let mut c = a.clone();
        c /= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let mut c = a.clone();
        c %= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);
    }

    // clear div/rem
    {
        let c = &a / clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let c = &a % clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);

        let (q, r) = (&a).div_rem(clear_b);
        let decrypted_q: u32 = q.decrypt(cks);
        let decrypted_r: u32 = r.decrypt(cks);
        assert_eq!(decrypted_q, clear_a / clear_b);
        assert_eq!(decrypted_r, clear_a % clear_b);

        let mut c = a.clone();
        c /= clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a / clear_b);

        let mut c = a;
        c %= clear_b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a % clear_b);
    }
}

fn test_case_if_then_else(client_key: &ClientKey) {
    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, client_key);
    let b = FheUint8::encrypt(clear_b, client_key);

    let result = a.le(&b).if_then_else(&a, &b);
    let decrypted_result: u8 = result.decrypt(client_key);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_a } else { clear_b }
    );

    let result = a.le(&b).if_then_else(&b, &a);
    let decrypted_result: u8 = result.decrypt(client_key);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_b } else { clear_a }
    );
}

fn test_case_if_then_zero(client_key: &ClientKey) {
    let clear_a = 42u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, client_key);
    let b = FheUint8::encrypt(clear_b, client_key);

    let result = a.le(&b).if_then_zero(&a);
    let decrypted_result: u8 = result.decrypt(client_key);
    assert_eq!(
        decrypted_result,
        if clear_a <= clear_b { clear_a } else { 0 }
    );

    let result = a.ge(&b).if_then_zero(&a);
    let decrypted_result: u8 = result.decrypt(client_key);
    assert_eq!(
        decrypted_result,
        if clear_a >= clear_b { clear_a } else { 0 }
    );
}

fn test_case_flip(client_key: &ClientKey) {
    let clear_a = rand::random::<u32>();
    let clear_b = rand::random::<u32>();

    let a = FheUint32::encrypt(clear_a, client_key);
    let b = FheUint32::encrypt(clear_b, client_key);

    let c = FheBool::encrypt(true, client_key);
    let (ra, rb) = c.flip(&a, &b);
    let decrypted_a: u32 = ra.decrypt(client_key);
    let decrypted_b: u32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_b, clear_a));

    let c = FheBool::encrypt(false, client_key);

    let (ra, rb) = c.flip(&a, &b);
    let decrypted_a: u32 = ra.decrypt(client_key);
    let decrypted_b: u32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_a, clear_b));
}

fn test_case_scalar_flip(client_key: &ClientKey) {
    let clear_a = rand::random::<u32>();
    let clear_b = rand::random::<u32>();

    let a = FheUint32::encrypt(clear_a, client_key);
    let b = FheUint32::encrypt(clear_b, client_key);

    let c = FheBool::encrypt(true, client_key);
    let (ra, rb) = c.flip(&a, clear_b);
    let decrypted_a: u32 = ra.decrypt(client_key);
    let decrypted_b: u32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_b, clear_a));

    let c = FheBool::encrypt(false, client_key);
    let (ra, rb) = c.flip(clear_a, &b);
    let decrypted_a: u32 = ra.decrypt(client_key);
    let decrypted_b: u32 = rb.decrypt(client_key);
    assert_eq!((decrypted_a, decrypted_b), (clear_a, clear_b));
}

fn test_case_leading_trailing_zeros_ones(cks: &ClientKey) {
    let mut rng = rand::rng();
    for _ in 0..5 {
        let clear_a = rng.gen::<u32>();
        let a = FheUint32::try_encrypt(clear_a, cks).unwrap();

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
    let mut rng = rand::rng();
    for _ in 0..5 {
        let clear_a = rng.gen_range(1..=u32::MAX);
        let a = FheUint32::try_encrypt(clear_a, cks).unwrap();

        let ilog2: u32 = a.ilog2().decrypt(cks);
        assert_eq!(ilog2, clear_a.ilog2());

        #[cfg(not(feature = "hpu"))]
        {
            let (ilog2, is_ok) = a.checked_ilog2();
            let ilog2: u32 = ilog2.decrypt(cks);
            let is_ok = is_ok.decrypt(cks);
            assert!(is_ok);
            assert_eq!(ilog2, clear_a.ilog2());
        }
    }

    #[cfg(not(feature = "hpu"))]
    {
        let a = FheUint32::try_encrypt(0u32, cks).unwrap();

        let (_ilog2, is_ok) = a.checked_ilog2();
        let is_ok = is_ok.decrypt(cks);
        assert!(!is_ok);
    }
}

fn test_case_bitslice(cks: &ClientKey) {
    let mut rng = rand::rng();
    for _ in 0..5 {
        // clear is a u64 so that `clear % (1 << 32)` does not overflow
        let clear = rng.gen::<u32>() as u64;

        let range_a = rng.gen_range(0..33);
        let range_b = rng.gen_range(0..33);

        let (range_start, range_end) = if range_a < range_b {
            (range_a, range_b)
        } else {
            (range_b, range_a)
        };

        let ct = FheUint32::try_encrypt(clear, cks).unwrap();

        {
            let slice = (&ct).bitslice(range_start..range_end).unwrap();
            let slice: u64 = slice.decrypt(cks);

            assert_eq!(slice, (clear % (1 << range_end)) >> range_start)
        }

        // Check with a slice that takes the last bits of the input
        {
            let slice = (&ct).bitslice(range_start..).unwrap();
            let slice: u64 = slice.decrypt(cks);

            assert_eq!(slice, (clear % (1 << 32)) >> range_start)
        }

        // Check with an invalid slice
        {
            let slice_res = ct.bitslice(range_start..33);
            assert!(slice_res.is_err())
        }
    }
}

fn test_case_sum(client_key: &ClientKey) {
    let mut rng = thread_rng();

    for _ in 0..5 {
        let num_ct = rng.gen_range(5..=10);
        let clears = (0..num_ct).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();

        let expected_result = clears.iter().copied().sum::<u32>();

        let ciphertext = clears
            .iter()
            .copied()
            .map(|clear| FheUint32::encrypt(clear, client_key))
            .collect::<Vec<_>>();

        let sum: u32 = ciphertext.iter().sum::<FheUint32>().decrypt(client_key);
        assert_eq!(sum, expected_result);

        let sum: u32 = ciphertext
            .into_iter()
            .sum::<FheUint32>()
            .decrypt(client_key);
        assert_eq!(sum, expected_result);
    }
}

fn test_case_is_even_is_odd(cks: &ClientKey) {
    let mut rng = rand::rng();
    // This operation is cheap
    for _ in 0..50 {
        let clear_a = rng.gen_range(1..=u32::MAX);
        let a = FheUint32::try_encrypt(clear_a, cks).unwrap();

        assert_eq!(
            a.is_even().decrypt(cks),
            (clear_a % 2) == 0,
            "Invalid is_even result for {clear_a}"
        );
        assert_eq!(
            a.is_odd().decrypt(cks),
            (clear_a % 2) == 1,
            "Invalid is_odd result for {clear_a}"
        );

        let clear_a = rng.gen_range(i32::MIN..=i32::MAX);
        let a = crate::FheInt32::try_encrypt(clear_a, cks).unwrap();
        assert_eq!(
            a.is_even().decrypt(cks),
            (clear_a % 2) == 0,
            "Invalid is_even result for {clear_a}"
        );
        // Use != 0 because if clear_a < 0, the returned mod is also < 0
        assert_eq!(
            a.is_odd().decrypt(cks),
            (clear_a % 2) != 0,
            "Invalid is_odd result for {clear_a}"
        );
    }
}

fn test_case_min_max(cks: &ClientKey) {
    let mut rng = rand::rng();
    let a_val: u8 = rng.gen();
    let b_val: u8 = rng.gen();

    let a = FheUint8::encrypt(a_val, cks);
    let b = FheUint8::encrypt(b_val, cks);

    // Test by-reference operations
    let encrypted_min = a.min(&b);
    let encrypted_max = a.max(&b);
    let decrypted_min: u8 = encrypted_min.decrypt(cks);
    let decrypted_max: u8 = encrypted_max.decrypt(cks);
    assert_eq!(decrypted_min, a_val.min(b_val));
    assert_eq!(decrypted_max, a_val.max(b_val));

    // Test by-value operations
    let encrypted_min = a.min(b.clone());
    let encrypted_max = a.max(b);
    let decrypted_min: u8 = encrypted_min.decrypt(cks);
    let decrypted_max: u8 = encrypted_max.decrypt(cks);
    assert_eq!(decrypted_min, a_val.min(b_val));
    assert_eq!(decrypted_max, a_val.max(b_val));
}

fn test_case_match_value(cks: &ClientKey) {
    let mut rng = thread_rng();

    for _ in 0..5 {
        let clear_in = rng.gen::<u8>();
        let ct = FheUint8::encrypt(clear_in, cks);

        let should_match = rng.gen_bool(0.5);

        let mut map: HashMap<u8, u8> = HashMap::new();
        let mut pairs = Vec::new();

        let expected_value = if should_match {
            let val = rng.gen::<u8>();
            map.insert(clear_in, val);
            pairs.push((clear_in, val));
            val
        } else {
            0u8
        };

        let num_entries = rng.gen_range(1..10);
        for _ in 0..num_entries {
            let mut k = rng.gen::<u8>();
            while !should_match && k == clear_in {
                k = rng.gen::<u8>();
            }
            if let std::collections::hash_map::Entry::Vacant(e) = map.entry(k) {
                let v = rng.gen::<u8>();
                e.insert(v);
                pairs.push((k, v));
            }
        }

        let matches = MatchValues::new(pairs).unwrap();

        let (result, found): (FheUint8, _) = ct.match_value(&matches).unwrap();

        let dec_result: u8 = result.decrypt(cks);
        let dec_found = found.decrypt(cks);

        assert_eq!(
            dec_found, should_match,
            "Mismatch on 'found' boolean flag for input {clear_in}"
        );

        if should_match {
            assert_eq!(
                dec_result, expected_value,
                "Mismatch on result value for input {clear_in}"
            );
        } else {
            assert_eq!(dec_result, 0, "Result should be 0 when no match is found");
        }
    }
}

fn test_case_match_value_or(cks: &ClientKey) {
    let mut rng = thread_rng();

    for _ in 0..5 {
        let clear_in = rng.gen::<u8>();
        let ct = FheUint8::encrypt(clear_in, cks);
        let clear_or_value = rng.gen::<u8>();

        let should_match = rng.gen_bool(0.5);

        let mut map: HashMap<u8, u8> = HashMap::new();
        let mut pairs = Vec::new();

        let expected_value = if should_match {
            let val = rng.gen::<u8>();
            map.insert(clear_in, val);
            pairs.push((clear_in, val));
            val
        } else {
            clear_or_value
        };

        let num_entries = rng.gen_range(1..10);
        for _ in 0..num_entries {
            let mut k = rng.gen::<u8>();
            while !should_match && k == clear_in {
                k = rng.gen::<u8>();
            }

            if let std::collections::hash_map::Entry::Vacant(e) = map.entry(k) {
                let v = rng.gen::<u8>();
                e.insert(v);
                pairs.push((k, v));
            }
        }

        let matches = MatchValues::new(pairs).unwrap();

        let result: FheUint8 = ct.match_value_or(&matches, clear_or_value).unwrap();

        let dec_result: u8 = result.decrypt(cks);

        assert_eq!(
            dec_result, expected_value,
            "Mismatch on result value for input {clear_in}. Should match: {should_match}"
        );
    }
}
