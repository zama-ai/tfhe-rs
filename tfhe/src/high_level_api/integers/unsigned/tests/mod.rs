use crate::integer::U256;
use crate::prelude::*;
use crate::{ClientKey, FheUint256, FheUint32, FheUint64, FheUint8};
use rand::{thread_rng, Rng};

mod cpu;
#[cfg(feature = "gpu")]
mod gpu;

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
    let mut rng = rand::thread_rng();
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
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();

    let a = FheUint64::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint64::try_encrypt(clear_b, cks).unwrap();

    let c = a + b;

    let decrypted: u64 = c.decrypt(cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

fn test_case_uint8_trivial(client_key: &ClientKey) {
    let a = FheUint8::try_encrypt_trivial(234u8).unwrap();

    let clear: u8 = a.decrypt(client_key);
    assert_eq!(clear, 234);
}

fn test_case_uint256_trivial(client_key: &ClientKey) {
    let clear_a = U256::from(u128::MAX);
    let a = FheUint256::try_encrypt_trivial(clear_a).unwrap();
    let clear: U256 = a.decrypt(client_key);
    assert_eq!(clear, clear_a);
}

#[allow(clippy::eq_op)]
fn test_case_uint8_compare(client_key: &ClientKey) {
    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, client_key);
    let b = FheUint8::encrypt(clear_b, client_key);

    // Test comparing encrypted with encrypted
    {
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

    // Test comparing encrypted with clear
    {
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
}

fn test_case_uint32_shift(cks: &ClientKey) {
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen_range(0u32..32u32);

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    // encrypted shifts
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
    {
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
    }
}

fn test_case_uint32_bitwise(cks: &ClientKey) {
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    // encrypted bitwise
    {
        let c = &a | &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let c = &a & &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let c = &a ^ &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a ^ clear_b);

        let mut c = a.clone();
        c |= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

        let mut c = a.clone();
        c &= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a & clear_b);

        let mut c = a.clone();
        c ^= &b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a ^ clear_b);
    }

    // clear bitwise
    {
        let c = &a | b;
        let decrypted: u32 = c.decrypt(cks);
        assert_eq!(decrypted, clear_a | clear_b);

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
}

fn test_case_uint32_rotate(cks: &ClientKey) {
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen_range(0u32..32u32);

    let a = FheUint32::try_encrypt(clear_a, cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, cks).unwrap();

    // encrypted rotate
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
    {
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
    }
}

fn test_case_uint32_div_rem(cks: &ClientKey) {
    let mut rng = rand::thread_rng();
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

fn test_case_leading_trailing_zeros_ones(cks: &ClientKey) {
    let mut rng = rand::thread_rng();
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
    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let clear_a = rng.gen_range(1..=u32::MAX);
        let a = FheUint32::try_encrypt(clear_a, cks).unwrap();

        let ilog2: u32 = a.ilog2().decrypt(cks);
        assert_eq!(ilog2, clear_a.ilog2());

        let (ilog2, is_ok) = a.checked_ilog2();
        let ilog2: u32 = ilog2.decrypt(cks);
        let is_ok = is_ok.decrypt(cks);
        assert!(is_ok);
        assert_eq!(ilog2, clear_a.ilog2());
    }

    {
        let a = FheUint32::try_encrypt(0u32, cks).unwrap();

        let (_ilog2, is_ok) = a.checked_ilog2();
        let is_ok = is_ok.decrypt(cks);
        assert!(!is_ok);
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
