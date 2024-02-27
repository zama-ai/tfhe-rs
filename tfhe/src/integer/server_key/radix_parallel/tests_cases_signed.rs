use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{NB_CTXT, NB_TESTS_SMALLER};
use crate::integer::{IntegerKeyKind, RadixClientKey, SignedRadixCiphertext};
use crate::shortint::PBSParameters;
use itertools::izip;
use rand::prelude::ThreadRng;
use rand::Rng;
use std::sync::Arc;

//================================================================================
//     Helper functions
//================================================================================

pub(crate) fn signed_add_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    signed_overflowing_add_under_modulus(lhs, rhs, modulus).0
}

// Adds two signed number modulo the given modulus
//
// This is to 'simulate' i8, i16, ixy using i64 integers
//
// lhs and rhs must be in [-modulus..modulus[
pub(crate) fn signed_overflowing_add_under_modulus(
    lhs: i64,
    rhs: i64,
    modulus: i64,
) -> (i64, bool) {
    assert!(modulus > 0);
    assert!((-modulus..modulus).contains(&lhs));

    // The code below requires rhs and lhs to be in range -modulus..modulus
    // in scalar tests, rhs may exceed modulus
    // so we truncate it (is the fhe ops does)
    let (mut res, mut overflowed) = if (-modulus..modulus).contains(&rhs) {
        (lhs + rhs, false)
    } else {
        // 2*modulus to get all the bits
        (lhs + (rhs % (2 * modulus)), true)
    };

    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
        overflowed = true;
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
        overflowed = true;
    }
    (res, overflowed)
}

pub(crate) fn signed_neg_under_modulus(lhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let mut res = -lhs;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }
    res
}

// Subs two signed number modulo the given modulus
//
// This is to 'simulate' i8, i16, ixy using i64 integers
//
// lhs and rhs must be in [-modulus..modulus[
pub(crate) fn signed_sub_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    signed_overflowing_sub_under_modulus(lhs, rhs, modulus).0
}

pub(crate) fn signed_overflowing_sub_under_modulus(
    lhs: i64,
    rhs: i64,
    modulus: i64,
) -> (i64, bool) {
    // Technically we should be able to call overflowing_add_under_modulus(lhs, -rhs, ...)
    // but due to -rhs being a 'special case' when rhs == -modulus, we have to
    // so the impl here
    assert!(modulus > 0);
    assert!((-modulus..modulus).contains(&lhs));

    // The code below requires rhs and lhs to be in range -modulus..modulus
    // in scalar tests, rhs may exceed modulus
    // so we truncate it (is the fhe ops does)
    let (mut res, mut overflowed) = if (-modulus..modulus).contains(&rhs) {
        (lhs - rhs, false)
    } else {
        // 2*modulus to get all the bits
        (lhs - (rhs % (2 * modulus)), true)
    };

    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
        overflowed = true;
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
        overflowed = true;
    }
    (res, overflowed)
}

pub(crate) fn signed_mul_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    overflowing_mul_under_modulus(lhs, rhs, modulus).0
}

pub(crate) fn overflowing_mul_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, bool) {
    let (mut res, mut overflowed) = lhs.overflowing_mul(rhs);
    overflowed |= res < -modulus || res >= modulus;
    res %= modulus * 2;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }

    (res, overflowed)
}

pub(crate) fn absolute_value_under_modulus(lhs: i64, modulus: i64) -> i64 {
    if lhs < 0 {
        signed_neg_under_modulus(lhs, modulus)
    } else {
        lhs
    }
}

pub(crate) fn signed_left_shift_under_modulus(lhs: i64, rhs: u32, modulus: i64) -> i64 {
    signed_mul_under_modulus(lhs, 1 << rhs, modulus)
}

pub(crate) fn signed_right_shift_under_modulus(lhs: i64, rhs: u32, _modulus: i64) -> i64 {
    lhs >> rhs
}

pub(crate) fn signed_div_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    // in signed integers, -modulus can be represented, but +modulus cannot
    // thus, when dividing: -128 / -1 = 128 the results overflows to -128
    assert!(modulus > 0);
    let mut res = lhs / rhs;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }
    res
}

pub(crate) fn signed_rem_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let q = signed_div_under_modulus(lhs, rhs, modulus);
    let q_times_rhs = signed_mul_under_modulus(q, rhs, modulus);
    signed_sub_under_modulus(lhs, q_times_rhs, modulus)
}

pub(crate) fn signed_div_rem_floor_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, i64) {
    let mut q = signed_div_under_modulus(lhs, rhs, modulus);
    let mut r = signed_rem_under_modulus(lhs, rhs, modulus);

    if (r != 0) && ((r < 0) != (rhs < 0)) {
        q = signed_sub_under_modulus(q, 1, modulus);
        r = signed_add_under_modulus(r, rhs, modulus);
    }

    (q, r)
}

/// helper function to do a rotate left when the type used to store
/// the value is bigger than the actual intended bit size
pub(crate) fn rotate_left_helper(value: i64, n: u32, actual_bit_size: u32) -> i64 {
    // We start with:
    // [0000000000000|xxxx]
    // 64           b    0
    //
    // rotated will be
    // [0000000000xx|xx00]
    // 64           b    0
    let n = n % actual_bit_size;
    let mask = 1i64.wrapping_shl(actual_bit_size) - 1;
    let shifted_mask = mask.wrapping_shl(n) & !mask;

    // Value maybe be negative and so, have its msb
    // set to one, so use mask to only keep the part that interest
    // us
    let rotated = (value & mask).rotate_left(n);

    let tmp = (rotated & mask) | ((rotated & shifted_mask) >> actual_bit_size);
    // If the sign bit after rotation is one,
    // then all bits above it needs to be one
    let new_sign_bit = (tmp >> (actual_bit_size - 1)) & 1;
    let mut pad = -new_sign_bit;
    pad <<= actual_bit_size; // only bits above actual_bit_size should be set

    pad | tmp
}

/// helper function to do a rotate right when the type used to store
/// the value is bigger than the actual intended bit size
pub(crate) fn rotate_right_helper(value: i64, n: u32, actual_bit_size: u32) -> i64 {
    // We start with:
    // [yyyyyyyyyyyy|xxxx]
    // 64           b    0
    // where xs are bits that we are interested in
    // and ys are either 0 or 1 depending on if value is positive
    //
    // mask: [yyyyyyyyyyyy|mmmm]
    // shifted_ mask: [mmyyyyyyyyyy|0000]
    //
    // rotated will be
    // [xxyyyyyyyyyy|00xx]
    // 64           b    0
    //
    // To get the 'cycled' bits where they should be,
    // we get them using a mask then shift
    let n = n % actual_bit_size;
    let mask = 1i64.wrapping_shl(actual_bit_size) - 1;
    // shifted mask only needs the bits that cycled
    let shifted_mask = mask.rotate_right(n) & !mask;

    // Value maybe be negative and so, have its msb
    // set to one, so use mask to only keep the part that interest
    // us
    let rotated = (value & mask).rotate_right(n);

    let tmp = (rotated & mask) | ((rotated & shifted_mask) >> (u64::BITS - actual_bit_size));
    // If the sign bit after rotation is one,
    // then all bits above it needs to be one
    let new_sign_bit = (tmp >> (actual_bit_size - 1)) & 1;
    let mut pad = -new_sign_bit;
    pad <<= actual_bit_size; // only bits above actual_bit_size should be set

    pad | tmp
}

/// Returns an array filled with random values such that:
/// - the first half contains values in [0..modulus[
/// - the second half contains values in [-modulus..0]
pub(crate) fn random_signed_value_under_modulus<const N: usize>(
    rng: &mut rand::prelude::ThreadRng,
    modulus: i64,
) -> [i64; N] {
    assert!(modulus > 0);

    let mut values = [0i64; N];

    for value in &mut values[..N / 2] {
        *value = rng.gen_range(0..modulus);
    }

    for value in &mut values[N / 2..] {
        *value = rng.gen_range(-modulus..=0);
    }

    values
}

/// Returns an array filled with random values such that:
/// - the first half contains values in ]0..modulus[
/// - the second half contains values in [-modulus..0[
pub(crate) fn random_non_zero_signed_value_under_modulus<const N: usize>(
    rng: &mut rand::prelude::ThreadRng,
    modulus: i64,
) -> [i64; N] {
    assert!(modulus > 0);

    let mut values = [0i64; N];

    for value in &mut values[..N / 2] {
        *value = rng.gen_range(1..modulus);
    }

    for value in &mut values[N / 2..] {
        *value = rng.gen_range(-modulus..0);
    }

    values
}

/// Returns an iterator that yields pairs of i64 values in range `-modulus..modulus`
/// such that there is at least one pair of (P, P), (P, N), (N, N) (N, P)
/// where P means value >=0 and N means <= 0
pub(crate) fn create_iterator_of_signed_random_pairs<const N: usize>(
    rng: &mut rand::prelude::ThreadRng,
    modulus: i64,
) -> impl Iterator<Item = (i64, i64)> {
    assert!(N >= 4, "N must be at least 4 to uphold the guarantee");
    let mut lhs_values = [0i64; N];
    let mut rhs_values = [0i64; N];

    lhs_values[0] = rng.gen_range(0..modulus);
    rhs_values[0] = rng.gen_range(0..modulus);

    lhs_values[1] = rng.gen_range(0..modulus);
    rhs_values[1] = rng.gen_range(-modulus..=0);

    lhs_values[2] = rng.gen_range(-modulus..=0);
    rhs_values[2] = rng.gen_range(-modulus..=0);

    lhs_values[3] = rng.gen_range(-modulus..=0);
    rhs_values[3] = rng.gen_range(0..modulus);

    for i in 4..N {
        lhs_values[i] = rng.gen_range(-modulus..modulus);
        rhs_values[i] = rng.gen_range(-modulus..modulus);
    }

    izip!(lhs_values, rhs_values)
}

pub(crate) fn random_non_zero_value(rng: &mut ThreadRng, modulus: i64) -> i64 {
    loop {
        let value = rng.gen::<i64>() % modulus;
        if value != 0 {
            break value;
        }
    }
}

// Signed tests

pub(crate) fn signed_unchecked_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, -1, modulus - 1),
        (modulus - 1, 1, -modulus),
        (-modulus, -2, modulus - 2),
        (modulus - 2, 2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);
        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<
        { crate::integer::server_key::radix_parallel::tests_signed::NB_TESTS_UNCHECKED },
    >(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let tmp_ct = executor.execute((&ctxt_0, &ctxt_1));
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        clear = signed_add_under_modulus(clear_0, clear_1, modulus);

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        // add multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = executor.execute((&ct_res, &ctxt_0));
            assert!(ct_res.block_carries_are_empty());
            clear = signed_add_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}
