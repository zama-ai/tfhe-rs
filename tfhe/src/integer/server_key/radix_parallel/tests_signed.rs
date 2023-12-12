use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::sub::SignedOperation;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::parameters::*;
use itertools::{iproduct, izip};
use paste::paste;
use rand::rngs::ThreadRng;
use rand::Rng;

/// Number of loop iteration within randomized tests
const NB_TESTS: usize = 30;

const NB_TESTS_SMALLER: usize = 10;
const NB_CTXT: usize = 4;

macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
        });
    };
}

//================================================================================
//     Helper functions
//================================================================================

fn signed_add_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    signed_overflowing_add_under_modulus(lhs, rhs, modulus).0
}

// Adds two signed number modulo the given modulus
//
// This is to 'simulate' i8, i16, ixy using i64 integers
//
// lhs and rhs must be in [-modulus..modulus[
fn signed_overflowing_add_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, bool) {
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

fn signed_neg_under_modulus(lhs: i64, modulus: i64) -> i64 {
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
fn signed_sub_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    signed_overflowing_sub_under_modulus(lhs, rhs, modulus).0
}

fn signed_overflowing_sub_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, bool) {
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

fn signed_mul_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let mut res = lhs * rhs;
    res %= modulus * 2;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }
    res
}

fn absolute_value_under_modulus(lhs: i64, modulus: i64) -> i64 {
    if lhs < 0 {
        signed_neg_under_modulus(lhs, modulus)
    } else {
        lhs
    }
}

fn signed_left_shift_under_modulus(lhs: i64, rhs: u32, modulus: i64) -> i64 {
    signed_mul_under_modulus(lhs, 1 << rhs, modulus)
}

fn signed_right_shift_under_modulus(lhs: i64, rhs: u32, _modulus: i64) -> i64 {
    lhs >> rhs
}

fn signed_div_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
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

fn signed_rem_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let q = signed_div_under_modulus(lhs, rhs, modulus);
    let q_times_rhs = signed_mul_under_modulus(q, rhs, modulus);
    signed_sub_under_modulus(lhs, q_times_rhs, modulus)
}

fn signed_div_rem_floor_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, i64) {
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
fn rotate_left_helper(value: i64, n: u32, actual_bit_size: u32) -> i64 {
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
fn rotate_right_helper(value: i64, n: u32, actual_bit_size: u32) -> i64 {
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
fn random_signed_value_under_modulus<const N: usize>(
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
fn random_non_zero_signed_value_under_modulus<const N: usize>(
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
fn create_iterator_of_signed_random_pairs<const N: usize>(
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

fn random_non_zero_value(rng: &mut ThreadRng, modulus: i64) -> i64 {
    loop {
        let value = rng.gen::<i64>() % modulus;
        if value != 0 {
            break value;
        }
    }
}

//================================================================================
//     Encrypt/Derypt Tests
//================================================================================

create_parametrized_test!(integer_signed_encrypt_decrypt);
create_parametrized_test!(integer_signed_encrypt_decrypt_128_bits);

fn integer_signed_encrypt_decrypt_128_bits(param: impl Into<PBSParameters>) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();
    let num_block =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log(2.0)).ceil() as usize;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i128>();

        let ct = cks.encrypt_signed_radix(clear, num_block);

        let dec: i128 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);
    }
}

fn integer_signed_encrypt_decrypt(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen_range(i64::MIN..=0) % modulus;

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);

        let trivial_ct = sks.create_trivial_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&trivial_ct);
        assert_eq!(clear, dec);
    }

    for _ in 0..NB_TESTS {
        let clear = rng.gen_range(0..=i64::MAX) % modulus;

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);

        let trivial_ct = sks.create_trivial_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&trivial_ct);
        assert_eq!(clear, dec);
    }
}

//================================================================================
//     Unchecked Tests
//================================================================================

create_parametrized_test!(integer_signed_unchecked_add);
create_parametrized_test!(integer_signed_unchecked_overflowing_add);
create_parametrized_test!(integer_signed_unchecked_overflowing_add_parallelized {
    // Requires 4 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_unchecked_neg);
create_parametrized_test!(integer_signed_unchecked_sub);
create_parametrized_test!(integer_signed_unchecked_overflowing_sub);
create_parametrized_test!(integer_signed_unchecked_overflowing_sub_parallelized {
    // Requires 4 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_unchecked_mul);
create_parametrized_test!(integer_signed_unchecked_bitand);
create_parametrized_test!(integer_signed_unchecked_bitor);
create_parametrized_test!(integer_signed_unchecked_bitxor);
create_parametrized_test!(integer_signed_unchecked_left_shift {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

create_parametrized_test!(integer_signed_unchecked_right_shift {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

create_parametrized_test!(integer_signed_unchecked_rotate_right {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

create_parametrized_test!(integer_signed_unchecked_rotate_left {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

create_parametrized_test!(integer_signed_unchecked_div_rem {
    // Does not support 1_1
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_unchecked_div_rem_floor {
    // Does not support 1_1
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_unchecked_absolute_value);

fn integer_signed_unchecked_add(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, -1, modulus - 1),
        (modulus - 1, 1, -modulus),
        (-modulus, -2, modulus - 2),
        (modulus - 2, 2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);
        let ct_res = sks.unchecked_add_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_add_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn signed_unchecked_overflowing_add_test_case<P, F>(param: P, signed_overflowing_add: F)
where
    P: Into<PBSParameters>,
    F: for<'a> Fn(
        &'a ServerKey,
        &'a SignedRadixCiphertext,
        &'a SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock),
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    let hardcoded_values = [
        (-modulus, -1),
        (modulus - 1, 1),
        (-1, -modulus),
        (1, modulus - 1),
    ];
    for (clear_0, clear_1) in hardcoded_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) =
            sks.signed_overflowing_scalar_add_parallelized(&ctxt_0, clear_1);
        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = signed_overflowing_add(&sks, &ctxt_0, &ctxt_1);
        let (tmp_ct, tmp_o) = signed_overflowing_add(&sks, &ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
    }

    // Test with trivial inputs, as it was bugged at some point
    let values = [
        (rng.gen::<i64>() % modulus, 0i64),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
    ];
    for (clear_0, clear_1) in values {
        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) = signed_overflowing_add(&sks, &a, &b);

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
    }
}

fn integer_signed_unchecked_overflowing_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // Calls the low level function like this so we are sure the sequential version is tested
    let func = |sks: &ServerKey,
                lhs: &SignedRadixCiphertext,
                rhs: &SignedRadixCiphertext|
     -> (SignedRadixCiphertext, BooleanBlock) {
        sks.unchecked_signed_overflowing_add_or_sub(lhs, rhs, SignedOperation::Addition)
    };
    signed_unchecked_overflowing_add_test_case(param, func);
}

fn integer_signed_unchecked_overflowing_add_parallelized<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // Calls the low level function like this so we are sure the parallel version is tested
    //
    // However this only supports param X_X where X >= 2
    let func = |sks: &ServerKey,
                lhs: &SignedRadixCiphertext,
                rhs: &SignedRadixCiphertext|
     -> (SignedRadixCiphertext, BooleanBlock) {
        sks.unchecked_signed_overflowing_add_or_sub_parallelized_impl(
            lhs,
            rhs,
            SignedOperation::Addition,
        )
    };
    signed_unchecked_overflowing_add_test_case(param, func);
}

// There is no unchecked_neg_parallelized,
// but test the non parallel version here anyway
// as it is used in other parallel ops (e.g: sub)
fn integer_signed_unchecked_neg(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // -modulus is a special case, its negation cannot be
    // represented. rust by default returns -modulus
    // (which is what two complement result in)
    {
        let clear = -modulus;
        let ctxt = cks.encrypt_signed_radix(clear, NB_CTXT);

        let ct_res = sks.neg_parallelized(&ctxt);

        let dec: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_result = signed_neg_under_modulus(clear, modulus);

        assert_eq!(clear_result, dec);
        assert_eq!(clear_result, -modulus);
    }

    for (clear_0, _) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus) {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_neg(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_neg_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }

    // negation of trivial 0
    {
        let ctxt_0 = sks.create_trivial_radix(0i64, NB_CTXT);
        let ct_res = sks.unchecked_neg(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(0, dec_res);
    }
}

fn integer_signed_unchecked_sub(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, 1, modulus - 1),
        (modulus - 1, -1, -modulus),
        (-modulus, 2, modulus - 2),
        (modulus - 2, -2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);
        let ct_res = sks.unchecked_sub(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_sub(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn signed_unchecked_overflowing_sub_test_case<P, F>(param: P, signed_overflowing_sub: F)
where
    P: Into<PBSParameters>,
    F: for<'a> Fn(
        &'a ServerKey,
        &'a SignedRadixCiphertext,
        &'a SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock),
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let hardcoded_values = [
        (-modulus, 1),
        (modulus - 1, -1),
        (1, -modulus),
        (-1, modulus - 1),
    ];
    for (clear_0, clear_1) in hardcoded_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) =
            sks.signed_overflowing_scalar_sub_parallelized(&ctxt_0, clear_1);
        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = signed_overflowing_sub(&sks, &ctxt_0, &ctxt_1);
        let (tmp_ct, tmp_o) = signed_overflowing_sub(&sks, &ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
    }

    // Test with trivial inputs, as it was bugged at some point
    let values = [
        (rng.gen::<i64>() % modulus, 0i64),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
        (rng.gen::<i64>() % modulus, rng.gen::<i64>() % modulus),
    ];
    for (clear_0, clear_1) in values {
        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) = signed_overflowing_sub(&sks, &a, &b);

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
    }
}

fn integer_signed_unchecked_overflowing_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    signed_unchecked_overflowing_sub_test_case(param, ServerKey::unchecked_signed_overflowing_sub);
}

fn integer_signed_unchecked_overflowing_sub_parallelized<P>(param: P)
where
    P: Into<PBSParameters>,
{
    // Call _impl so we are sure the parallel version is tested
    //
    // However this only supports param X_X where X >= 4
    signed_unchecked_overflowing_sub_test_case(
        param,
        ServerKey::unchecked_signed_overflowing_sub_parallelized_impl,
    );
}

fn integer_signed_unchecked_mul(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_mul_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_mul_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_bitand(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_bitand_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_bitor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_bitor_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_bitxor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for (clear_0, clear_1) in create_iterator_of_signed_random_pairs::<NB_TESTS>(&mut rng, modulus)
    {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.unchecked_bitxor_parallelized(&ctxt_0, &ctxt_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_absolute_value(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // For signed integers, the range of value is [-modulus..modulus[
    // e.g.: for i8, the range is [-128..128[ <=> [-128..127]
    // which means -modulus cannot be represented.
    //
    // In Rust, .abs() / .wrapping_abs() returns MIN (-modulus)
    // https://doc.rust-lang.org/std/primitive.i8.html#method.wrapping_abs
    //
    // Here we test we have same behaviour
    //
    // (Conveniently, when using Two's complement, casting the result of abs to
    // an unsigned to will give correct value for -modulus
    // e.g.:(-128i8).wrapping_abs() as u8 == 128
    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.unchecked_abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_left_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(clear_res, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_left_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(clear_res, dec_res);
        }
    }
}

fn integer_signed_unchecked_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_right_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(clear_res, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_right_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shr manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(clear_res, dec_res);
        }
    }
}

fn integer_signed_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            println!("{clear} << {clear_shift}");
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_left_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_left_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_left_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_right_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let shift = cks.encrypt(clear_shift as u64);
            let ct_res = sks.unchecked_rotate_right_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = nb_bits;
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            let expected = rotate_right_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_div_rem(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // Test case of division by 0
    // This is mainly to show we know the behaviour of division by 0
    // using the current algorithm
    for clear_0 in [0i64, rng.gen::<i64>() % modulus] {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(0, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);

        assert_eq!(r, clear_0);
        assert_eq!(q, if clear_0 >= 0 { -1 } else { 1 });
    }

    // Div is the slowest operation
    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = loop {
            let value = rng.gen::<i64>() % modulus;
            if value != 0 {
                break value;
            }
        };

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let expected_q = signed_div_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(
            q, expected_q,
            "Invalid division result, for {clear_0} / {clear_1} \
            expected quotient: {expected_q} got: {q}"
        );
        let expected_r = signed_rem_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(
            r, expected_r,
            "Invalid remainder result, for {clear_0} % {clear_1} \
            expected quotient: {expected_r} got: {r}"
        );
    }
}

fn integer_signed_unchecked_div_rem_floor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    if modulus > 8 {
        // Some hard coded test for flooring div
        // For example, truncating_div(-7, 3) would give q = -2 and r = -1
        // truncating div is the default in rust (and many other languages)
        // Python does use a flooring div, so you can try these values in you local
        // interpreter.
        let values = [
            (-8, 3, -3, 1),
            (8, -3, -3, -1),
            (7, 3, 2, 1),
            (-7, 3, -3, 2),
            (7, -3, -3, -2),
            (-7, -3, 2, -1),
        ];
        for (clear_0, clear_1, expected_q, expected_r) in values {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
            let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_div_rem_floor_parallelized(&ctxt_0, &ctxt_1);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);

            // Uses the hardcoded values to also test our clear function
            let (q2, r2) = signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

            assert_eq!(q2, expected_q);
            assert_eq!(r2, expected_r);
            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    // A test where the division is whole, aka remainder is zero
    {
        let ctxt_0 = cks.encrypt_signed_radix(4, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(-2, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_floor_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);

        // Uses the hardcoded values to also test our clear function
        let (q2, r2) = signed_div_rem_floor_under_modulus(4, -2, modulus);

        assert_eq!(q2, -2);
        assert_eq!(r2, 0);
        assert_eq!(q, -2);
        assert_eq!(r, 0);
    }

    // Div is the slowest operation
    for _ in 0..5 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = loop {
            let value = rng.gen::<i64>() % modulus;
            if value != 0 {
                break value;
            }
        };

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_floor_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let (expected_q, expected_r) =
            signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

        println!("{clear_0} / {clear_1} -> ({q}, {r})");
        assert_eq!(q, expected_q);
        assert_eq!(r, expected_r);
    }
}

//================================================================================
//     Smart Tests
//================================================================================

create_parametrized_test!(integer_signed_smart_add);
create_parametrized_test!(integer_signed_smart_neg);
create_parametrized_test!(integer_signed_smart_absolute_value);

fn integer_signed_smart_add(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen_range(-modulus..modulus);
        let clear_1 = rng.gen_range(-modulus..modulus);

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let mut ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let mut ct_res = sks.smart_add_parallelized(&mut ctxt_0, &mut ctxt_1);
        clear = signed_add_under_modulus(clear_0, clear_1, modulus);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(clear, dec_res);

        // add multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = sks.smart_add_parallelized(&mut ct_res, &mut ctxt_0);
            clear = signed_add_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_signed_smart_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<i64>() % modulus;

        let mut ctxt = cks.encrypt_signed(clear);

        let mut ct_res = sks.smart_neg_parallelized(&mut ctxt);
        let mut clear_res = signed_neg_under_modulus(clear, modulus);
        let dec: i64 = cks.decrypt_signed(&ct_res);
        assert_eq!(clear_res, dec);

        for _ in 0..NB_TESTS_SMALLER {
            ct_res = sks.smart_neg_parallelized(&mut ct_res);
            clear_res = signed_neg_under_modulus(clear_res, modulus);

            let dec: i64 = cks.decrypt_signed(&ct_res);
            println!("clear_res: {clear_res}, dec : {dec}");
            assert_eq!(clear_res, dec);
        }
    }
}

fn integer_signed_smart_absolute_value(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let clear_to_add = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_to_add);
        clear_0 = signed_add_under_modulus(clear_0, clear_to_add, modulus);

        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

//================================================================================
//     Default Tests
//================================================================================

create_parametrized_test!(integer_signed_default_add);
create_parametrized_test!(integer_signed_default_overflowing_add);
create_parametrized_test!(integer_signed_default_neg);
create_parametrized_test!(integer_signed_default_sub);
create_parametrized_test!(integer_signed_default_overflowing_sub);
create_parametrized_test!(integer_signed_default_mul);
create_parametrized_test!(integer_signed_default_bitnot);
create_parametrized_test!(integer_signed_default_bitand);
create_parametrized_test!(integer_signed_default_bitor);
create_parametrized_test!(integer_signed_default_bitxor);
create_parametrized_test!(integer_signed_default_absolute_value);
create_parametrized_test!(integer_signed_default_left_shift {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_default_right_shift {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_default_rotate_left {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_signed_default_rotate_right {
    // Requires 3 bits, so 1_1 parameters are not supported
    // until they get their own version of the algorithm
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

fn integer_signed_default_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = sks.add_parallelized(&ctxt_0, &ctxt_1);
        let tmp_ct = sks.add_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        clear = signed_add_under_modulus(clear_0, clear_1, modulus);

        // println!("clear_0 = {}, clear_1 = {}", clear_0, clear_1);
        // add multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = sks.add_parallelized(&ct_res, &ctxt_0);
            assert!(ct_res.block_carries_are_empty());
            clear = signed_add_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_signed_default_overflowing_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = sks.signed_overflowing_add_parallelized(&ctxt_0, &ctxt_1);
        let (tmp_ct, tmp_o) = sks.signed_overflowing_add_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_suv for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

        for _ in 0..NB_TESTS_SMALLER {
            // Add non zero scalar to have non clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_3 = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let ctxt_1 = sks.unchecked_scalar_add(&ctxt_1, clear_3);

            let clear_lhs = signed_add_under_modulus(clear_0, clear_2, modulus);
            let clear_rhs = signed_add_under_modulus(clear_1, clear_3, modulus);

            let d0: i64 = cks.decrypt_signed(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");
            let d1: i64 = cks.decrypt_signed(&ctxt_1);
            assert_eq!(d1, clear_rhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) =
                sks.signed_overflowing_add_parallelized(&ctxt_0, &ctxt_1);
            assert!(ct_res.block_carries_are_empty());

            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_add, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    // Test with trivial inputs, as it was bugged at some point
    for _ in 0..4 {
        // Reduce maximum value of random number such that at least the last block is a trivial 0
        // (This is how the reproducing case was found)
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_add_parallelized(&a, &b);

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

fn integer_signed_default_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // -modulus is a special case, its negation cannot be
    // represented. rust by default returns -modulus
    // (which is what two complement result in)
    {
        let clear = -modulus;
        let ctxt = cks.encrypt_signed(clear);

        let ct_res = sks.neg_parallelized(&ctxt);
        let tmp = sks.neg_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec: i64 = cks.decrypt_signed(&ct_res);
        let clear_result = signed_neg_under_modulus(clear, modulus);

        assert_eq!(clear_result, dec);
    }

    for _ in 0..NB_TESTS_SMALLER {
        let clear = rng.gen::<i64>() % modulus;

        let ctxt = cks.encrypt_signed(clear);

        let ct_res = sks.neg_parallelized(&ctxt);
        let tmp = sks.neg_parallelized(&ctxt);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp);

        let dec: i64 = cks.decrypt_signed(&ct_res);
        let clear_result = signed_neg_under_modulus(clear, modulus);

        assert_eq!(clear_result, dec);
    }
}

fn integer_signed_default_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = sks.sub_parallelized(&ctxt_0, &ctxt_1);
        let tmp_ct = sks.sub_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        clear = signed_sub_under_modulus(clear_0, clear_1, modulus);

        // sub multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = sks.sub_parallelized(&ct_res, &ctxt_0);
            assert!(ct_res.block_carries_are_empty());
            clear = signed_sub_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_signed_default_overflowing_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let (ct_res, result_overflowed) = sks.signed_overflowing_sub_parallelized(&ctxt_0, &ctxt_1);
        let (tmp_ct, tmp_o) = sks.signed_overflowing_sub_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_suv for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

        for _ in 0..NB_TESTS_SMALLER {
            // Add non zero scalar to have non clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_3 = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let ctxt_1 = sks.unchecked_scalar_add(&ctxt_1, clear_3);

            let clear_lhs = signed_add_under_modulus(clear_0, clear_2, modulus);
            let clear_rhs = signed_add_under_modulus(clear_1, clear_3, modulus);

            let d0: i64 = cks.decrypt_signed(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");
            let d1: i64 = cks.decrypt_signed(&ctxt_1);
            assert_eq!(d1, clear_rhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) =
                sks.signed_overflowing_sub_parallelized(&ctxt_0, &ctxt_1);
            assert!(ct_res.block_carries_are_empty());

            let (expected_result, expected_overflowed) =
                signed_overflowing_sub_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for sub, for ({clear_lhs} - {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_sub, for ({clear_lhs} - {clear_rhs}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    // Test with trivial inputs, as it was bugged at some point
    for _ in 0..4 {
        // Reduce maximum value of random number such that at least the last block is a trivial 0
        // (This is how the reproducing case was found)
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);
        let b: SignedRadixCiphertext = sks.create_trivial_radix(clear_1, NB_CTXT);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_sub_parallelized(&a, &b);

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

fn integer_signed_default_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let mut ct_res = sks.mul_parallelized(&ctxt_0, &ctxt_1);
        let tmp_ct = sks.mul_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct);

        clear = signed_mul_under_modulus(clear_0, clear_1, modulus);

        // mul multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            ct_res = sks.mul_parallelized(&ct_res, &ctxt_0);
            assert!(ct_res.block_carries_are_empty());
            clear = signed_mul_under_modulus(clear, clear_0, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);

            // println!("clear = {}, dec_res = {}", clear, dec_res);
            assert_eq!(clear, dec_res);
        }
    }
}

fn integer_signed_default_bitnot(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.bitnot_parallelized(&ctxt_0);
        let ct_res2 = sks.bitnot_parallelized(&ctxt_0);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = !clear_0;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_default_bitand(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let mut clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let mut ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.bitand_parallelized(&ctxt_0, &ctxt_1);
        let ct_res2 = sks.bitand_parallelized(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        let clear_3 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        sks.unchecked_scalar_add_assign(&mut ctxt_1, clear_3);

        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        clear_0 = signed_add_under_modulus(clear_0, clear_2, modulus);
        clear_1 = signed_add_under_modulus(clear_1, clear_3, modulus);

        let ct_res = sks.bitand_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

        let expected_result = clear_0 & clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

fn integer_signed_default_bitor(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let mut clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let mut ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.bitor_parallelized(&ctxt_0, &ctxt_1);
        let ct_res2 = sks.bitor_parallelized(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        let clear_3 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        sks.unchecked_scalar_add_assign(&mut ctxt_1, clear_3);

        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        clear_0 = signed_add_under_modulus(clear_0, clear_2, modulus);
        clear_1 = signed_add_under_modulus(clear_1, clear_3, modulus);

        let ct_res = sks.bitor_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

        let expected_result = clear_0 | clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

fn integer_signed_default_bitxor(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let mut clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let mut ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let ct_res = sks.bitxor_parallelized(&ctxt_0, &ctxt_1);
        let ct_res2 = sks.bitxor_parallelized(&ctxt_0, &ctxt_1);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);
        let clear_3 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        sks.unchecked_scalar_add_assign(&mut ctxt_1, clear_3);

        assert!(!ctxt_0.block_carries_are_empty());
        assert!(!ctxt_1.block_carries_are_empty());

        clear_0 = signed_add_under_modulus(clear_0, clear_2, modulus);
        clear_1 = signed_add_under_modulus(clear_1, clear_3, modulus);

        let ct_res = sks.bitxor_parallelized(&ctxt_0, &ctxt_1);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

        let expected_result = clear_0 ^ clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

fn integer_signed_default_absolute_value(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let clear_to_add = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_to_add);
        clear_0 = signed_add_under_modulus(clear_0, clear_to_add, modulus);

        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);

        let ct_res2 = sks.abs_parallelized(&ctxt_0);
        assert_eq!(ct_res2, ct_res);
    }
}

fn integer_signed_default_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            // Here we create a encrypted shift value in range O..nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(0u32);
            sks.unchecked_add_assign(&mut shift, &tmp);
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.left_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.left_shift_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            // Here we create a encrypted shift value >= nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let mut clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(nb_bits);
            sks.unchecked_add_assign(&mut shift, &tmp);
            clear_shift += nb_bits;
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.left_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.left_shift_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

fn integer_signed_default_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            // Here we create a encrypted shift value in range O..nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(0u32);
            sks.unchecked_add_assign(&mut shift, &tmp);
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.right_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.right_shift_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            // Here we create a encrypted shift value >= nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let mut clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(nb_bits);
            sks.unchecked_add_assign(&mut shift, &tmp);
            clear_shift += nb_bits;
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.right_shift_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.right_shift_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

fn integer_signed_default_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            // Here we create a encrypted shift value in range O..nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(0u32);
            sks.unchecked_add_assign(&mut shift, &tmp);
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.rotate_left_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear}.rotate_left({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.rotate_left_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            // Here we create a encrypted shift value >= nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let mut clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(nb_bits);
            sks.unchecked_add_assign(&mut shift, &tmp);
            clear_shift += nb_bits;
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.rotate_left_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_left_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(
                clear_res,
                dec_res,
                "Invalid rotate left result, for '{clear}.rotate_left({})', \
                expected:  {clear_res}, got: {dec_res}",
                clear_shift % nb_bits
            );

            let ct_res2 = sks.rotate_left_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

fn integer_signed_default_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            // Here we create a encrypted shift value in range O..nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(0u32);
            sks.unchecked_add_assign(&mut shift, &tmp);
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.rotate_right_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear}.rotate_right({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.rotate_right_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            // Here we create a encrypted shift value >= nb_bits
            // in a way that the shift ciphertext is seen as having non empty carries
            let mut clear_shift = rng.gen::<u32>() % nb_bits;
            let tmp = cks.encrypt(clear_shift);
            let mut shift = cks.encrypt(nb_bits);
            sks.unchecked_add_assign(&mut shift, &tmp);
            clear_shift += nb_bits;
            assert!(!shift.block_carries_are_empty());

            let ct_res = sks.rotate_right_parallelized(&ct, &shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // When nb_bits is not a power of two
            // then the behaviour is not the same
            let true_nb_bits = nb_bits;
            let mut nb_bits = modulus.ilog2();
            if !nb_bits.is_power_of_two() {
                nb_bits = nb_bits.next_power_of_two();
            }
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_right_helper(clear, clear_shift % nb_bits, true_nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid rotate right result, for '{clear}.rotate_right({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.rotate_right_parallelized(&ct, &shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

//================================================================================
//     Unchecked Scalar Tests
//================================================================================

create_parametrized_test!(integer_signed_unchecked_scalar_add);
create_parametrized_test!(integer_signed_unchecked_scalar_sub);
create_parametrized_test!(integer_signed_unchecked_scalar_mul);
create_parametrized_test!(integer_signed_unchecked_scalar_rotate_left);
create_parametrized_test!(integer_signed_unchecked_scalar_rotate_right);
create_parametrized_test!(integer_signed_unchecked_scalar_left_shift);
create_parametrized_test!(integer_signed_unchecked_scalar_right_shift);
create_parametrized_test!(integer_signed_unchecked_scalar_bitand);
create_parametrized_test!(integer_signed_unchecked_scalar_bitor);
create_parametrized_test!(integer_signed_unchecked_scalar_bitxor);
create_parametrized_test!(integer_signed_unchecked_scalar_div_rem);
create_parametrized_test!(integer_signed_unchecked_scalar_div_rem_floor);

fn integer_signed_unchecked_scalar_add(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, -1, modulus - 1),
        (modulus - 1, 1, -modulus),
        (-modulus, -2, modulus - 2),
        (modulus - 2, 2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.unchecked_scalar_add(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_scalar_add(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_scalar_sub(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, 1, modulus - 1),
        (modulus - 1, -1, -modulus),
        (-modulus, 2, modulus - 2),
        (modulus - 2, -2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.unchecked_scalar_sub(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_scalar_sub(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_scalar_mul(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_scalar_mul_parallelized(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = signed_mul_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_scalar_bitand(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_scalar_bitand_parallelized(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_scalar_bitor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_scalar_bitor_parallelized(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_scalar_bitxor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_scalar_bitxor_parallelized(&ctxt_0, clear_1);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_scalar_rotate_left(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = sks.unchecked_scalar_rotate_left_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when rotate >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_rotate_left_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_scalar_rotate_right(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);

        // case when 0 <= rotate < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when rotate >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_rotate_right_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_scalar_left_shift(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_left_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = signed_left_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_scalar_right_shift(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = sks.unchecked_scalar_right_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
            let expected = signed_right_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(expected, dec_res);
        }
    }
}

fn integer_signed_unchecked_scalar_div_rem(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = rng.gen::<i64>() % modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let result = std::panic::catch_unwind(|| {
            let _ = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, 0);
        });
        assert!(result.is_err(), "Division by zero did not panic");
    }

    // check when scalar is out of ciphertext MIN..=MAX
    for d in [
        rng.gen_range(i64::MIN..-modulus),
        rng.gen_range(modulus..=i64::MAX),
    ] {
        for numerator in [rng.gen_range(-modulus..=0), rng.gen_range(0..modulus)] {
            let ctxt_0 = cks.encrypt_signed_radix(numerator, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(numerator, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(numerator, d, modulus));
        }
    }

    // The algorithm has a special case for when divisor is 1 or -1
    for d in [1i64, -1i64] {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        assert_eq!(q, signed_div_under_modulus(clear_0, d, modulus));
        assert_eq!(r, signed_rem_under_modulus(clear_0, d, modulus));
    }

    // 3 / -3 takes the second branch in the if else if series
    for d in [3, -3] {
        {
            let neg_clear_0 = rng.gen_range(-modulus..=0);
            let ctxt_0 = cks.encrypt_signed_radix(neg_clear_0, NB_CTXT);
            println!("{neg_clear_0} / {d}");
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
        }

        {
            let pos_clear_0 = rng.gen_range(0..modulus);
            let ctxt_0 = cks.encrypt_signed_radix(pos_clear_0, NB_CTXT);
            println!("{pos_clear_0} / {d}");
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
        }
    }

    // Param 1_1 cannot do this, with our NB_CTXT
    if modulus >= 43 {
        // For param_2_2 this will take the third branch in the if else if series
        for d in [-89, 89] {
            {
                let neg_clear_0 = rng.gen_range(-modulus..=0);
                let ctxt_0 = cks.encrypt_signed_radix(neg_clear_0, NB_CTXT);
                let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
                let q: i64 = cks.decrypt_signed_radix(&q_res);
                let r: i64 = cks.decrypt_signed_radix(&r_res);
                assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
                assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
            }

            {
                let pos_clear_0 = rng.gen_range(0..modulus);
                let ctxt_0 = cks.encrypt_signed_radix(pos_clear_0, NB_CTXT);
                println!("{pos_clear_0} / {d}");
                let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
                let q: i64 = cks.decrypt_signed_radix(&q_res);
                let r: i64 = cks.decrypt_signed_radix(&r_res);
                assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
                assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
            }
        }

        // For param_2_2 this will take the first branch
        for (clear_0, clear_1) in [(43, 8), (43, -8), (-43, 8), (-43, -8)] {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, clear_1);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(clear_0, clear_1, modulus));
            assert_eq!(r, signed_rem_under_modulus(clear_0, clear_1, modulus));
        }
    }

    for d in [-modulus, modulus - 1] {
        {
            let neg_clear_0 = rng.gen_range(-modulus..=0);
            let ctxt_0 = cks.encrypt_signed_radix(neg_clear_0, NB_CTXT);
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
        }

        {
            let pos_clear_0 = rng.gen_range(0..modulus);
            let ctxt_0 = cks.encrypt_signed_radix(pos_clear_0, NB_CTXT);
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
        }
    }

    let lhs_values = random_signed_value_under_modulus::<6>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<6>(&mut rng, modulus);

    for (clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let ctxt_0 = cks.encrypt_signed_radix(clear_lhs, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, clear_rhs);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        assert_eq!(q, signed_div_under_modulus(clear_lhs, clear_rhs, modulus));
        assert_eq!(r, signed_rem_under_modulus(clear_lhs, clear_rhs, modulus));
    }
}

fn integer_signed_unchecked_scalar_div_rem_floor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    if modulus > 8 {
        // Some hard coded test for flooring div
        // For example, truncating_div(-7, 3) would give q = -2 and r = -1
        // truncating div is the default in rust (and many other languages)
        // Python does use a flooring div, so you can try these values in you local
        // interpreter.
        let values = [
            (-8, 3, -3, 1),
            (8, -3, -3, -1),
            (7, 3, 2, 1),
            (-7, 3, -3, 2),
            (7, -3, -3, -2),
            (-7, -3, 2, -1),
        ];
        for (clear_0, clear_1, expected_q, expected_r) in values {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

            let (q_res, r_res) =
                sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, clear_1);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);

            // Also serves as a test for our function

            let (q2, r2) = signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

            assert_eq!(q2, expected_q);
            assert_eq!(r2, expected_r);
            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    {
        let clear_0 = rng.gen::<i64>() % modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let result = std::panic::catch_unwind(|| {
            let _ = sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, 0);
        });
        assert!(result.is_err(), "Division by zero did not panic");
    }

    // check when scalar is out of ciphertext MIN..=MAX
    for d in [
        rng.gen_range(i64::MIN..-modulus),
        rng.gen_range(modulus..=i64::MAX),
    ] {
        for numerator in [0, rng.gen_range(-modulus..=0), rng.gen_range(0..modulus)] {
            let ctxt_0 = cks.encrypt_signed_radix(numerator, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);

            println!("{numerator} + {d} -> ({q}, {r})");

            let mut expected_q = numerator / d;
            let mut expected_r = numerator % d;
            assert_eq!(expected_q, 0);
            assert_eq!(expected_r, numerator);

            // This does the almost the same thing as signed_div_mod_under_modulus
            // but it applies a bit mask where the tested function also does
            if expected_r != 0 && ((expected_r < 0) != (d < 0)) {
                expected_q = -1;
                // numerator = (quotient * divisor) + rest
                expected_r = signed_sub_under_modulus(
                    numerator,
                    signed_mul_under_modulus(expected_q, d & ((2 * modulus) - 1), modulus),
                    modulus,
                );
            }

            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    let lhs_values = random_signed_value_under_modulus::<5>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<5>(&mut rng, modulus);

    for (clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let ctxt_0 = cks.encrypt_signed_radix(clear_lhs, NB_CTXT);

        let (q_res, r_res) =
            sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, clear_rhs);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let (expected_q, expected_r) =
            signed_div_rem_floor_under_modulus(clear_lhs, clear_rhs, modulus);
        assert_eq!(q, expected_q);
        assert_eq!(r, expected_r);
    }
}

//================================================================================
//     Smart Scalar Tests
//================================================================================

//================================================================================
//     Default Scalar Tests
//================================================================================

create_parametrized_test!(integer_signed_default_scalar_add);
create_parametrized_test!(integer_signed_default_overflowing_scalar_add);
create_parametrized_test!(integer_signed_default_overflowing_scalar_sub);
create_parametrized_test!(integer_signed_default_scalar_bitand);
create_parametrized_test!(integer_signed_default_scalar_bitor);
create_parametrized_test!(integer_signed_default_scalar_bitxor);
create_parametrized_test!(integer_signed_default_scalar_div_rem);
create_parametrized_test!(integer_signed_default_scalar_left_shift);
create_parametrized_test!(integer_signed_default_scalar_right_shift);
create_parametrized_test!(integer_signed_default_scalar_rotate_right);
create_parametrized_test!(integer_signed_default_scalar_rotate_left);

fn integer_signed_default_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let mut clear;

    let mut rng = rand::thread_rng();

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let mut ct_res = sks.scalar_add_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());

        clear = signed_add_under_modulus(clear_0, clear_1, modulus);

        // add multiple times to raise the degree
        for _ in 0..NB_TESTS_SMALLER {
            let tmp = sks.scalar_add_parallelized(&ct_res, clear_1);
            ct_res = sks.scalar_add_parallelized(&ct_res, clear_1);
            assert!(ct_res.block_carries_are_empty());
            assert_eq!(ct_res, tmp);
            clear = signed_add_under_modulus(clear, clear_1, modulus);

            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn integer_signed_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let hardcoded_values = [
        (-modulus, -1),
        (modulus - 1, 1),
        (-1, -modulus),
        (1, modulus - 1),
    ];
    for (clear_0, clear_1) in hardcoded_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) =
            sks.signed_overflowing_scalar_add_parallelized(&ctxt_0, clear_1);
        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
    }

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) =
            sks.signed_overflowing_scalar_add_parallelized(&ctxt_0, clear_1);
        let (tmp_ct, tmp_o) = sks.signed_overflowing_scalar_add_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add for ({clear_0} + {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

        for _ in 0..NB_TESTS_SMALLER {
            // Add non zero scalar to have non clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_rhs = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let (clear_lhs, _) = signed_overflowing_add_under_modulus(clear_0, clear_2, modulus);
            let d0: i64 = cks.decrypt_signed(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) =
                sks.signed_overflowing_scalar_add_parallelized(&ctxt_0, clear_rhs);
            assert!(ct_res.block_carries_are_empty());
            let (expected_result, expected_overflowed) =
                signed_overflowing_add_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for add, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_add, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    // Test with trivial inputs
    for _ in 0..4 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_scalar_add_parallelized(&a, clear_1);

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} + {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }

    // Test with scalar that is bigger than ciphertext modulus
    for _ in 0..2 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen_range(modulus..=i64::MAX);

        let a = cks.encrypt_signed(clear_0);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_scalar_add_parallelized(&a, clear_1);

        let (expected_result, expected_overflowed) =
            signed_overflowing_add_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_add, for ({clear_0} + {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert!(decrypted_overflowed); // Actually we know its an overflow case
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

pub(crate) fn integer_signed_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    let hardcoded_values = [
        (-modulus, 1),
        (modulus - 1, -1),
        (1, -modulus),
        (-1, modulus - 1),
    ];
    for (clear_0, clear_1) in hardcoded_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) =
            sks.signed_overflowing_scalar_sub_parallelized(&ctxt_0, clear_1);
        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
    }

    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (ct_res, result_overflowed) =
            sks.signed_overflowing_scalar_sub_parallelized(&ctxt_0, clear_1);
        let (tmp_ct, tmp_o) = sks.signed_overflowing_scalar_sub_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        assert_eq!(ct_res, tmp_ct, "Failed determinism check");
        assert_eq!(tmp_o, result_overflowed, "Failed determinism check");

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
        let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
             expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub for ({clear_0} - {clear_1}) % {modulus} \
             expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(result_overflowed.0.degree.get(), 1);
        assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);

        for _ in 0..NB_TESTS_SMALLER {
            // Add non zero scalar to have non clean ciphertexts
            let clear_2 = random_non_zero_value(&mut rng, modulus);
            let clear_rhs = random_non_zero_value(&mut rng, modulus);

            let ctxt_0 = sks.unchecked_scalar_add(&ctxt_0, clear_2);
            let (clear_lhs, _) = signed_overflowing_add_under_modulus(clear_0, clear_2, modulus);
            let d0: i64 = cks.decrypt_signed(&ctxt_0);
            assert_eq!(d0, clear_lhs, "Failed sanity decryption check");

            let (ct_res, result_overflowed) =
                sks.signed_overflowing_scalar_sub_parallelized(&ctxt_0, clear_rhs);
            assert!(ct_res.block_carries_are_empty());
            let (expected_result, expected_overflowed) =
                signed_overflowing_sub_under_modulus(clear_lhs, clear_rhs, modulus);

            let decrypted_result: i64 = cks.decrypt_signed(&ct_res);
            let decrypted_overflowed = cks.decrypt_bool(&result_overflowed);
            assert_eq!(
                decrypted_result, expected_result,
                "Invalid result for sub, for ({clear_lhs} + {clear_rhs}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
            );
            assert_eq!(
                decrypted_overflowed,
                expected_overflowed,
                "Invalid overflow flag result for overflowing_sub, for ({clear_lhs} - {clear_rhs}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
            );
            assert_eq!(result_overflowed.0.degree.get(), 1);
            assert_eq!(result_overflowed.0.noise_level(), NoiseLevel::NOMINAL);
        }
    }

    // Test with trivial inputs
    for _ in 0..4 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let a: SignedRadixCiphertext = sks.create_trivial_radix(clear_0, NB_CTXT);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_scalar_sub_parallelized(&a, clear_1);

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for add, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }

    // Test with scalar that is bigger than ciphertext modulus
    for _ in 0..2 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen_range(modulus..=i64::MAX);

        let a = cks.encrypt_signed(clear_0);

        let (encrypted_result, encrypted_overflow) =
            sks.signed_overflowing_scalar_sub_parallelized(&a, clear_1);

        let (expected_result, expected_overflowed) =
            signed_overflowing_sub_under_modulus(clear_0, clear_1, modulus);

        let decrypted_result: i64 = cks.decrypt_signed(&encrypted_result);
        let decrypted_overflowed = cks.decrypt_bool(&encrypted_overflow);
        assert_eq!(
            decrypted_result, expected_result,
            "Invalid result for sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected {expected_result}, got {decrypted_result}"
        );
        assert_eq!(
            decrypted_overflowed,
            expected_overflowed,
            "Invalid overflow flag result for overflowing_sub, for ({clear_0} - {clear_1}) % {modulus} \
                expected overflow flag {expected_overflowed}, got {decrypted_overflowed}"
        );
        assert!(decrypted_overflowed); // Actually we know its an overflow case
        assert_eq!(encrypted_overflow.0.degree.get(), 1);
        assert_eq!(encrypted_overflow.0.noise_level(), NoiseLevel::ZERO);
    }
}

fn integer_signed_default_scalar_bitand(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.scalar_bitand_parallelized(&ctxt_0, clear_1);
        let ct_res2 = sks.scalar_bitand_parallelized(&ctxt_0, clear_1);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        assert!(!ctxt_0.block_carries_are_empty());

        let ct_res = sks.scalar_bitand_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

        let expected_result = signed_add_under_modulus(clear_0, clear_2, modulus) & clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

fn integer_signed_default_scalar_bitor(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.scalar_bitor_parallelized(&ctxt_0, clear_1);
        let ct_res2 = sks.scalar_bitor_parallelized(&ctxt_0, clear_1);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        assert!(!ctxt_0.block_carries_are_empty());

        let ct_res = sks.scalar_bitor_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

        let expected_result = signed_add_under_modulus(clear_0, clear_2, modulus) | clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

fn integer_signed_default_scalar_bitxor(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.scalar_bitxor_parallelized(&ctxt_0, clear_1);
        let ct_res2 = sks.scalar_bitxor_parallelized(&ctxt_0, clear_1);
        assert_eq!(ct_res, ct_res2);

        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);

        let clear_2 = random_non_zero_value(&mut rng, modulus);

        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_2);
        assert!(!ctxt_0.block_carries_are_empty());

        let ct_res = sks.scalar_bitxor_parallelized(&ctxt_0, clear_1);
        assert!(ct_res.block_carries_are_empty());
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);

        let expected_result = signed_add_under_modulus(clear_0, clear_2, modulus) ^ clear_1;
        assert_eq!(dec_res, expected_result);
    }
}

fn integer_signed_default_scalar_div_rem(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = rng.gen::<i64>() % modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let result = std::panic::catch_unwind(|| {
            let _ = sks.signed_scalar_div_rem_parallelized(&ctxt_0, 0);
        });
        assert!(result.is_err(), "Division by zero did not panic");
    }

    let lhs_values = random_signed_value_under_modulus::<5>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<5>(&mut rng, modulus);

    for (mut clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let mut ctxt_0 = cks.encrypt_signed_radix(clear_lhs, NB_CTXT);

        // Make the degree non-fresh
        let offset = random_non_zero_value(&mut rng, modulus);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, offset);
        clear_lhs = signed_add_under_modulus(clear_lhs, offset, modulus);
        assert!(!ctxt_0.block_carries_are_empty());

        let (q_res, r_res) = sks.signed_scalar_div_rem_parallelized(&ctxt_0, clear_rhs);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let expected_q = signed_div_under_modulus(clear_lhs, clear_rhs, modulus);
        let expected_r = signed_rem_under_modulus(clear_lhs, clear_rhs, modulus);
        assert_eq!(
            q, expected_q,
            "Invalid quotient result for division, for {clear_lhs} / {clear_rhs}, \
             Expected {expected_q}, got {q}"
        );
        assert_eq!(
            r, expected_r,
            "Invalid remainder result for division, for {clear_lhs} % {clear_rhs}, \
             Expected {expected_r}, got {r}"
        );

        let (q2_res, r2_res) = sks.signed_scalar_div_rem_parallelized(&ctxt_0, clear_rhs);
        assert_eq!(q2_res, q_res, "Failed determinism check");
        assert_eq!(r2_res, r_res, "Failed determinism check");
    }
}

fn integer_signed_default_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = sks.scalar_left_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_left_shift_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = sks.scalar_left_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_left_shift_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

fn integer_signed_default_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = sks.scalar_right_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_right_shift_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = sks.scalar_right_shift_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift % nb_bits, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_right_shift_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

fn integer_signed_default_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = sks.scalar_rotate_left_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear}.rotate_left({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_rotate_left_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = sks.scalar_rotate_left_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res,
                dec_res,
                "Invalid rotate left result, for '{clear}.rotate_left({})', \
                expected:  {clear_res}, got: {dec_res}",
                clear_shift % nb_bits
            );

            let ct_res2 = sks.scalar_rotate_left_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

fn integer_signed_default_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = sks.scalar_rotate_right_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear}.rotate_right({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_rotate_right_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = sks.scalar_rotate_right_parallelized(&ct, clear_shift);
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid rotate right result, for '{clear}.rotate_right({clear_shift})', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = sks.scalar_rotate_right_parallelized(&ct, clear_shift);
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}
