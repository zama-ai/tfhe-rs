use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, signed_add_under_modulus, signed_left_shift_under_modulus,
    signed_right_shift_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    large_shift_amounts, nb_tests_for_params, nb_tests_smaller_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_scalar_left_shift);
create_parameterized_test!(integer_signed_default_scalar_left_shift);
create_parameterized_test!(integer_signed_unchecked_scalar_right_shift);
create_parameterized_test!(integer_signed_default_scalar_right_shift);
create_parameterized_test!(integer_signed_default_scalar_shift_large_amount);

fn integer_signed_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift_parallelized);
    signed_unchecked_scalar_left_shift_test(param, executor);
}

fn integer_signed_default_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    signed_default_scalar_left_shift_test(param, executor);
}

fn integer_signed_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift_parallelized);
    signed_unchecked_scalar_right_shift_test(param, executor);
}

fn integer_signed_default_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    signed_default_scalar_right_shift_test(param, executor);
}
pub(crate) fn signed_unchecked_scalar_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            // An overshift pushes every bit out, so a left shift returns 0.
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            assert_eq!(0, dec_res);
        }
    }
}

pub(crate) fn signed_unchecked_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;
    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests {
        let clear = rng.gen::<i64>() % modulus;
        let clear_shift = rng.gen::<u32>();

        let ct = cks.encrypt_signed(clear);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = clear_shift % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            // An overshift saturates an arithmetic right shift to the sign: -1 if negative, else 0.
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = if clear < 0 { -1i64 } else { 0i64 };
            assert_eq!(expected, dec_res);
        }
    }
}

pub(crate) fn signed_default_scalar_left_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests_smaller {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_left_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }

        // case when shift >= nb_bits
        {
            // An overshift pushes every bit out, so a left shift returns 0.
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = 0i64;
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }
    }
}

pub(crate) fn signed_default_scalar_right_shift_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, u64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    assert!(modulus > 0);
    assert!((modulus as u64).is_power_of_two());
    let nb_bits = modulus.ilog2() + 1; // We are using signed numbers

    for _ in 0..nb_tests_smaller {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = signed_right_shift_under_modulus(clear, clear_shift, modulus);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }

        // case when shift >= nb_bits
        {
            // An overshift saturates an arithmetic right shift to the sign: -1 if negative, else 0.
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, u64::from(clear_shift)));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = if clear < 0 { -1i64 } else { 0i64 };
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, u64::from(clear_shift)));
            assert_eq!(ct_res, ct_res2, "Failed determinism check, \n\n\n msg0: {clear}, \n\n\nct: {ct:?}, \n\n\nclear: {clear_shift:?}\n\n\n");
        }
    }
}

/// Non regression test: amounts that do not fit in a u64 were truncated to their low 64 bits,
/// turning an overshift into a regular shift.
fn integer_signed_default_scalar_shift_large_amount<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let mut rng = rand::thread_rng();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for num_blocks in [3, 5] {
        let nb_bits = bits_per_block * num_blocks as u32;
        let half_modulus = 1i64 << (nb_bits - 1);
        // With its lowest and highest bits set, any shift below the bit count leaves a bit set
        let values = [
            -half_modulus + 1,
            rng.gen_range(-half_modulus..half_modulus),
        ];
        for clear in values {
            let ct = cks.encrypt_signed_radix(clear, num_blocks);
            for amount in large_shift_amounts(&mut rng, nb_bits) {
                // Every amount overshifts, an arithmetic right shift then gives the sign
                let sign = if clear < 0 { -1 } else { 0 };
                for (name, result, expected) in [
                    ("left", sks.scalar_left_shift_parallelized(&ct, amount), 0),
                    (
                        "right",
                        sks.scalar_right_shift_parallelized(&ct, amount),
                        sign,
                    ),
                ] {
                    assert!(result.block_carries_are_empty());
                    let decrypted: i64 = cks.decrypt_signed_radix(&result);
                    assert_eq!(
                        decrypted, expected,
                        "invalid {name} shift of {clear} by {amount} ({nb_bits} bits)"
                    );
                }
            }
        }
    }
}
