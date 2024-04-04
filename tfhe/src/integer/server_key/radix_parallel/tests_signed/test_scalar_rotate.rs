use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_value, rotate_left_helper, rotate_right_helper, signed_add_under_modulus,
    NB_CTXT, NB_TESTS, NB_TESTS_SMALLER,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parametrized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parametrized_test!(integer_signed_unchecked_scalar_rotate_left);
create_parametrized_test!(integer_signed_default_scalar_rotate_left);
create_parametrized_test!(integer_signed_unchecked_scalar_rotate_right);
create_parametrized_test!(integer_signed_default_scalar_rotate_right);

fn integer_signed_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_rotate_left_parallelized);
    signed_unchecked_scalar_rotate_left_test(param, executor);
}

fn integer_signed_default_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_rotate_left_parallelized);
    signed_default_scalar_rotate_left_test(param, executor);
}

fn integer_signed_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_rotate_right_parallelized);
    signed_unchecked_scalar_rotate_right_test(param, executor);
}

fn integer_signed_default_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_rotate_right_parallelized);
    signed_default_scalar_rotate_right_test(param, executor);
}

pub(crate) fn signed_unchecked_scalar_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

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
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when rotate >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

pub(crate) fn signed_unchecked_scalar_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks);

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
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }

        // case when shift >= nb_bits
        {
            let clear_shift = clear_shift.saturating_add(nb_bits);
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let expected = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(expected, dec_res);
        }
    }
}

pub(crate) fn signed_default_scalar_rotate_left_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
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

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, clear_shift as i64));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_left_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid left shift result, for '{clear} << {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, clear_shift as i64));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}

pub(crate) fn signed_default_scalar_rotate_right_test<P, T>(param: P, mut executor: T)
where
    P: Into<PBSParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
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

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear = rng.gen::<i64>() % modulus;

        let offset = random_non_zero_value(&mut rng, modulus);

        let mut ct = cks.encrypt_signed(clear);
        sks.unchecked_scalar_add_assign(&mut ct, offset);
        clear = signed_add_under_modulus(clear, offset, modulus);

        // case when 0 <= shift < nb_bits
        {
            let clear_shift = rng.gen::<u32>() % nb_bits;
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, clear_shift as i64));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }

        // case when shift >= nb_bits
        {
            let clear_shift = rng.gen_range(nb_bits..=u32::MAX);
            let ct_res = executor.execute((&ct, clear_shift as i64));
            let dec_res: i64 = cks.decrypt_signed(&ct_res);
            // We mimic wrapping_shl manually as we use a bigger type
            // than the nb_bits we actually simulate in this test
            let clear_res = rotate_right_helper(clear, clear_shift, nb_bits);
            assert_eq!(
                clear_res, dec_res,
                "Invalid right shift result, for '{clear} >> {clear_shift}', \
                expected:  {clear_res}, got: {dec_res}"
            );

            let ct_res2 = executor.execute((&ct, clear_shift as i64));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}
