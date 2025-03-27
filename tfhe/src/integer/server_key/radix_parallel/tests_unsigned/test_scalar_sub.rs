use std::sync::Arc;

use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_sub_test, default_scalar_sub_test, smart_scalar_sub_test,
    FunctionExecutor,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, random_non_zero_value, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::prelude::*;

use super::{MAX_NB_CTXT, NB_CTXT};

create_parameterized_test!(integer_smart_scalar_sub);
create_parameterized_test!(integer_default_scalar_sub);
create_parameterized_test!(integer_unchecked_left_scalar_sub);
create_parameterized_test!(integer_smart_left_scalar_sub);
create_parameterized_test!(integer_default_left_scalar_sub);
create_parameterized_test!(integer_default_overflowing_scalar_sub);

fn integer_smart_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_sub_parallelized);
    smart_scalar_sub_test(param, executor);
}

fn integer_default_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    default_scalar_sub_test(param, executor);
}

fn integer_unchecked_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_scalar_sub);
    unchecked_left_scalar_sub_test(param, executor);
}

fn integer_smart_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_left_scalar_sub_parallelized);
    smart_left_scalar_sub_test(param, executor);
}

fn integer_default_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::left_scalar_sub_parallelized);
    default_left_scalar_sub_test(param, executor);
}

fn integer_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized);
    default_overflowing_scalar_sub_test(param, executor);
}

pub(crate) fn unchecked_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(u64, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = thread_rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests {
            let clear_lhs = rng.gen::<u64>() % modulus;
            let mut clear_rhs = rng.gen::<u64>() % modulus;

            let mut ct_rhs = cks.encrypt_radix(clear_rhs, num_blocks);

            ct_rhs = executor.execute((clear_lhs, &ct_rhs));
            clear_rhs = clear_lhs.wrapping_sub(clear_rhs) % modulus;

            let dec_res: u64 = cks.decrypt_radix(&ct_rhs);
            assert_eq!(dec_res, clear_rhs);

            let mut clear_lhs = rng.gen::<u64>() % modulus;
            while sks.is_left_scalar_sub_possible(clear_lhs, &ct_rhs).is_ok() {
                ct_rhs = executor.execute((clear_lhs, &ct_rhs));
                clear_rhs = clear_lhs.wrapping_sub(clear_rhs) % modulus;
                let dec_res: u64 = cks.decrypt_radix(&ct_rhs);
                assert_eq!(dec_res, clear_rhs);
                clear_lhs = rng.gen::<u64>() % modulus;
            }
        }
    }
}

pub(crate) fn smart_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(u64, &'a mut RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = thread_rng();

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        let clear_lhs = rng.gen::<u64>() % modulus;
        let mut clear_rhs = rng.gen::<u64>() % modulus;

        let mut ct_rhs = cks.encrypt_radix(clear_rhs, num_blocks);

        ct_rhs = executor.execute((clear_lhs, &mut ct_rhs));
        clear_rhs = clear_lhs.wrapping_sub(clear_rhs) % modulus;

        let dec_res: u64 = cks.decrypt_radix(&ct_rhs);
        assert_eq!(dec_res, clear_rhs);
        for _ in 0..nb_tests {
            let clear_lhs = rng.gen::<u64>() % modulus;

            ct_rhs = executor.execute((clear_lhs, &mut ct_rhs));
            clear_rhs = clear_lhs.wrapping_sub(clear_rhs) % modulus;
            let dec_res: u64 = cks.decrypt_radix(&ct_rhs);
            assert_eq!(dec_res, clear_rhs);
        }
    }
}

pub(crate) fn default_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(u64, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = thread_rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = cks.parameters().message_modulus().0.pow(num_blocks as u32);

        for _ in 0..nb_tests {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let ctxt_1 = cks.encrypt_radix(clear_1, num_blocks);

            let ct_res = executor.execute((clear_0, &ctxt_1));
            assert!(ct_res.block_carries_are_empty());

            let tmp = executor.execute((clear_0, &ctxt_1));
            assert_eq!(ct_res, tmp, "Operation is not deterministic");

            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(dec_res, (clear_0.wrapping_sub(clear_1)) % modulus);

            let non_zero = random_non_zero_value(&mut rng, modulus);
            let non_clean = sks.unchecked_scalar_add(&ctxt_1, non_zero);
            let ct_res = executor.execute((clear_0, &non_clean));
            assert!(ct_res.block_carries_are_empty());
            let dec_res: u64 = cks.decrypt_radix(&ct_res);
            assert_eq!(
                dec_res,
                (clear_0.wrapping_sub(clear_1.wrapping_add(non_zero))) % modulus
            );

            let ct_res2 = executor.execute((clear_0, &non_clean));
            assert_eq!(ct_res, ct_res2, "Failed determinism check");
        }
    }
}
