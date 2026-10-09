use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    narrow_scalar_cases, scalar_fits_the_blocks_but_not_the_range_cases, signed_add_under_modulus,
    MAX_NB_CTXT, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_scalar_add);
create_parameterized_test!(integer_signed_default_scalar_add);
create_parameterized_test!(integer_signed_default_overflowing_scalar_add);
create_parameterized_test!(integer_signed_default_overflowing_scalar_add_i8);

fn integer_signed_unchecked_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_add);
    signed_unchecked_scalar_add_test(param, executor);
}

fn integer_signed_default_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    signed_default_scalar_add_test(param, executor);
}

fn integer_signed_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_add_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_scalar_add_test(&ctx, executor);
}

fn integer_signed_default_overflowing_scalar_add_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_add_parallelized::<i8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_overflowing_scalar_add_test(&ctx, executor);
}

pub(crate) fn default_overflowing_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i64), (SignedRadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(default_scalar_fixed_cases::<i64>)
        .fixed_cases(scalar_fits_the_blocks_but_not_the_range_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<_>)| {
            lhs.overflowing_scalar_add(rhs.clear())
        });
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_overflowing_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i8), (SignedRadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .n_random(0)
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<_>)| {
            lhs.overflowing_scalar_add(rhs.clear())
        });
}
pub(crate) fn signed_unchecked_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
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
        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_add_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_default_scalar_add_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    executor.setup(&cks, sks);

    let cks: crate::integer::ClientKey = cks.into();

    let mut clear;

    let mut rng = rand::thread_rng();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;

        for _ in 0..nb_tests_smaller {
            let clear_0 = rng.gen::<i64>() % modulus;
            let clear_1 = rng.gen::<i64>() % modulus;

            let ctxt_0 = cks.encrypt_signed_radix(clear_0, num_blocks);

            let mut ct_res = executor.execute((&ctxt_0, clear_1));
            assert!(ct_res.block_carries_are_empty());

            clear = signed_add_under_modulus(clear_0, clear_1, modulus);

            // add multiple times to raise the degree
            for _ in 0..nb_tests_smaller {
                let tmp = executor.execute((&ct_res, clear_1));
                ct_res = executor.execute((&ct_res, clear_1));
                assert!(ct_res.block_carries_are_empty());
                assert_eq!(ct_res, tmp);
                clear = signed_add_under_modulus(clear, clear_1, modulus);

                let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
                assert_eq!(clear, dec_res);
            }
        }
    }
}
