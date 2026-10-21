use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    radix_edges_fixed_cases, radix_pair_fixed_cases, ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, nb_tests_smaller_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_default_bitand);
create_parameterized_test!(integer_default_bitor);
create_parameterized_test!(integer_default_bitnot);
create_parameterized_test!(integer_default_bitxor);
create_parameterized_test!(integer_unchecked_bitand);
create_parameterized_test!(integer_unchecked_bitor);
create_parameterized_test!(integer_unchecked_bitnot);
create_parameterized_test!(integer_unchecked_bitxor);

fn integer_default_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_bitand_test(&ctx, executor);
}

pub(crate) fn default_bitand_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Uint>)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| lhs.bitand(rhs));
}

fn integer_default_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_bitor_test(&ctx, executor);
}

pub(crate) fn default_bitor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Uint>)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| lhs.bitor(rhs));
}

fn integer_default_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_bitxor_test(&ctx, executor);
}

pub(crate) fn default_bitxor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Uint>)
        .execute(executor, |(lhs, rhs): (Uint, Uint)| lhs.bitxor(rhs));
}

fn integer_default_bitnot<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    executor.setup_with_server_key(ctx.server_key());
    default_bitnot_test(&ctx, executor);
}

pub(crate) fn default_bitnot_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext,), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_edges_fixed_cases::<Uint>)
        .execute(executor, |(value,): (Uint,)| value.bitnot());
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    unchecked_bitand_test(param, executor);
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitor_parallelized);
    unchecked_bitor_test(param, executor);
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitxor_parallelized);
    unchecked_bitxor_test(param, executor);
}

fn integer_unchecked_bitnot<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    unchecked_bitnot_test(param, executor);
}

pub(crate) fn unchecked_bitnot_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);

        let ct_res = executor.execute(&ctxt);

        let dec: u64 = cks.decrypt(&ct_res);

        let clear_result = !clear % modulus;
        assert_eq!(clear_result, dec);
    }
}

pub(crate) fn unchecked_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;
    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));

        clear = clear_0 & clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&ct_res, &ctxt_2));
            clear &= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn unchecked_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;

    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);

        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));

        clear = (clear_0 | clear_1) % modulus;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;
            let ctxt_2 = cks.encrypt(clear_2);
            ct_res = executor.execute((&ct_res, &ctxt_2));
            clear |= clear_2;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}

pub(crate) fn unchecked_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, &'a RadixCiphertext), RadixCiphertext>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    executor.setup(&cks, sks);

    let mut clear;
    for _ in 0..nb_tests_smaller {
        let clear_0 = rng.gen::<u64>() % modulus;
        let clear_1 = rng.gen::<u64>() % modulus;

        let ctxt_0 = cks.encrypt(clear_0);
        let ctxt_1 = cks.encrypt(clear_1);
        let mut ct_res = executor.execute((&ctxt_0, &ctxt_1));

        clear = clear_0 ^ clear_1;

        for _ in 0..nb_tests_smaller {
            let clear_2 = rng.gen::<u64>() % modulus;

            let ctxt_2 = cks.encrypt(clear_2);

            ct_res = executor.execute((&ct_res, &ctxt_2));
            clear = (clear ^ clear_2) % modulus;

            let dec_res: u64 = cks.decrypt(&ct_res);
            assert_eq!(clear, dec_res);
        }
    }
}
