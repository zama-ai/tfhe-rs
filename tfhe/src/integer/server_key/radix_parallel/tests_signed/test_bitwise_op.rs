use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    radix_edges_fixed_cases, radix_pair_fixed_cases, ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    create_iterator_of_signed_random_pairs, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_unchecked_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_bitand);
create_parameterized_test!(integer_signed_unchecked_bitor);
create_parameterized_test!(integer_signed_unchecked_bitxor);
create_parameterized_test!(integer_signed_default_bitnot);
create_parameterized_test!(integer_signed_default_bitand);
create_parameterized_test!(integer_signed_default_bitor);
create_parameterized_test!(integer_signed_default_bitxor);

fn integer_signed_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitand_parallelized);
    signed_unchecked_bitand_test(param, executor);
}

fn integer_signed_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitor_parallelized);
    signed_unchecked_bitor_test(param, executor);
}

fn integer_signed_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_bitxor_parallelized);
    signed_unchecked_bitxor_test(param, executor);
}

fn integer_signed_default_bitnot<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitnot);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_bitnot_test(&ctx, executor);
}

pub(crate) fn signed_default_bitnot_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext,), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_edges_fixed_cases::<Int>)
        .execute(executor, |(value,): (Int,)| value.bitnot());
}

fn integer_signed_default_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_bitand_test(&ctx, executor);
}

pub(crate) fn signed_default_bitand_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, SignedRadixCiphertext), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Int>)
        .execute(executor, |(lhs, rhs): (Int, Int)| lhs.bitand(rhs));
}

fn integer_signed_default_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_bitor_test(&ctx, executor);
}

pub(crate) fn signed_default_bitor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, SignedRadixCiphertext), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Int>)
        .execute(executor, |(lhs, rhs): (Int, Int)| lhs.bitor(rhs));
}

fn integer_signed_default_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_bitxor_test(&ctx, executor);
}

pub(crate) fn signed_default_bitxor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, SignedRadixCiphertext), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(radix_pair_fixed_cases::<Int>)
        .execute(executor, |(lhs, rhs): (Int, Int)| lhs.bitxor(rhs));
}

pub(crate) fn signed_unchecked_bitand_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_unchecked_tests = nb_unchecked_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs(&mut rng, modulus, nb_unchecked_tests)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 & clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_unchecked_bitor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_unchecked_tests = nb_unchecked_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs(&mut rng, modulus, nb_unchecked_tests)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 | clear_1;
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn signed_unchecked_bitxor_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
        (&'a SignedRadixCiphertext, &'a SignedRadixCiphertext),
        SignedRadixCiphertext,
    >,
{
    let param = param.into();
    let nb_unchecked_tests = nb_unchecked_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    for (clear_0, clear_1) in
        create_iterator_of_signed_random_pairs(&mut rng, modulus, nb_unchecked_tests)
    {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ctxt_1 = cks.encrypt_signed(clear_1);

        let ct_res = executor.execute((&ctxt_0, &ctxt_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = clear_0 ^ clear_1;
        assert_eq!(clear_res, dec_res);
    }
}
