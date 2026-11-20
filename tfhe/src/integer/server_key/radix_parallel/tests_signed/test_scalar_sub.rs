use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, scalar_on_the_left, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    narrow_scalar_cases, signed_sub_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor, MAX_NB_CTXT,
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

create_parameterized_test!(integer_signed_unchecked_scalar_sub);
create_parameterized_test!(integer_signed_default_scalar_sub);
create_parameterized_test!(integer_signed_default_scalar_sub_i8);
create_parameterized_test!(integer_signed_default_overflowing_scalar_sub);
create_parameterized_test!(integer_signed_default_overflowing_scalar_sub_i8);
create_parameterized_test!(integer_signed_unchecked_left_scalar_sub);
create_parameterized_test!(integer_signed_default_left_scalar_sub);
create_parameterized_test!(integer_signed_default_left_scalar_sub_i8);

fn integer_signed_unchecked_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_sub);
    signed_unchecked_scalar_sub_test(param, executor);
}

fn integer_signed_default_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized::<SignedRadixCiphertext, i64>);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_sub_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<i64>)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i64>)| {
            // The scalar is taken as its two's complement bits on the radix width
            lhs.wrapping_sub(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_scalar_sub_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized::<SignedRadixCiphertext, i8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_scalar_sub_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i8), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        // Only fixed_cases: signed_default_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i8>)| {
            lhs.wrapping_sub(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_sub_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_scalar_sub_test(&ctx, executor);
}

fn integer_signed_default_overflowing_scalar_sub_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::signed_overflowing_scalar_sub_parallelized::<i8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_overflowing_scalar_sub_test(&ctx, executor);
}

fn integer_signed_unchecked_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_scalar_sub);
    signed_unchecked_left_scalar_sub_test(param, executor);
}

fn integer_signed_default_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::left_scalar_sub_parallelized::<i64, SignedRadixCiphertext>,
    );
    executor.setup_with_server_key(ctx.server_key());
    signed_default_left_scalar_sub_test(&ctx, executor);
}

pub(crate) fn signed_default_left_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(i64, SignedRadixCiphertext), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(|input_size, ctx| {
            scalar_on_the_left(default_scalar_fixed_cases::<i64>(input_size, ctx))
        })
        .execute(executor, |(lhs, rhs): (TestScalar<i64>, Int)| {
            lhs.cast(rhs.bits()).wrapping_sub(rhs)
        });
}

fn integer_signed_default_left_scalar_sub_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::left_scalar_sub_parallelized::<i8, SignedRadixCiphertext>,
    );
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_left_scalar_sub_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_left_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(i8, SignedRadixCiphertext), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        // Only fixed_cases: signed_default_left_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(|input_size, ctx| scalar_on_the_left(narrow_scalar_cases(input_size, ctx)))
        .execute(executor, |(lhs, rhs): (TestScalar<i8>, Int)| {
            lhs.cast(rhs.bits()).wrapping_sub(rhs)
        });
}

pub(crate) fn signed_unchecked_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    // check some overflow behaviour
    let overflowing_values = [
        (-modulus, 1, modulus - 1),
        (modulus - 1, -1, -modulus),
        (-modulus, 2, modulus - 2),
        (modulus - 2, -2, -modulus),
    ];
    for (clear_0, clear_1, expected_clear) in overflowing_values {
        let ctxt_0 = cks.encrypt_signed(clear_0);
        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
        assert_eq!(clear_res, expected_clear);
    }

    for _ in 0..nb_tests {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let ct_res = executor.execute((&ctxt_0, clear_1));
        let dec_res: i64 = cks.decrypt_signed(&ct_res);
        let clear_res = signed_sub_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

pub(crate) fn default_overflowing_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i64), (SignedRadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<i64>)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<_>)| {
            lhs.overflowing_scalar_sub(rhs.clear())
        });
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_overflowing_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i8), (SignedRadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        // Only fixed_cases: default_overflowing_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<_>)| {
            lhs.overflowing_scalar_sub(rhs.clear())
        });
}

pub(crate) fn signed_unchecked_left_scalar_sub_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(i64, &'a SignedRadixCiphertext), SignedRadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::thread_rng();

    executor.setup(&cks, sks.clone());

    let cks: crate::integer::ClientKey = cks.into();

    for num_blocks in 1..MAX_NB_CTXT {
        // message_modulus^vec_length
        let modulus = (cks.parameters().message_modulus().0.pow(num_blocks as u32) / 2) as i64;
        if modulus <= 1 {
            continue;
        }

        for _ in 0..nb_tests {
            let clear_lhs = rng.gen::<i64>() % modulus;
            let mut clear_rhs = rng.gen::<i64>() % modulus;

            let mut ct_rhs = cks.encrypt_signed_radix(clear_rhs, num_blocks);

            ct_rhs = executor.execute((clear_lhs, &ct_rhs));
            clear_rhs = signed_sub_under_modulus(clear_lhs, clear_rhs, modulus);

            let dec_res: i64 = cks.decrypt_signed_radix(&ct_rhs);
            assert_eq!(dec_res, clear_rhs);

            let mut clear_lhs = rng.gen::<i64>() % modulus;
            while sks.is_left_scalar_sub_possible(clear_lhs, &ct_rhs).is_ok() {
                ct_rhs = executor.execute((clear_lhs, &ct_rhs));
                clear_rhs = signed_sub_under_modulus(clear_lhs, clear_rhs, modulus);
                let dec_res: i64 = cks.decrypt_signed_radix(&ct_rhs);
                assert_eq!(dec_res, clear_rhs);
                clear_lhs = rng.gen::<i64>() % modulus;
            }
        }
    }
}
