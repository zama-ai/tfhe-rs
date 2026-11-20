use std::sync::Arc;

use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, scalar_on_the_left, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    narrow_scalar_cases, narrow_scalar_input_sizes, narrow_signed_scalar_on_unsigned_radix_cases,
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::prelude::*;

use super::{MAX_NB_CTXT, NB_CTXT};

create_parameterized_test!(integer_default_scalar_sub);
create_parameterized_test!(integer_default_scalar_sub_u8);
create_parameterized_test!(integer_default_scalar_sub_i8);
create_parameterized_test!(integer_unchecked_left_scalar_sub);
create_parameterized_test!(integer_default_left_scalar_sub);
create_parameterized_test!(integer_default_left_scalar_sub_u8);
create_parameterized_test!(integer_default_left_scalar_sub_i8);
create_parameterized_test!(integer_default_overflowing_scalar_sub);
create_parameterized_test!(integer_default_overflowing_scalar_sub_u8);

fn integer_default_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_sub_test(&ctx, executor);
}

pub(crate) fn default_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            // The scalar bits past the radix width do not change the result
            lhs.wrapping_sub(rhs.cast(lhs.bits()))
        });
}

fn integer_default_scalar_sub_u8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized::<RadixCiphertext, u8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_scalar_sub_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u8), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u8>)| {
            lhs.wrapping_sub(rhs.cast(lhs.bits()))
        });
}

fn integer_default_scalar_sub_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized::<RadixCiphertext, i8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_signed_scalar_scalar_sub_test(&ctx, executor);
}

/// Only the cases a signed scalar narrower than the radix adds, see
/// [`narrow_signed_scalar_on_unsigned_radix_cases`].
pub(crate) fn narrow_signed_scalar_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, i8), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a signed scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_signed_scalar_on_unsigned_radix_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<i8>)| {
            // The scalar's two's complement bits, sign extended to the radix width
            lhs.wrapping_sub(Uint::new(rhs.clear().value() as u128, lhs.bits()))
        });
}

fn integer_unchecked_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_scalar_sub);
    unchecked_left_scalar_sub_test(param, executor);
}

fn integer_default_left_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::left_scalar_sub_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_left_scalar_sub_test(&ctx, executor);
}

pub(crate) fn default_left_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(u64, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(|input_size, ctx| {
            scalar_on_the_left(default_scalar_fixed_cases::<u64>(input_size, ctx))
        })
        .execute(executor, |(lhs, rhs): (TestScalar<u64>, Uint)| {
            lhs.cast(rhs.bits()).wrapping_sub(rhs)
        });
}

fn integer_default_left_scalar_sub_u8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::left_scalar_sub_parallelized::<u8, RadixCiphertext>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_left_scalar_sub_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_left_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(u8, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_left_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(|input_size, ctx| scalar_on_the_left(narrow_scalar_cases(input_size, ctx)))
        .execute(executor, |(lhs, rhs): (TestScalar<u8>, Uint)| {
            lhs.cast(rhs.bits()).wrapping_sub(rhs)
        });
}

fn integer_default_left_scalar_sub_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::left_scalar_sub_parallelized::<i8, RadixCiphertext>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_signed_scalar_left_scalar_sub_test(&ctx, executor);
}

/// Only the cases a signed scalar narrower than the radix adds, see
/// [`narrow_signed_scalar_on_unsigned_radix_cases`].
pub(crate) fn narrow_signed_scalar_left_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(i8, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_left_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a signed scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(|input_size, ctx| {
            scalar_on_the_left(narrow_signed_scalar_on_unsigned_radix_cases(
                input_size, ctx,
            ))
        })
        .execute(executor, |(lhs, rhs): (TestScalar<i8>, Uint)| {
            // The scalar's two's complement bits, sign extended to the radix width
            Uint::new(lhs.clear().value() as u128, rhs.bits()).wrapping_sub(rhs)
        });
}

fn integer_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_scalar_sub_test(&ctx, executor);
}

fn integer_default_overflowing_scalar_sub_u8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized::<u8>);
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_overflowing_scalar_sub_test(&ctx, executor);
}

pub(crate) fn default_overflowing_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            lhs.overflowing_scalar_sub(rhs.clear())
        });
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`].
pub(crate) fn narrow_scalar_overflowing_scalar_sub_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u8), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .input_sizes(narrow_scalar_input_sizes(ctx))
        // Only fixed_cases: default_overflowing_scalar_sub_test already draws random inputs,
        // this test only adds the edges of a scalar narrower than the radix
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u8>)| {
            lhs.overflowing_scalar_sub(rhs.clear())
        });
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
