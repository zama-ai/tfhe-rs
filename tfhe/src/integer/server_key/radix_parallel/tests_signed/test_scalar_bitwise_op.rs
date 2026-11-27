use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_signed::narrow_scalar_cases;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::int::Int;
use crate::integer::{ServerKey, SignedRadixCiphertext};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_signed_default_scalar_bitand);
create_parameterized_test!(integer_signed_default_scalar_bitor);
create_parameterized_test!(integer_signed_default_scalar_bitxor);
create_parameterized_test!(integer_signed_default_scalar_bitand_narrow_i8);
create_parameterized_test!(integer_signed_default_scalar_bitor_narrow_i8);
create_parameterized_test!(integer_signed_default_scalar_bitxor_narrow_i8);

fn integer_signed_default_scalar_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_bitand_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_bitand_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<i64>)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i64>)| {
            // The scalar is applied as its two's complement bits on the radix width
            lhs.bitand(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_scalar_bitand_narrow_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::scalar_bitand_parallelized::<SignedRadixCiphertext, i8>,
    );
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_bitand_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`]: a
/// negative scalar is sign extended over the radix width.
pub(crate) fn narrow_scalar_bitand_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i8), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i8>)| {
            lhs.bitand(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_scalar_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_bitor_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_bitor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<i64>)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i64>)| {
            // The scalar is applied as its two's complement bits on the radix width
            lhs.bitor(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_scalar_bitor_narrow_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::scalar_bitor_parallelized::<SignedRadixCiphertext, i8>,
    );
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_bitor_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`]: a
/// negative scalar is sign extended over the radix width.
pub(crate) fn narrow_scalar_bitor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i8), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i8>)| {
            lhs.bitor(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_scalar_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    signed_default_scalar_bitxor_test(&ctx, executor);
}

pub(crate) fn signed_default_scalar_bitxor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i64), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<i64>)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i64>)| {
            // The scalar is applied as its two's complement bits on the radix width
            lhs.bitxor(rhs.cast(lhs.bits()))
        });
}

fn integer_signed_default_scalar_bitxor_narrow_i8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(
        &ServerKey::scalar_bitxor_parallelized::<SignedRadixCiphertext, i8>,
    );
    executor.setup_with_server_key(ctx.server_key());
    narrow_scalar_bitxor_test(&ctx, executor);
}

/// Only the cases a scalar narrower than the radix adds, see [`narrow_scalar_cases`]: a
/// negative scalar is sign extended over the radix width.
pub(crate) fn narrow_scalar_bitxor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(SignedRadixCiphertext, i8), SignedRadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases_only()
        .fixed_cases(narrow_scalar_cases)
        .execute(executor, |(lhs, rhs): (Int, TestScalar<i8>)| {
            lhs.bitxor(rhs.cast(lhs.bits()))
        });
}
