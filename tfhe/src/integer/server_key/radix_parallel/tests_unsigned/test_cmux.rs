use crate::integer::prelude::*;
use crate::integer::server_key::radix_parallel::test_harness::{
    condition_radix_pair_fixed_cases, condition_radix_scalar_fixed_cases,
    condition_scalar_radix_fixed_cases, scalar_if_then_else_fixed_cases, ExecuteOn, NumBlocks,
    TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_default_if_then_else);
create_parameterized_test!(integer_default_left_scalar_if_then_else);
create_parameterized_test!(integer_default_right_scalar_if_then_else);
create_parameterized_test!(integer_default_scalar_if_then_else);
create_parameterized_test!(integer_default_flip);
create_parameterized_test!(integer_default_left_scalar_flip);
create_parameterized_test!(integer_default_right_scalar_flip);

fn integer_default_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func =
        |sks: &ServerKey, cond: &BooleanBlock, lhs: &RadixCiphertext, rhs: &RadixCiphertext| {
            sks.if_then_else_parallelized(cond, lhs, rhs)
        };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_if_then_else_test(&ctx, executor);
}

pub(crate) fn default_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, RadixCiphertext, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_pair_fixed_cases::<Uint>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Uint, Uint)| {
                if cond {
                    lhs
                } else {
                    rhs
                }
            },
        );
}

fn integer_default_left_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: u64, rhs: &RadixCiphertext| {
        sks.if_then_else_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_left_scalar_if_then_else_test(&ctx, executor);
}

pub(crate) fn default_left_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, u64, RadixCiphertext), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_scalar_radix_fixed_cases::<u64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, TestScalar<u64>, Uint)| {
                // The scalar bits past the radix width are dropped
                if cond {
                    lhs.cast(rhs.bits())
                } else {
                    rhs
                }
            },
        );
}

fn integer_default_right_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: &RadixCiphertext, rhs: u64| {
        sks.if_then_else_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_right_scalar_if_then_else_test(&ctx, executor);
}

pub(crate) fn default_right_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_scalar_fixed_cases::<u64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Uint, TestScalar<u64>)| {
                if cond {
                    lhs
                } else {
                    rhs.cast(lhs.bits())
                }
            },
        );
}

fn integer_default_scalar_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: u64, rhs: u64, num_blocks: usize| {
        sks.scalar_if_then_else_parallelized(cond, lhs, rhs, num_blocks)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_if_then_else_test(&ctx, executor);
}

pub(crate) fn default_scalar_if_then_else_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, u64, u64, usize), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(scalar_if_then_else_fixed_cases::<u64>)
        .execute(
            executor,
            |(cond, lhs, rhs, num_blocks): (bool, TestScalar<u64>, TestScalar<u64>, NumBlocks)| {
                if cond {
                    lhs.cast(num_blocks.bits())
                } else {
                    rhs.cast(num_blocks.bits())
                }
            },
        );
}

fn integer_default_flip<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey,
                cond: &BooleanBlock,
                lhs: &RadixCiphertext,
                rhs: &RadixCiphertext| { sks.flip_parallelized(cond, lhs, rhs) };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_flip_test(&ctx, executor);
}

pub(crate) fn default_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<
        (BooleanBlock, RadixCiphertext, RadixCiphertext),
        (RadixCiphertext, RadixCiphertext),
    >,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_pair_fixed_cases::<Uint>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Uint, Uint)| {
                if cond {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}

fn integer_default_left_scalar_flip<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: u64, rhs: &RadixCiphertext| {
        sks.flip_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_left_scalar_flip_test(&ctx, executor);
}

pub(crate) fn default_left_scalar_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, u64, RadixCiphertext), (RadixCiphertext, RadixCiphertext)>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_scalar_radix_fixed_cases::<u64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, TestScalar<u64>, Uint)| {
                let lhs = lhs.cast(rhs.bits());
                if cond {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}

fn integer_default_right_scalar_flip<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let func = |sks: &ServerKey, cond: &BooleanBlock, lhs: &RadixCiphertext, rhs: u64| {
        sks.flip_parallelized(cond, lhs, rhs)
    };
    let mut executor = CpuFunctionExecutor::new(&func);
    executor.setup_with_server_key(ctx.server_key());
    default_right_scalar_flip_test(&ctx, executor);
}

pub(crate) fn default_right_scalar_flip_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(BooleanBlock, RadixCiphertext, u64), (RadixCiphertext, RadixCiphertext)>,
{
    TestBuilder::new(ctx)
        .fixed_cases(condition_radix_scalar_fixed_cases::<u64>)
        .execute(
            executor,
            |(cond, lhs, rhs): (bool, Uint, TestScalar<u64>)| {
                let rhs = rhs.cast(lhs.bits());
                if cond {
                    (rhs, lhs)
                } else {
                    (lhs, rhs)
                }
            },
        );
}
