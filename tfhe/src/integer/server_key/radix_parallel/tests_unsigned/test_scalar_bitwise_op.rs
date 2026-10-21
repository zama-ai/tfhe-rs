use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_default_scalar_bitand);
create_parameterized_test!(integer_default_scalar_bitor);
create_parameterized_test!(integer_default_scalar_bitxor);

fn integer_default_scalar_bitand<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_bitand_test(&ctx, executor);
}

pub(crate) fn default_scalar_bitand_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            // The scalar bits past the radix width have nothing to apply to
            lhs.bitand(rhs.cast(lhs.bits()))
        });
}

fn integer_default_scalar_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_bitor_test(&ctx, executor);
}

pub(crate) fn default_scalar_bitor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            lhs.bitor(rhs.cast(lhs.bits()))
        });
}

fn integer_default_scalar_bitxor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_bitxor_test(&ctx, executor);
}

pub(crate) fn default_scalar_bitxor_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            lhs.bitxor(rhs.cast(lhs.bits()))
        });
}
