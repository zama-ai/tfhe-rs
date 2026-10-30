use crate::integer::server_key::radix_parallel::test_harness::{
    scalar_shift_amount_fixed_cases, ExecuteOn, ShiftAmount, ShiftAmountOperand, TestBuilder,
    TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    unchecked_scalar_left_shift_test, unchecked_scalar_right_shift_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_unchecked_scalar_left_shift);
create_parameterized_test!(integer_default_scalar_left_shift);
create_parameterized_test!(integer_unchecked_scalar_right_shift);
create_parameterized_test!(integer_default_scalar_right_shift);

fn integer_default_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_left_shift_test(&ctx, executor);
}

pub(crate) fn default_scalar_left_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, ShiftAmountOperand<u128>), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(scalar_shift_amount_fixed_cases::<Uint, u128>)
        .execute(executor, |(lhs, amount): (Uint, ShiftAmount<u128>)| {
            lhs.shl(amount.value())
        });
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift_parallelized);
    unchecked_scalar_left_shift_test(param, executor);
}

fn integer_default_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_right_shift_test(&ctx, executor);
}

pub(crate) fn default_scalar_right_shift_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, ShiftAmountOperand<u128>), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(scalar_shift_amount_fixed_cases::<Uint, u128>)
        .execute(executor, |(lhs, amount): (Uint, ShiftAmount<u128>)| {
            lhs.shr(amount.value())
        });
}

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift_parallelized);
    unchecked_scalar_right_shift_test(param, executor);
}
