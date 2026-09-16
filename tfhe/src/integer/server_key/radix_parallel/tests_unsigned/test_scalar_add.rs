use crate::integer::server_key::radix_parallel::test_harness::{
    default_scalar_fixed_cases, ExecuteOn, TestBuilder, TestContext, TestScalar,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_add_test, smart_scalar_add_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{RadixCiphertext, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_parameterized_test!(integer_smart_scalar_add);
create_parameterized_test!(integer_default_scalar_add);
create_parameterized_test!(integer_default_overflowing_scalar_add);

fn integer_smart_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_add_parallelized);
    smart_scalar_add_test(param, executor);
}

fn integer_default_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_scalar_add_test(&ctx, executor);
}

pub(crate) fn default_scalar_add_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext, u64), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(default_scalar_fixed_cases::<u64>)
        .execute(executor, |(lhs, rhs): (Uint, TestScalar<u64>)| {
            // The scalar is reduced to the radix width
            lhs.wrapping_add(rhs.cast(lhs.bits()))
        });
}

fn integer_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized);
    default_overflowing_scalar_add_test(param, executor);
}
