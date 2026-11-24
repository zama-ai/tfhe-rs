use super::legacy_default_tests::legacy_default_scalar_add_test;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::test_harness::TestContext;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_add_test, unchecked_scalar_add_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_scalar_add::{
    default_overflowing_scalar_add_signed_scalar_test, narrow_scalar_overflowing_scalar_add_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_scalar_add);
create_gpu_parameterized_test!(integer_scalar_add);
create_gpu_parameterized_test!(integer_default_overflowing_scalar_add);
create_gpu_parameterized_test!(integer_default_overflowing_scalar_add_u8);
create_gpu_parameterized_test!(integer_default_overflowing_scalar_add_signed_scalar);
fn integer_unchecked_scalar_add<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_add);
    unchecked_scalar_add_test(param, executor);
}

fn integer_scalar_add<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_add);
    legacy_default_scalar_add_test(param, executor);
}

fn integer_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_scalar_add);
    default_overflowing_scalar_add_test(param, executor);
}

fn integer_default_overflowing_scalar_add_u8<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_scalar_add::<u8>);
    executor.setup_with_client_key(ctx.client_key());
    narrow_scalar_overflowing_scalar_add_test(&ctx, executor);
}

/// The unsigned overflowing scalar add also accepts a signed scalar on an unsigned radix.
fn integer_default_overflowing_scalar_add_signed_scalar<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor =
        GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_scalar_add::<i64>);
    executor.setup_with_client_key(ctx.client_key());
    default_overflowing_scalar_add_signed_scalar_test(&ctx, executor);
}
