use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_overflowing_scalar_add_test, default_scalar_add_test, unchecked_scalar_add_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_scalar_add);
create_gpu_parameterized_test!(integer_scalar_add);
create_gpu_parameterized_test!(integer_default_overflowing_scalar_add);
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
    default_scalar_add_test(param, executor);
}

fn integer_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_scalar_add);
    default_overflowing_scalar_add_test(param, executor);
}
