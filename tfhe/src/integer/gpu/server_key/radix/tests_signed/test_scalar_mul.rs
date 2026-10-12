use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_mul::{
    signed_unchecked_scalar_mul_corner_cases_test, signed_unchecked_scalar_mul_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_scalar_mul);
create_gpu_parameterized_test!(integer_signed_unchecked_scalar_mul_corner_cases);

fn integer_signed_unchecked_scalar_mul<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_mul);
    signed_unchecked_scalar_mul_test(param, executor);
}

fn integer_signed_unchecked_scalar_mul_corner_cases<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_mul);
    signed_unchecked_scalar_mul_corner_cases_test(param, executor);
}
