use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_mul_test, unchecked_scalar_mul_corner_cases_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_scalar_mul);
create_gpu_parametrized_test!(integer_scalar_mul);

fn integer_unchecked_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_mul);
    unchecked_scalar_mul_corner_cases_test(param, executor);
}

fn integer_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_mul);
    default_scalar_mul_test(param, executor);
}
