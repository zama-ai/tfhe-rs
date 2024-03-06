use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_mul_test, unchecked_mul_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_mul);
create_gpu_parametrized_test!(integer_mul);

fn integer_unchecked_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_mul);
    unchecked_mul_test(param, executor);
}

fn integer_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::mul);
    default_mul_test(param, executor);
}
