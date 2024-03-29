use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_mul::signed_unchecked_scalar_mul_test;
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_signed_unchecked_scalar_mul);

fn integer_signed_unchecked_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_mul);
    signed_unchecked_scalar_mul_test(param, executor);
}
