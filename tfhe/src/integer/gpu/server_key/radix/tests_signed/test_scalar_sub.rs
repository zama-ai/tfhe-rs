use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_sub::signed_unchecked_scalar_sub_test;
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_signed_unchecked_scalar_sub);

fn integer_signed_unchecked_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_sub);
    signed_unchecked_scalar_sub_test(param, executor);
}
