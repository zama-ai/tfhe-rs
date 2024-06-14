use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_div_mod::signed_unchecked_scalar_div_rem_test;
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_signed_unchecked_scalar_div_rem);

fn integer_signed_unchecked_scalar_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::signed_scalar_div_rem);
    signed_unchecked_scalar_div_rem_test(param, executor);
}
