use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_signed::{
    signed_default_scalar_bitand_test, signed_default_scalar_bitor_test,
    signed_default_scalar_bitxor_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_signed_default_scalar_bitand);
create_gpu_parametrized_test!(integer_signed_default_scalar_bitor);
create_gpu_parametrized_test!(integer_signed_default_scalar_bitxor);

fn integer_signed_default_scalar_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitand);
    signed_default_scalar_bitand_test(param, executor);
}

fn integer_signed_default_scalar_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitor);
    signed_default_scalar_bitor_test(param, executor);
}

fn integer_signed_default_scalar_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_bitxor);
    signed_default_scalar_bitxor_test(param, executor);
}
