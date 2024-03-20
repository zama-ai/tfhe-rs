use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_shift::{
    signed_default_scalar_left_shift_test, signed_default_scalar_right_shift_test,
    signed_unchecked_scalar_left_shift_test, signed_unchecked_scalar_right_shift_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_signed_unchecked_scalar_left_shift);
create_gpu_parametrized_test!(integer_signed_scalar_left_shift);
create_gpu_parametrized_test!(integer_signed_unchecked_scalar_right_shift);
create_gpu_parametrized_test!(integer_signed_scalar_right_shift);

fn integer_signed_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_left_shift);
    signed_unchecked_scalar_left_shift_test(param, executor);
}

fn integer_signed_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_left_shift);
    signed_default_scalar_left_shift_test(param, executor);
}

fn integer_signed_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_right_shift);
    signed_unchecked_scalar_right_shift_test(param, executor);
}

fn integer_signed_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_right_shift);
    signed_default_scalar_right_shift_test(param, executor);
}
