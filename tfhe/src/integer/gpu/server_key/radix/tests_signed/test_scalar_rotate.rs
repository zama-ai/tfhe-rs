use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_scalar_rotate::{
    signed_default_scalar_rotate_left_test, signed_default_scalar_rotate_right_test,
    signed_unchecked_scalar_rotate_left_test, signed_unchecked_scalar_rotate_right_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_scalar_rotate_left);
create_gpu_parameterized_test!(integer_signed_scalar_rotate_left);
create_gpu_parameterized_test!(integer_signed_unchecked_scalar_rotate_right);
create_gpu_parameterized_test!(integer_signed_scalar_rotate_right);

fn integer_signed_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_rotate_left);
    signed_unchecked_scalar_rotate_left_test(param, executor);
}

fn integer_signed_scalar_rotate_left<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_rotate_left);
    signed_default_scalar_rotate_left_test(param, executor);
}

fn integer_signed_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_rotate_right);
    signed_unchecked_scalar_rotate_right_test(param, executor);
}

fn integer_signed_scalar_rotate_right<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_rotate_right);
    signed_default_scalar_rotate_right_test(param, executor);
}
