use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_scalar_rotate::{
    default_scalar_rotate_left_test, default_scalar_rotate_right_test,
    unchecked_scalar_rotate_left_test, unchecked_scalar_rotate_right_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_scalar_rotate_left);
create_gpu_parameterized_test!(integer_unchecked_scalar_rotate_right);
create_gpu_parameterized_test!(integer_scalar_rotate_left);
create_gpu_parameterized_test!(integer_scalar_rotate_right);

fn integer_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_rotate_right);
    unchecked_scalar_rotate_right_test(param, executor);
}

fn integer_scalar_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_rotate_right);
    default_scalar_rotate_right_test(param, executor);
}

fn integer_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_rotate_left);
    unchecked_scalar_rotate_left_test(param, executor);
}

fn integer_scalar_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_rotate_left);
    default_scalar_rotate_left_test(param, executor);
}
