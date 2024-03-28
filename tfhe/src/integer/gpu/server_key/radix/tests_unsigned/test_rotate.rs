use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_rotate_left_test, default_rotate_right_test, unchecked_rotate_left_test,
    unchecked_rotate_right_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_rotate_left);
create_gpu_parametrized_test!(integer_unchecked_rotate_right);
create_gpu_parametrized_test!(integer_rotate_left);
create_gpu_parametrized_test!(integer_rotate_right);

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_rotate_right);
    unchecked_rotate_right_test(param, executor);
}

fn integer_rotate_right<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rotate_right);
    default_rotate_right_test(param, executor);
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_rotate_left);
    unchecked_rotate_left_test(param, executor);
}

fn integer_rotate_left<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rotate_left);
    default_rotate_left_test(param, executor);
}
