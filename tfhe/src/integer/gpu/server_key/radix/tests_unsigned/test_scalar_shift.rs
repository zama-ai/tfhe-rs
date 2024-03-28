use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_left_shift_test, default_scalar_right_shift_test,
    unchecked_scalar_left_shift_test, unchecked_scalar_right_shift_test,
};
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_scalar_left_shift);
create_gpu_parametrized_test!(integer_unchecked_scalar_right_shift);
create_gpu_parametrized_test!(integer_scalar_left_shift);
create_gpu_parametrized_test!(integer_scalar_right_shift);

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_right_shift);
    unchecked_scalar_right_shift_test(param, executor);
}

fn integer_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_right_shift);
    default_scalar_right_shift_test(param, executor);
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_scalar_left_shift);
    unchecked_scalar_left_shift_test(param, executor);
}

fn integer_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::scalar_left_shift);
    default_scalar_left_shift_test(param, executor);
}
