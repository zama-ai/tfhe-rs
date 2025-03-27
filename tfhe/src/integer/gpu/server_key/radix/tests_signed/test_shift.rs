use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_shift::{
    signed_default_left_shift_test, signed_default_right_shift_test,
    signed_unchecked_left_shift_test, signed_unchecked_right_shift_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_left_shift);
create_gpu_parameterized_test!(integer_signed_unchecked_right_shift);
create_gpu_parameterized_test!(integer_signed_left_shift);
create_gpu_parameterized_test!(integer_signed_right_shift);

fn integer_signed_unchecked_right_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_right_shift);
    signed_unchecked_right_shift_test(param, executor);
}

fn integer_signed_right_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::right_shift);
    signed_default_right_shift_test(param, executor);
}

fn integer_signed_unchecked_left_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_left_shift);
    signed_unchecked_left_shift_test(param, executor);
}

fn integer_signed_left_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::left_shift);
    signed_default_left_shift_test(param, executor);
}
