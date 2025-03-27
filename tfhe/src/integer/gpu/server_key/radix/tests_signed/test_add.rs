use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_add::{
    signed_default_add_test, signed_unchecked_add_test, signed_unchecked_overflowing_add_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_add);
create_gpu_parameterized_test!(integer_add);

create_gpu_parameterized_test!(integer_unchecked_signed_overflowing_add);
create_gpu_parameterized_test!(integer_signed_overflowing_add);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    signed_unchecked_add_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    signed_default_add_test(param, executor);
}

fn integer_unchecked_signed_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_signed_overflowing_add);
    signed_unchecked_overflowing_add_test(param, executor);
}

fn integer_signed_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::signed_overflowing_add);
    signed_unchecked_overflowing_add_test(param, executor);
}
