use super::legacy_default_tests::{
    legacy_signed_default_overflowing_sub_test, legacy_signed_default_sub_test,
};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_sub::{
    signed_unchecked_overflowing_sub_test, signed_unchecked_sub_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_sub);
create_gpu_parameterized_test!(integer_sub);

create_gpu_parameterized_test!(integer_unchecked_signed_overflowing_sub);
create_gpu_parameterized_test!(integer_signed_overflowing_sub);

fn integer_unchecked_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_sub);
    signed_unchecked_sub_test(param, executor);
}

fn integer_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::sub);
    legacy_signed_default_sub_test(param, executor);
}

fn integer_unchecked_signed_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_signed_overflowing_sub);
    signed_unchecked_overflowing_sub_test(param, executor);
}

fn integer_signed_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::signed_overflowing_sub);
    legacy_signed_default_overflowing_sub_test(param, executor);
}
