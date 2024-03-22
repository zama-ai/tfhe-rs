use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parametrized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_sub_test, unchecked_sub_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_sub::default_overflowing_sub_test;
use crate::shortint::parameters::*;

create_gpu_parametrized_test!(integer_unchecked_sub);
create_gpu_parametrized_test!(integer_sub);
create_gpu_parametrized_test!(integer_default_overflowing_sub);

fn integer_unchecked_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_sub);
    unchecked_sub_test(param, executor);
}

fn integer_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::sub);
    default_sub_test(param, executor);
}

fn integer_default_overflowing_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_sub);
    default_overflowing_sub_test(param, executor);
}
