use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_bitonic_sort_test, unchecked_bitonic_sort_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_bitonic_sort);
create_gpu_parameterized_test!(integer_bitonic_sort);

fn integer_unchecked_bitonic_sort<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitonic_sort);
    unchecked_bitonic_sort_test(param, executor);
}

fn integer_bitonic_sort<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitonic_sort);
    default_bitonic_sort_test(param, executor);
}
