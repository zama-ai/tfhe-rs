use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_bitonic_sort::{
    signed_default_bitonic_sort_test, signed_unchecked_bitonic_sort_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_unchecked_bitonic_sort);
create_gpu_parameterized_test!(integer_signed_bitonic_sort);

fn integer_signed_unchecked_bitonic_sort<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitonic_sort);
    signed_unchecked_bitonic_sort_test(param, executor);
}

fn integer_signed_bitonic_sort<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitonic_sort);
    signed_default_bitonic_sort_test(param, executor);
}
