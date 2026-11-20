use super::legacy_default_tests::legacy_default_if_then_else_test;
use crate::core_crypto::gpu::get_number_of_gpus;
use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_if_then_else);
create_gpu_parameterized_test!(multi_device_integer_if_then_else);

fn integer_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::if_then_else);
    legacy_default_if_then_else_test(param, executor);
}
fn multi_device_integer_if_then_else<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);
    let num_gpus = get_number_of_gpus();
    if num_gpus > 1 {
        legacy_default_if_then_else_test(param, executor);
    }
}
