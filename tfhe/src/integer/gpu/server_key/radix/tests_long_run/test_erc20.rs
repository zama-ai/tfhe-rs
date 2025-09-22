use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_long_run::test_erc20::{
    no_cmux_erc20_test, safe_erc20_test, whitepaper_erc20_test,
};
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(safe_erc20 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_gpu_parameterized_test!(whitepaper_erc20 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_gpu_parameterized_test!(no_cmux_erc20 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn safe_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let overflowing_add_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    let overflowing_sub_executor =
        GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_sub);
    let if_then_else_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);
    let bitwise_or_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::bitor);
    safe_erc20_test(
        param,
        overflowing_add_executor,
        overflowing_sub_executor,
        if_then_else_executor,
        bitwise_or_executor,
    );
}

fn whitepaper_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ge_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ge);
    let add_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let if_then_else_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);
    let sub_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    whitepaper_erc20_test(
        param,
        ge_executor,
        add_executor,
        if_then_else_executor,
        sub_executor,
    );
}

fn no_cmux_erc20<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ge_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ge);
    let mul_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::mul);
    let add_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let sub_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    no_cmux_erc20_test(param, ge_executor, mul_executor, add_executor, sub_executor);
}
