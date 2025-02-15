use crate::integer::gpu::server_key::radix::tests_long_run::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_long_run::test_signed_erc20::{
    signed_no_cmux_erc20_test, signed_whitepaper_erc20_test,
};
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(signed_whitepaper_erc20 {
    // TODO GPU DRIFT UPDATE
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
});
create_gpu_parameterized_test!(signed_no_cmux_erc20 {
    // TODO GPU DRIFT UPDATE
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64
});

fn signed_whitepaper_erc20<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let ge_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ge);
    let add_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let if_then_else_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::if_then_else);
    let sub_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    signed_whitepaper_erc20_test(
        param,
        ge_executor,
        add_executor,
        if_then_else_executor,
        sub_executor,
    );
}

fn signed_no_cmux_erc20<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let ge_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::ge);
    let mul_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::mul);
    let add_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let sub_executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::sub);
    signed_no_cmux_erc20_test(param, ge_executor, mul_executor, add_executor, sub_executor);
}
