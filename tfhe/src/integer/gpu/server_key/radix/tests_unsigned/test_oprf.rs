use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_oprf::{
    oprf_almost_uniformity_test, oprf_any_range_test, oprf_uniformity_test,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(oprf_uniformity_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_gpu_parameterized_test!(oprf_any_range_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
create_gpu_parameterized_test!(oprf_almost_uniformity_unsigned {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn oprf_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_unsigned_integer_bounded,
    );
    oprf_uniformity_test(param, executor);
}

fn oprf_any_range_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );
    oprf_any_range_test(param, executor);
}

fn oprf_almost_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_unsigned_custom_range,
    );
    oprf_almost_uniformity_test(param, executor);
}
