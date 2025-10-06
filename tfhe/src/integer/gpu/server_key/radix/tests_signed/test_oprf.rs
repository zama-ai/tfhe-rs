use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_oprf::{
    oprf_uniformity_bounded_test, oprf_uniformity_unbounded_test,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(oprf_signed_uniformity_bounded {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(oprf_signed_uniformity_unbounded {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn oprf_signed_uniformity_bounded<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_signed_integer_bounded,
    );
    oprf_uniformity_bounded_test(param, executor);
}

fn oprf_signed_uniformity_unbounded<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(
        &CudaServerKey::par_generate_oblivious_pseudo_random_signed_integer,
    );
    oprf_uniformity_unbounded_test(param, executor);
}
