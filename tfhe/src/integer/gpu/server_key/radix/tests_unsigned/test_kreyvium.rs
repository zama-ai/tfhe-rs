use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kreyvium::{
    kreyvium_comparison_test, kreyvium_test_vector_1_test,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(integer_kreyvium_test_vector_1 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_kreyvium_comparison {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn integer_kreyvium_test_vector_1<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::kreyvium_generate_keystream);
    kreyvium_test_vector_1_test(param, executor);
}

fn integer_kreyvium_comparison<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::kreyvium_generate_keystream);
    kreyvium_comparison_test(param, executor);
}
