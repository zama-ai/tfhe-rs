use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_trivium::{
    trivium_comparison_test, trivium_test_vector_1_test, trivium_test_vector_2_test,
    trivium_test_vector_3_test, trivium_test_vector_4_test,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

create_gpu_parameterized_test!(integer_trivium_test_vector_1 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_trivium_test_vector_2 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_trivium_test_vector_3 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_trivium_test_vector_4 {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_trivium_comparison {
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});

fn integer_trivium_test_vector_1<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trivium_generate_keystream);
    trivium_test_vector_1_test(param, executor);
}

fn integer_trivium_test_vector_2<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trivium_generate_keystream);
    trivium_test_vector_2_test(param, executor);
}

fn integer_trivium_test_vector_3<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trivium_generate_keystream);
    trivium_test_vector_3_test(param, executor);
}

fn integer_trivium_test_vector_4<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trivium_generate_keystream);
    trivium_test_vector_4_test(param, executor);
}

fn integer_trivium_comparison<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trivium_generate_keystream);
    trivium_comparison_test(param, executor);
}
