use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_count_zeros_ones::{
    extensive_trivial_signed_default_count_zeros_ones_test, signed_default_count_zeros_ones_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_signed_default_count_zeros_ones {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

create_gpu_parameterized_test!(integer_extensive_trivial_signed_default_count_zeros_ones {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_signed_default_count_zeros_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let count_zeros_executor = GpuFunctionExecutor::new(&CudaServerKey::count_zeros);
    let count_ones_executor = GpuFunctionExecutor::new(&CudaServerKey::count_ones);
    signed_default_count_zeros_ones_test(param, count_zeros_executor, count_ones_executor);
}

fn integer_extensive_trivial_signed_default_count_zeros_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let count_zeros_executor = GpuFunctionExecutor::new(&CudaServerKey::count_zeros);
    let count_ones_executor = GpuFunctionExecutor::new(&CudaServerKey::count_ones);
    extensive_trivial_signed_default_count_zeros_ones_test(
        param,
        count_zeros_executor,
        count_ones_executor,
    );
}
