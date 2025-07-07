use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_ilog2::{
    default_checked_ilog2_test, default_ilog2_test, default_leading_ones_test,
    default_leading_zeros_test, default_trailing_ones_test, default_trailing_zeros_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_default_trailing_zeros);
create_gpu_parameterized_test!(integer_default_trailing_ones);
create_gpu_parameterized_test!(integer_default_leading_zeros);
create_gpu_parameterized_test!(integer_default_leading_ones);
create_gpu_parameterized_test!(integer_default_ilog2 {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_default_checked_ilog2);

fn integer_default_trailing_zeros<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trailing_zeros);
    default_trailing_zeros_test(param, executor);
}

fn integer_default_trailing_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::trailing_ones);
    default_trailing_ones_test(param, executor);
}

fn integer_default_leading_zeros<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::leading_zeros);
    default_leading_zeros_test(param, executor);
}

fn integer_default_leading_ones<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::leading_ones);
    default_leading_ones_test(param, executor);
}

fn integer_default_ilog2<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::ilog2);
    default_ilog2_test(param, executor);
}

fn integer_default_checked_ilog2<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::checked_ilog2);
    default_checked_ilog2_test(param, executor);
}
