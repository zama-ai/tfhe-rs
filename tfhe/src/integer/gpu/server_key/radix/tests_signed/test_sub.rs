use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_sub::{
    signed_default_overflowing_sub_test, signed_default_sub_test,
    signed_unchecked_overflowing_sub_test, signed_unchecked_sub_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_sub);
create_gpu_parameterized_test!(integer_sub);

create_gpu_parameterized_test!(integer_unchecked_signed_overflowing_sub {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_signed_overflowing_sub {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_unchecked_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_sub);
    signed_unchecked_sub_test(param, executor);
}

fn integer_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::sub);
    signed_default_sub_test(param, executor);
}

fn integer_unchecked_signed_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_signed_overflowing_sub);
    signed_unchecked_overflowing_sub_test(param, executor);
}

fn integer_signed_overflowing_sub<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::signed_overflowing_sub);
    signed_default_overflowing_sub_test(param, executor);
}
