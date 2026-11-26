use super::legacy_default_tests::{
    legacy_default_rotate_left_test, legacy_default_rotate_right_test,
    legacy_unchecked_rotate_left_test, legacy_unchecked_rotate_right_test,
};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_rotate::{
    rotate_left_amount_of_another_width_test, rotate_right_amount_of_another_width_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

// 2_2 goes through the block-level barrel shifter, 3_3 through the bit-level
// one, so both paths of the CUDA backend are covered.
create_gpu_parameterized_test!(integer_unchecked_rotate_left {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_unchecked_rotate_right {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_default_rotate_left {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_default_rotate_right {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
});
// The GPU reduces the amount modulo the next power of two of the number of bits, so these
// cases only match the CPU model on widths that are powers of two (2 bits per block).
create_gpu_parameterized_test!(integer_rotate_left_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_rotate_right_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_rotate_left_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rotate_left);
    rotate_left_amount_of_another_width_test(param, executor);
}

fn integer_rotate_right_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rotate_right);
    rotate_right_amount_of_another_width_test(param, executor);
}

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_rotate_right);
    legacy_unchecked_rotate_right_test(param, executor);
}

fn integer_default_rotate_right<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rotate_right);
    legacy_default_rotate_right_test(param, executor);
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_rotate_left);
    legacy_unchecked_rotate_left_test(param, executor);
}

fn integer_default_rotate_left<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::rotate_left);
    legacy_default_rotate_left_test(param, executor);
}
