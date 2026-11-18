use super::legacy_default_tests::{
    legacy_default_left_shift_test, legacy_default_right_shift_test,
};
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::{gen_keys_gpu, CudaServerKey};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_shift::{
    unchecked_left_shift_test, unchecked_right_shift_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

// 2_2 goes through the block-level barrel shifter, 3_3 through the bit-level
// one, so both paths of the CUDA backend are covered.
create_gpu_parameterized_test!(integer_unchecked_left_shift {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_unchecked_right_shift {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_default_left_shift {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_default_right_shift {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_shift_and_rotate_assign_of_value_with_carries {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_right_shift);
    unchecked_right_shift_test(param, executor);
}

fn integer_default_right_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::right_shift);
    legacy_default_right_shift_test(param, executor);
}

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_left_shift);
    unchecked_left_shift_test(param, executor);
}

fn integer_default_left_shift<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::left_shift);
    legacy_default_left_shift_test(param, executor);
}

fn integer_shift_and_rotate_assign_of_value_with_carries<P>(param: P)
where
    P: Into<AtomicPatternParameters>,
{
    let streams = CudaStreams::new_multi_gpu();
    let (cks, sks) = gen_keys_gpu(param, &streams);
    let num_blocks = 4;

    let d_three = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.encrypt_radix(3u8, num_blocks),
        &streams,
    );
    let d_one = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
        &cks.encrypt_radix(1u8, num_blocks),
        &streams,
    );
    let d_value_with_carries = sks.unchecked_add(&d_three, &d_one, &streams);

    let mut d_shifted = d_value_with_carries.duplicate(&streams);
    sks.left_shift_assign(&mut d_shifted, &d_one, &streams);
    let shifted: u8 = cks.decrypt_radix(&d_shifted.to_radix_ciphertext(&streams));
    assert_eq!(shifted, 4u8 << 1);

    let mut d_rotated = d_value_with_carries.duplicate(&streams);
    sks.rotate_left_assign(&mut d_rotated, &d_one, &streams);
    let rotated: u8 = cks.decrypt_radix(&d_rotated.to_radix_ciphertext(&streams));
    assert_eq!(rotated, 4u8.rotate_left(1));
}
