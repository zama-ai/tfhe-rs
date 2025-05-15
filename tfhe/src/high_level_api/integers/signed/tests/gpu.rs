use crate::high_level_api::integers::signed::tests::{
    test_case_ilog2, test_case_leading_trailing_zeros_ones,
};
use crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu;
use crate::high_level_api::traits::AddAssignSizeOnGpu;
use crate::prelude::{check_valid_cuda_malloc, FheTryEncrypt};
use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS;
use crate::{FheInt32, GpuIndex};
use rand::Rng;

#[test]
fn test_int32_compare() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    super::test_case_int32_compare(&client_key);
}

#[test]
fn test_int32_bitwise() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    super::test_case_int32_bitwise(&client_key);
}

#[test]
fn test_int64_rotate() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    super::test_case_int64_rotate(&client_key);
}

#[test]
fn test_integer_casting() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    super::test_case_integer_casting(&client_key);
}

#[test]
fn test_if_then_else() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_abs() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    super::test_case_abs(&client_key);
}

#[test]
fn test_ilog2() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    test_case_ilog2(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
    ));
    test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_gpu_get_add_assign_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::rng();
    let clear_a = rng.random_range(1..=i32::MAX);
    let clear_b = rng.random_range(1..=i32::MAX);
    let mut a = FheInt32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheInt32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();

    let tmp_buffer_size = a.get_add_assign_size_on_gpu(b);
    assert!(check_valid_cuda_malloc(tmp_buffer_size, GpuIndex::new(0)));
}
