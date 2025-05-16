use crate::high_level_api::integers::signed::tests::{
    test_case_ilog2, test_case_leading_trailing_zeros_ones,
};
use crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu;
use crate::high_level_api::traits::AddSizeOnGpu;
use crate::prelude::{
    check_valid_cuda_malloc, BitAndSizeOnGpu, BitNotSizeOnGpu, BitOrSizeOnGpu, BitXorSizeOnGpu,
    FheTryEncrypt, SubSizeOnGpu,
};
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
fn test_gpu_get_add_sub_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=i32::MAX);
    let clear_b = rng.gen_range(1..=i32::MAX);
    let mut a = FheInt32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheInt32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();
    let a = &a;
    let b = &b;

    let add_tmp_buffer_size = a.get_add_size_on_gpu(b);
    let sub_tmp_buffer_size = a.get_sub_size_on_gpu(b);
    let scalar_add_tmp_buffer_size = clear_a.get_add_size_on_gpu(b);
    let scalar_sub_tmp_buffer_size = clear_a.get_sub_size_on_gpu(b);
    assert!(check_valid_cuda_malloc(
        add_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert!(check_valid_cuda_malloc(
        sub_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert!(check_valid_cuda_malloc(
        scalar_add_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert!(check_valid_cuda_malloc(
        scalar_sub_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert_eq!(add_tmp_buffer_size, sub_tmp_buffer_size);
    assert_eq!(add_tmp_buffer_size, scalar_add_tmp_buffer_size);
    assert_eq!(add_tmp_buffer_size, scalar_sub_tmp_buffer_size);
}

#[test]
fn test_gpu_get_bitops_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=i32::MAX);
    let clear_b = rng.gen_range(1..=i32::MAX);
    let mut a = FheInt32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheInt32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();
    let a = &a;
    let b = &b;

    let bitand_tmp_buffer_size = a.get_bitand_size_on_gpu(b);
    let scalar_bitand_tmp_buffer_size = clear_a.get_bitand_size_on_gpu(b);
    assert!(check_valid_cuda_malloc(
        bitand_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert!(check_valid_cuda_malloc(
        scalar_bitand_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    let bitor_tmp_buffer_size = a.get_bitor_size_on_gpu(b);
    let scalar_bitor_tmp_buffer_size = clear_a.get_bitor_size_on_gpu(b);
    assert!(check_valid_cuda_malloc(
        bitor_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert!(check_valid_cuda_malloc(
        scalar_bitor_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    let bitxor_tmp_buffer_size = a.get_bitxor_size_on_gpu(b);
    let scalar_bitxor_tmp_buffer_size = clear_a.get_bitxor_size_on_gpu(b);
    assert!(check_valid_cuda_malloc(
        bitxor_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    assert!(check_valid_cuda_malloc(
        scalar_bitxor_tmp_buffer_size,
        GpuIndex::new(0)
    ));
    let bitnot_tmp_buffer_size = a.get_bitnot_size_on_gpu();
    assert!(check_valid_cuda_malloc(
        bitnot_tmp_buffer_size,
        GpuIndex::new(0)
    ));
}
