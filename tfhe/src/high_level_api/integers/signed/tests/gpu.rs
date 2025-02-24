use crate::high_level_api::integers::signed::tests::{
    test_case_ilog2, test_case_leading_trailing_zeros_ones,
};
use crate::shortint::parameters::PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;

#[test]
fn test_int32_compare() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    super::test_case_int32_compare(&client_key);
}

#[test]
fn test_int32_bitwise() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    super::test_case_int32_bitwise(&client_key);
}

#[test]
fn test_int64_rotate() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    super::test_case_int64_rotate(&client_key);
}

#[test]
fn test_integer_casting() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    super::test_case_integer_casting(&client_key);
}

#[test]
fn test_if_then_else() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_abs() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    super::test_case_abs(&client_key);
}

#[test]
fn test_ilog2() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    test_case_ilog2(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones() {
    let client_key = crate::high_level_api::integers::unsigned::tests::gpu::setup_gpu(Some(
        PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    ));
    test_case_leading_trailing_zeros_ones(&client_key);
}
