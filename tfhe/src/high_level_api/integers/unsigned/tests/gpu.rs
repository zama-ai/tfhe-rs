use crate::high_level_api::traits::AddAssignSizeOnGpu;
use crate::prelude::{check_valid_cuda_malloc, FheTryEncrypt};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
};
use crate::shortint::ClassicPBSParameters;
use crate::{set_server_key, ClientKey, ConfigBuilder, FheUint32, GpuIndex};
use rand::Rng;

/// GPU setup for tests
///
/// Crates a client key, with the given parameters or default params in None were given
/// and sets the gpu server key for the current thread
pub(crate) fn setup_gpu(params: Option<impl Into<TestParameters>>) -> ClientKey {
    let config = params
        .map_or_else(ConfigBuilder::default, |p| {
            ConfigBuilder::with_custom_parameters(p.into())
        })
        .build();

    let client_key = ClientKey::generate(config);
    let csks = crate::CompressedServerKey::new(&client_key);
    let server_key = csks.decompress_to_gpu();

    set_server_key(server_key);

    client_key
}

fn setup_default_gpu() -> ClientKey {
    setup_gpu(Option::<ClassicPBSParameters>::None)
}

#[test]
fn test_uint8_quickstart_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint8_quickstart(&client_key);
}

#[test]
fn test_uint8_quickstart_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_uint8_quickstart(&client_key);
}

#[test]
fn test_uint32_quickstart_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint32_quickstart(&client_key);
}

#[test]
fn test_uint32_quickstart_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_uint32_quickstart(&client_key);
}

#[test]
fn test_uint64_quickstart_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint64_quickstart(&client_key);
}

#[test]
fn test_uint64_quickstart_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_uint64_quickstart(&client_key);
}

#[test]
fn test_trivial_uint8_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint8_trivial(&client_key);
}

#[test]
fn test_trivial_uint256_small_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint256_trivial(&client_key);
}

#[test]
fn test_uint32_bitwise_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint32_bitwise(&client_key);
}

#[test]
fn test_uint32_bitwise_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_uint32_bitwise(&client_key);
}

#[test]
fn test_uint32_scalar_bitwise_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_uint32_scalar_bitwise(&client_key);
}

#[test]
fn test_uint32_scalar_bitwise_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_uint32_scalar_bitwise(&client_key);
}

#[test]
fn test_if_then_else_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_if_then_else_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_if_then_else(&client_key);
}

#[test]
fn test_sum_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_sum(&client_key);
}

#[test]
fn test_sum_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_sum(&client_key);
}

#[test]
fn test_is_even_is_odd_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_is_even_is_odd(&client_key);
}

#[test]
fn test_is_even_is_odd_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_is_even_is_odd(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_leading_trailing_zeros_ones_gpu_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_leading_trailing_zeros_ones(&client_key);
}

#[test]
fn test_ilog2_gpu() {
    let client_key = setup_default_gpu();
    super::test_case_ilog2(&client_key);
}

#[test]
fn test_ilog2_multibit() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_ilog2(&client_key);
}

#[test]
fn test_gpu_get_add_assign_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();

    let tmp_buffer_size = a.get_add_assign_size_on_gpu(b);
    assert!(check_valid_cuda_malloc(tmp_buffer_size, GpuIndex::new(0)));
}
