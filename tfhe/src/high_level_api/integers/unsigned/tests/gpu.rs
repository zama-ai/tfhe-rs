use crate::high_level_api::traits::AddSizeOnGpu;
use crate::prelude::{
    check_valid_cuda_malloc_assert_oom, BitAndSizeOnGpu, BitNotSizeOnGpu, BitOrSizeOnGpu,
    BitXorSizeOnGpu, DivRemSizeOnGpu, DivSizeOnGpu, FheEncrypt, FheEqSizeOnGpu, FheMaxSizeOnGpu,
    FheMinSizeOnGpu, FheOrdSizeOnGpu, FheTryEncrypt, IfThenElseSizeOnGpu, MulSizeOnGpu,
    NegSizeOnGpu, RemSizeOnGpu, RotateLeftSizeOnGpu, RotateRightSizeOnGpu, ShlSizeOnGpu,
    ShrSizeOnGpu, SubSizeOnGpu,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS,
};
use crate::shortint::ClassicPBSParameters;
use crate::{set_server_key, ClientKey, ConfigBuilder, FheBool, FheUint32, GpuIndex};
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
fn test_flip() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_flip(&client_key);
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
fn test_min_max() {
    let client_key = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    super::test_case_min_max(&client_key);
}

#[test]
fn test_gpu_get_add_and_sub_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();

    let a = &a;
    let b = &b;

    let add_tmp_buffer_size = a.get_add_size_on_gpu(b);
    let sub_tmp_buffer_size = a.get_sub_size_on_gpu(b);
    let scalar_add_tmp_buffer_size = clear_a.get_add_size_on_gpu(b);
    let scalar_sub_tmp_buffer_size = clear_a.get_sub_size_on_gpu(b);
    check_valid_cuda_malloc_assert_oom(add_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(sub_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_add_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_sub_tmp_buffer_size, GpuIndex::new(0));
    assert_eq!(add_tmp_buffer_size, sub_tmp_buffer_size);
    assert_eq!(add_tmp_buffer_size, scalar_add_tmp_buffer_size);
    assert_eq!(add_tmp_buffer_size, scalar_sub_tmp_buffer_size);
    let neg_tmp_buffer_size = a.get_neg_size_on_gpu();
    check_valid_cuda_malloc_assert_oom(neg_tmp_buffer_size, GpuIndex::new(0));
}
#[test]
fn test_gpu_get_bitops_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();

    let a = &a;
    let b = &b;

    let bitand_tmp_buffer_size = a.get_bitand_size_on_gpu(b);
    let scalar_bitand_tmp_buffer_size = clear_a.get_bitand_size_on_gpu(b);
    check_valid_cuda_malloc_assert_oom(bitand_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_bitand_tmp_buffer_size, GpuIndex::new(0));
    let bitor_tmp_buffer_size = a.get_bitor_size_on_gpu(b);
    let scalar_bitor_tmp_buffer_size = clear_a.get_bitor_size_on_gpu(b);
    check_valid_cuda_malloc_assert_oom(bitor_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_bitor_tmp_buffer_size, GpuIndex::new(0));
    let bitxor_tmp_buffer_size = a.get_bitxor_size_on_gpu(b);
    let scalar_bitxor_tmp_buffer_size = clear_a.get_bitxor_size_on_gpu(b);
    check_valid_cuda_malloc_assert_oom(bitxor_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_bitxor_tmp_buffer_size, GpuIndex::new(0));
    let bitnot_tmp_buffer_size = a.get_bitnot_size_on_gpu();
    check_valid_cuda_malloc_assert_oom(bitnot_tmp_buffer_size, GpuIndex::new(0));
}
#[test]
fn test_gpu_get_comparisons_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();
    let a = &a;
    let b = &b;

    let gt_tmp_buffer_size = a.get_gt_size_on_gpu(b);
    let scalar_gt_tmp_buffer_size = a.get_gt_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(gt_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_gt_tmp_buffer_size, GpuIndex::new(0));
    let ge_tmp_buffer_size = a.get_ge_size_on_gpu(b);
    let scalar_ge_tmp_buffer_size = a.get_ge_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(ge_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_ge_tmp_buffer_size, GpuIndex::new(0));
    let lt_tmp_buffer_size = a.get_lt_size_on_gpu(b);
    let scalar_lt_tmp_buffer_size = a.get_lt_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(lt_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_lt_tmp_buffer_size, GpuIndex::new(0));
    let le_tmp_buffer_size = a.get_le_size_on_gpu(b);
    let scalar_le_tmp_buffer_size = a.get_le_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(le_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_le_tmp_buffer_size, GpuIndex::new(0));
    let max_tmp_buffer_size = a.get_max_size_on_gpu(b);
    let scalar_max_tmp_buffer_size = a.get_max_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(max_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_max_tmp_buffer_size, GpuIndex::new(0));
    let min_tmp_buffer_size = a.get_min_size_on_gpu(b);
    let scalar_min_tmp_buffer_size = a.get_min_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(min_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_min_tmp_buffer_size, GpuIndex::new(0));
    let eq_tmp_buffer_size = a.get_eq_size_on_gpu(b);
    let scalar_eq_tmp_buffer_size = a.get_eq_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(eq_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_eq_tmp_buffer_size, GpuIndex::new(0));
    let ne_tmp_buffer_size = a.get_ne_size_on_gpu(b);
    let scalar_ne_tmp_buffer_size = a.get_ne_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(ne_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_ne_tmp_buffer_size, GpuIndex::new(0));
}

#[test]
fn test_gpu_get_shift_rotate_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();
    let a = &a;
    let b = &b;

    let left_shift_tmp_buffer_size = a.get_left_shift_size_on_gpu(b);
    let scalar_left_shift_tmp_buffer_size = a.get_left_shift_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(left_shift_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_left_shift_tmp_buffer_size, GpuIndex::new(0));
    let right_shift_tmp_buffer_size = a.get_right_shift_size_on_gpu(b);
    let scalar_right_shift_tmp_buffer_size = a.get_right_shift_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(right_shift_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_right_shift_tmp_buffer_size, GpuIndex::new(0));
    let rotate_left_tmp_buffer_size = a.get_rotate_left_size_on_gpu(b);
    let scalar_rotate_left_tmp_buffer_size = a.get_rotate_left_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(rotate_left_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_rotate_left_tmp_buffer_size, GpuIndex::new(0));
    let rotate_right_tmp_buffer_size = a.get_rotate_right_size_on_gpu(b);
    let scalar_rotate_right_tmp_buffer_size = a.get_rotate_right_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(rotate_right_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_rotate_right_tmp_buffer_size, GpuIndex::new(0));
}

#[test]
fn test_gpu_get_if_then_else_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let clear_c = rng.gen_range(0..=1);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    let c = FheBool::encrypt(clear_c != 0, &cks);
    a.move_to_current_device();
    b.move_to_current_device();
    let a = &a;
    let b = &b;

    let if_then_else_tmp_buffer_size = c.get_if_then_else_size_on_gpu(a, b);
    check_valid_cuda_malloc_assert_oom(if_then_else_tmp_buffer_size, GpuIndex::new(0));
    let select_tmp_buffer_size = c.get_select_size_on_gpu(a, b);
    check_valid_cuda_malloc_assert_oom(select_tmp_buffer_size, GpuIndex::new(0));
    let cmux_tmp_buffer_size = c.get_cmux_size_on_gpu(a, b);
    check_valid_cuda_malloc_assert_oom(cmux_tmp_buffer_size, GpuIndex::new(0));
}
#[test]
fn test_gpu_get_mul_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();

    let a = &a;
    let b = &b;

    let mul_tmp_buffer_size = a.get_mul_size_on_gpu(b);
    let scalar_mul_tmp_buffer_size = b.get_mul_size_on_gpu(clear_a);
    check_valid_cuda_malloc_assert_oom(mul_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_mul_tmp_buffer_size, GpuIndex::new(0));
}
#[test]
fn test_gpu_get_div_size_on_gpu() {
    let cks = setup_gpu(Some(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS));
    let mut rng = rand::thread_rng();
    let clear_a = rng.gen_range(1..=u32::MAX);
    let clear_b = rng.gen_range(1..=u32::MAX);
    let mut a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let mut b = FheUint32::try_encrypt(clear_b, &cks).unwrap();
    a.move_to_current_device();
    b.move_to_current_device();

    let a = &a;
    let b = &b;

    let div_tmp_buffer_size = a.get_div_size_on_gpu(b);
    let rem_tmp_buffer_size = a.get_rem_size_on_gpu(b);
    let div_rem_tmp_buffer_size = a.get_div_rem_size_on_gpu(b);
    check_valid_cuda_malloc_assert_oom(div_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(rem_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(div_rem_tmp_buffer_size, GpuIndex::new(0));
    let scalar_div_tmp_buffer_size = a.get_div_size_on_gpu(clear_b);
    let scalar_rem_tmp_buffer_size = a.get_rem_size_on_gpu(clear_b);
    let scalar_div_rem_tmp_buffer_size = a.get_div_rem_size_on_gpu(clear_b);
    check_valid_cuda_malloc_assert_oom(scalar_div_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_rem_tmp_buffer_size, GpuIndex::new(0));
    check_valid_cuda_malloc_assert_oom(scalar_div_rem_tmp_buffer_size, GpuIndex::new(0));
}
