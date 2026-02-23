use crate::high_level_api::integers::signed::tests::{
    test_case_ilog2, test_case_leading_trailing_zeros_ones,
};
use crate::prelude::{
    check_valid_cuda_malloc_assert_oom, AddSizeOnGpu, BitAndSizeOnGpu, BitNotSizeOnGpu,
    BitOrSizeOnGpu, BitXorSizeOnGpu, CiphertextList, DivRemSizeOnGpu, DivSizeOnGpu, FheDecrypt,
    FheEncrypt, FheEqSizeOnGpu, FheMaxSizeOnGpu, FheMinSizeOnGpu, FheOrdSizeOnGpu, FheTryEncrypt,
    IfThenElseSizeOnGpu, MulSizeOnGpu, NegSizeOnGpu, RemSizeOnGpu, RotateLeftSizeOnGpu,
    RotateRightSizeOnGpu, ShlSizeOnGpu, ShrSizeOnGpu, SubSizeOnGpu,
};
use crate::{
    CompactCiphertextList, CompactPublicKey, CompressedFheInt16, FheBool, FheInt32, FheInt8,
    FheUint32, GpuIndex,
};
use rand::{thread_rng, Rng};

#[test]
fn test_signed_integer_compressed_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let clear = -1234i16;
        let compressed = CompressedFheInt16::try_encrypt(clear, &client_key).unwrap();
        let decompressed = compressed.decompress();
        let clear_decompressed: i16 = decompressed.decrypt(&client_key);
        assert_eq!(clear_decompressed, clear);
    }
}

#[test]
fn test_integer_compressed_small_gpu() {
    let mut rng = thread_rng();

    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let clear = rng.gen::<i16>();
        let compressed = CompressedFheInt16::try_encrypt(clear, &client_key).unwrap();
        let decompressed = compressed.decompress();
        let clear_decompressed: i16 = decompressed.decrypt(&client_key);
        assert_eq!(clear_decompressed, clear);
    }
}

#[test]
fn test_int32_compare_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_int32_compare(&client_key);
    }
}

#[test]
fn test_int32_bitwise_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_int32_bitwise(&client_key);
    }
}

#[test]
fn test_int64_rotate_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_int64_rotate(&client_key);
    }
}

#[test]
fn test_int32_div_rem_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_int32_div_rem(&client_key);
    }
}
#[test]
fn test_integer_casting_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_integer_casting(&client_key);
    }
}

#[test]
fn test_if_then_else_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_if_then_else(&client_key);
    }
}

#[test]
fn test_flip_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_flip(&client_key);
    }
}

#[test]
fn test_abs_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_abs(&client_key);
    }
}

#[test]
fn test_ilog2_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        test_case_ilog2(&client_key);
    }
}

#[test]
fn test_leading_trailing_zeros_ones_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        test_case_leading_trailing_zeros_ones(&client_key);
    }
}

#[test]
fn test_min_max_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        super::test_case_min_max(&client_key);
    }
}

#[test]
fn test_compact_public_key_big_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let public_key = CompactPublicKey::new(&client_key);
        let compact_list = CompactCiphertextList::builder(&public_key)
            .push(-1i8)
            .build();
        let expanded = compact_list.expand().unwrap();
        let a: FheInt8 = expanded.get(0).unwrap().unwrap();

        let clear: i8 = a.decrypt(&client_key);
        assert_eq!(clear, -1i8);
    }
}

#[test]
fn test_compact_public_key_small_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let public_key = CompactPublicKey::new(&client_key);
        let compact_list = CompactCiphertextList::builder(&public_key)
            .push(-123i8)
            .build();
        let expanded = compact_list.expand().unwrap();
        let a: FheInt8 = expanded.get(0).unwrap().unwrap();

        let clear: i8 = a.decrypt(&client_key);
        assert_eq!(clear, -123i8);
    }
}

#[test]
fn test_gpu_get_add_sub_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=i32::MAX);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
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
}

#[test]
fn test_gpu_get_bitops_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=i32::MAX);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
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
}
#[test]
fn test_gpu_get_comparisons_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=i32::MAX);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
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
}

#[test]
fn test_gpu_get_shift_rotate_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=u32::MAX);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheUint32::try_encrypt(clear_b, &client_key).unwrap();
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
}

#[test]
fn test_gpu_get_if_then_else_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=i32::MAX);
        let clear_c = rng.gen_range(0..=1);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
        let c = FheBool::encrypt(clear_c != 0, &client_key);
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
}
#[test]
fn test_gpu_get_mul_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=i32::MAX);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
        a.move_to_current_device();
        b.move_to_current_device();
        let a = &a;
        let b = &b;

        let mul_tmp_buffer_size = a.get_mul_size_on_gpu(b);
        let scalar_mul_tmp_buffer_size = b.get_mul_size_on_gpu(clear_a);
        check_valid_cuda_malloc_assert_oom(mul_tmp_buffer_size, GpuIndex::new(0));
        check_valid_cuda_malloc_assert_oom(scalar_mul_tmp_buffer_size, GpuIndex::new(0));
    }
}
#[test]
fn test_gpu_get_div_size_on_gpu() {
    for setup_fn in crate::high_level_api::integers::unsigned::tests::gpu::GPU_SETUP_FN {
        let client_key = setup_fn();
        let mut rng = rand::rng();
        let clear_a = rng.gen_range(1..=i32::MAX);
        let clear_b = rng.gen_range(1..=i32::MAX);
        let mut a = FheInt32::try_encrypt(clear_a, &client_key).unwrap();
        let mut b = FheInt32::try_encrypt(clear_b, &client_key).unwrap();
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
}
