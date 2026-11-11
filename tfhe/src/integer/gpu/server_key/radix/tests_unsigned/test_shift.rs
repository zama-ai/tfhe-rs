use super::legacy_default_tests::{
    legacy_default_left_shift_test, legacy_default_right_shift_test,
};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
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

/// The in-place shifts and rotations must write their result back into `ct` when `ct` has
/// non-empty carries (they used to work on a cleaned copy and leave `ct` unchanged).
#[test]
fn test_gpu_integer_shift_rotate_assign_dirty_lhs() {
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::{
        CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext,
    };
    use crate::integer::gpu::gen_keys_gpu;

    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    let num_blocks = 4;
    let (a, b, n) = (0x5Au64, 0x7Bu64, 3u32);
    let v = (a + b) % 256;
    let to_gpu = |m: u64| {
        CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt_radix(m, num_blocks),
            &streams,
        )
    };
    let d_shift = to_gpu(u64::from(n));
    let expected = [
        v >> n,
        (v << n) % 256,
        ((v >> n) | (v << (8 - n))) % 256,
        ((v << n) | (v >> (8 - n))) % 256,
    ];
    for (i, expected) in expected.into_iter().enumerate() {
        let mut ct = sks.unchecked_add(&to_gpu(a), &to_gpu(b), &streams);
        assert!(!ct.block_carries_are_empty());
        match i {
            0 => sks.right_shift_assign(&mut ct, &d_shift, &streams),
            1 => sks.left_shift_assign(&mut ct, &d_shift, &streams),
            2 => sks.rotate_right_assign(&mut ct, &d_shift, &streams),
            _ => sks.rotate_left_assign(&mut ct, &d_shift, &streams),
        }
        let got: u64 = cks.decrypt_radix(&ct.to_radix_ciphertext(&streams));
        assert_eq!(got, expected, "case {i}: v={v:#x} n={n}");
    }
}

/// An encrypted shift/rotate amount with a different number of blocks than the value must be
/// rejected by a Rust panic (the backend aborted the process); same widths still work.
#[test]
fn test_gpu_integer_shift_rotate_amount_width_mismatch_rejected() {
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::{
        CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext,
    };
    use crate::integer::gpu::gen_keys_gpu;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    let s = &streams;
    let to_gpu = |m: u64, num_blocks: usize| {
        CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cks.encrypt_radix(m, num_blocks), s)
    };
    // 0x5A on 4 blocks (8 bits), 0x0F5A on 8 blocks (16 bits), amount 3 on 4 and 8 blocks
    let narrow = to_gpu(0x5A, 4);
    let wide = to_gpu(0x0F5A, 8);
    let amount_narrow = to_gpu(3, 4);
    let amount_wide = to_gpu(3, 8);

    let rejected = |name: &str, f: &dyn Fn()| {
        assert!(
            catch_unwind(AssertUnwindSafe(f)).is_err(),
            "{name}: amount of a different width was not rejected"
        );
    };
    rejected("left_shift narrower amount", &|| {
        sks.left_shift(&wide, &amount_narrow, s);
    });
    rejected("right_shift narrower amount", &|| {
        sks.right_shift(&wide, &amount_narrow, s);
    });
    rejected("rotate_left narrower amount", &|| {
        sks.rotate_left(&wide, &amount_narrow, s);
    });
    rejected("rotate_right narrower amount", &|| {
        sks.rotate_right(&wide, &amount_narrow, s);
    });
    rejected("left_shift_assign narrower amount", &|| {
        let mut ct = wide.duplicate(s);
        sks.left_shift_assign(&mut ct, &amount_narrow, s);
    });
    rejected("right_shift_assign narrower amount", &|| {
        let mut ct = wide.duplicate(s);
        sks.right_shift_assign(&mut ct, &amount_narrow, s);
    });
    rejected("rotate_left_assign narrower amount", &|| {
        let mut ct = wide.duplicate(s);
        sks.rotate_left_assign(&mut ct, &amount_narrow, s);
    });
    rejected("rotate_right_assign narrower amount", &|| {
        let mut ct = wide.duplicate(s);
        sks.rotate_right_assign(&mut ct, &amount_narrow, s);
    });
    rejected("left_shift wider amount", &|| {
        sks.left_shift(&narrow, &amount_wide, s);
    });
    rejected("rotate_right_assign wider amount", &|| {
        let mut ct = narrow.duplicate(s);
        sks.rotate_right_assign(&mut ct, &amount_wide, s);
    });

    // Same widths still work: 0x5A on 8 bits, by 3
    for (name, r, expected) in [
        (
            "left_shift",
            sks.left_shift(&narrow, &amount_narrow, s),
            0xD0,
        ),
        (
            "right_shift",
            sks.right_shift(&narrow, &amount_narrow, s),
            0x0B,
        ),
        (
            "rotate_left",
            sks.rotate_left(&narrow, &amount_narrow, s),
            0xD2,
        ),
        (
            "rotate_right",
            sks.rotate_right(&narrow, &amount_narrow, s),
            0x4B,
        ),
    ] {
        let r: u64 = cks.decrypt_radix(&r.to_radix_ciphertext(s));
        assert_eq!(r, expected, "{name}");
    }
}
