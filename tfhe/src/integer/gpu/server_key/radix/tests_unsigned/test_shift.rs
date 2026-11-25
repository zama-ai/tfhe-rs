use super::legacy_default_tests::{
    legacy_default_left_shift_test, legacy_default_right_shift_test,
};
use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::{CudaIntegerRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_shift::{
    left_shift_amount_of_another_width_test, right_shift_amount_of_another_width_test,
    unchecked_left_shift_test, unchecked_right_shift_test,
};
use crate::integer::IntegerKeyKind;
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
create_gpu_parameterized_test!(integer_left_shift_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
});
create_gpu_parameterized_test!(integer_right_shift_amount_of_another_width {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
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

fn integer_left_shift_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::left_shift);
    left_shift_amount_of_another_width_test(param, executor);
}

fn integer_right_shift_amount_of_another_width<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::right_shift);
    right_shift_amount_of_another_width_test(param, executor);
}

#[test]
fn test_gpu_integer_shift_and_rotate_size_and_empty_radix_with_amount_of_another_width() {
    type GpuSizeOp = fn(
        &CudaServerKey,
        &CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    ) -> u64;
    type GpuAssignOp = fn(
        &CudaServerKey,
        &mut CudaUnsignedRadixCiphertext,
        &CudaUnsignedRadixCiphertext,
        &CudaStreams,
    );

    let (cks, _) = KEY_CACHE.get_from_params(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        IntegerKeyKind::Radix,
    );
    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);

    let ops: [(&str, GpuAssignOp, GpuSizeOp); 4] = [
        (
            "left_shift",
            CudaServerKey::left_shift_assign,
            CudaServerKey::get_left_shift_size_on_gpu,
        ),
        (
            "right_shift",
            CudaServerKey::right_shift_assign,
            CudaServerKey::get_right_shift_size_on_gpu,
        ),
        (
            "rotate_left",
            CudaServerKey::rotate_left_assign,
            CudaServerKey::get_rotate_left_size_on_gpu,
        ),
        (
            "rotate_right",
            CudaServerKey::rotate_right_assign,
            CudaServerKey::get_rotate_right_size_on_gpu,
        ),
    ];
    // (value blocks, amount blocks)
    let widths = [(4usize, 8usize), (4, 1), (4, 2), (1, 4)];

    for (name, gpu_assign_op, gpu_size_op) in ops {
        for (value_blocks, amount_blocks) in widths {
            let d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &cks.encrypt_radix(1u64, value_blocks),
                &streams,
            );
            let d_amount = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
                &cks.encrypt_radix(1u64, amount_blocks),
                &streams,
            );
            assert!(
                gpu_size_op(&sks, &d_ct, &d_amount, &streams) > 0,
                "{name}: {value_blocks} value blocks, {amount_blocks} amount blocks"
            );
        }

        let mut d_empty: CudaUnsignedRadixCiphertext = sks.create_trivial_zero_radix(0, &streams);
        let d_amount = CudaUnsignedRadixCiphertext::from_radix_ciphertext(
            &cks.encrypt_radix(1u64, 2),
            &streams,
        );
        gpu_assign_op(&sks, &mut d_empty, &d_amount, &streams);
        assert_eq!(
            d_empty.as_ref().d_blocks.lwe_ciphertext_count().0,
            0,
            "{name}"
        );
    }
}
