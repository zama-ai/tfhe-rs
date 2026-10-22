use super::legacy_default_tests::{
    legacy_default_add_test, legacy_default_overflowing_add_test,
    legacy_default_sum_ciphertexts_vec_test,
};
use crate::core_crypto::gpu::{get_number_of_gpus, CudaStreams};
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_signed::GpuMultiDeviceFunctionExecutor;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    unchecked_add_assign_test, unchecked_add_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_add {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_unchecked_add_assign {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_add {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(multi_device_integer_add {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
});
create_gpu_parameterized_test!(integer_sum_ciphertexts_vec);
create_gpu_parameterized_test!(integer_default_overflowing_add);
create_gpu_parameterized_test!(multi_device_integer_default_overflowing_add);

fn integer_unchecked_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_add_assign);
    unchecked_add_assign_test(param, executor);
}

fn integer_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::add);
    legacy_default_add_test(param, executor);
}

fn multi_device_integer_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::add);
    let num_gpus = get_number_of_gpus();
    if num_gpus > 1 {
        legacy_default_add_test(param, executor);
    }
}

fn integer_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<TestParameters>,
{
    // Without this the compiler seems lost, and outputs errors about
    // 'one type is more general than the other' probably because the
    // `sum_ciphertexts_parallelized` is generic over the input collection
    let sum_vec = |sks: &CudaServerKey,
                   ctxt: Vec<CudaUnsignedRadixCiphertext>|
     -> Option<CudaUnsignedRadixCiphertext> {
        let streams = CudaStreams::new_multi_gpu();
        sks.sum_ciphertexts(ctxt, &streams)
    };
    let executor = GpuFunctionExecutor::new(sum_vec);
    legacy_default_sum_ciphertexts_vec_test(param, executor);
}

fn integer_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    legacy_default_overflowing_add_test(param, executor);
}

fn multi_device_integer_default_overflowing_add<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuMultiDeviceFunctionExecutor::new(&CudaServerKey::unsigned_overflowing_add);
    let num_gpus = get_number_of_gpus();
    if num_gpus > 1 {
        legacy_default_overflowing_add_test(param, executor);
    }
}

/// Batched-trivial tests: verify `add` correctness on cleartext data packed into
/// all LWE coefficients (body + every mask slot), without any cryptographic key
/// material being exercised. Carry propagation, LUT sequencing, and block
/// indexing are all checked simultaneously across `lwe_dimension` independent
/// test vectors per operation.
#[cfg(feature = "gpu-nofhe-testing-batched-trivial")]
mod batched_trivial {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use crate::integer::gpu::CudaServerKey;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::IntegerKeyKind;
    use crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use rand::Rng;

    #[test]
    fn test_gpu_integer_add_batched_trivial() {
        let (cks, _) = KEY_CACHE
            .get_from_params(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, IntegerKeyKind::Radix);

        let streams = CudaStreams::new_multi_gpu();
        let sks = CudaServerKey::new(&cks, &streams);
        streams.synchronize();

        let mut rng = rand::thread_rng();
        let num_blocks = 4usize;
        let p = cks.parameters().message_modulus().0 as u64;
        let modulus = p.pow(num_blocks as u32);

        for _ in 0..5 {
            let clear_0 = rng.gen::<u64>() % modulus;
            let clear_1 = rng.gen::<u64>() % modulus;

            let (ct0, tv0) = cks.encrypt_radix_batched_trivial(clear_0, num_blocks, &mut rng);
            let (ct1, tv1) = cks.encrypt_radix_batched_trivial(clear_1, num_blocks, &mut rng);

            let d_ct0 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct0, &streams);
            let d_ct1 = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct1, &streams);

            let d_result = sks.add(&d_ct0, &d_ct1, &streams);
            let result = d_result.to_radix_ciphertext(&streams);

            let expected_body = clear_0.wrapping_add(clear_1) % modulus;
            let expected_slots: Vec<u64> = tv0
                .iter()
                .zip(tv1.iter())
                .map(|(&a, &b)| a.wrapping_add(b) % modulus)
                .collect();

            cks.decrypt_and_check_radix_batched_trivial(&result, expected_body, &expected_slots);
        }
    }
}
