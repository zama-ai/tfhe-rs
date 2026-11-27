use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_bitand_test, default_bitnot_test, default_bitor_test, default_bitxor_test,
    unchecked_bitand_test, unchecked_bitnot_test, unchecked_bitor_test, unchecked_bitxor_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;

create_gpu_parameterized_test!(integer_unchecked_bitnot);
create_gpu_parameterized_test!(integer_unchecked_bitand);
create_gpu_parameterized_test!(integer_unchecked_bitor);
create_gpu_parameterized_test!(integer_unchecked_bitxor);
create_gpu_parameterized_test!(integer_bitnot);
create_gpu_parameterized_test!(integer_bitand);
create_gpu_parameterized_test!(integer_bitor);
create_gpu_parameterized_test!(integer_bitxor {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
});

fn integer_unchecked_bitnot<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitnot);
    unchecked_bitnot_test(param, executor);
}

fn integer_unchecked_bitand<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitand);
    unchecked_bitand_test(param, executor);
}

fn integer_unchecked_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitor);
    unchecked_bitor_test(param, executor);
}

fn integer_unchecked_bitxor<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::unchecked_bitxor);
    unchecked_bitxor_test(param, executor);
}

fn integer_bitnot<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitnot);
    default_bitnot_test(param, executor);
}

fn integer_bitand<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitand);
    default_bitand_test(param, executor);
}

fn integer_bitor<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitor);
    default_bitor_test(param, executor);
}

fn integer_bitxor<P>(param: P)
where
    P: Into<TestParameters> + Copy,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::bitxor);
    default_bitxor_test(param, executor);
}

/// A boolean block of degree 2 or 3 (e.g. the sum of two booleans) must be cleaned (bit
/// extracted modulo 2) before the NOT, like on the CPU; it used to keep the padding bit set.
#[test]
fn test_gpu_integer_boolean_bitnot_degree_2() {
    use crate::core_crypto::gpu::vec::GpuIndex;
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    use crate::integer::gpu::gen_keys_gpu;

    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let (cks, sks) = gen_keys_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, &streams);
    for (a, b) in [(true, true), (true, false), (false, false)] {
        let d_a = CudaBooleanBlock::from_boolean_block(&cks.encrypt_bool(a), &streams);
        let d_b = CudaBooleanBlock::from_boolean_block(&cks.encrypt_bool(b), &streams);
        let sum = sks.unchecked_add(&d_a.0, &d_b.0, &streams);
        // Degree 2: built directly, `from_cuda_radix_ciphertext` asserts degree <= 1
        let dirty = CudaBooleanBlock(sum);
        let result = sks
            .boolean_bitnot(&dirty, &streams)
            .to_boolean_block(&streams)
            .0;
        let expected = u64::from((u8::from(a) + u8::from(b)) % 2 == 0);
        assert_eq!(cks.key.decrypt_message_and_carry(&result), expected);
        assert_eq!(result.degree.get(), 1);
    }
}
