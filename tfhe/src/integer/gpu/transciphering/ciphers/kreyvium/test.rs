use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::server_key::tests_unsigned::test_kreyvium::{
    encrypt_bits, kreyvium_batched_matches_single_test,
};
use crate::integer::gpu::server_key::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::{gen_keys_radix_gpu, CudaServerKey};
use crate::integer::server_key::radix_parallel::tests_unsigned::test_kreyvium::{
    kreyvium_comparison_test, kreyvium_stateful_comparison_test, kreyvium_test_vector_1_test,
};
use crate::shortint::parameters::{
    TestParameters, PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128,
};

// FastKreyvium evaluates the standard Kreyvium cipher, so the known-answer vector and the CPU
// reference comparison are shared with the original Kreyvium harness; only the parameter set and
// the entry-point methods differ.
create_gpu_parameterized_test!(integer_fast_kreyvium_test_vector_1 {
    PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_fast_kreyvium_comparison {
    PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_fast_kreyvium_stateful_comparison {
    PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_fast_kreyvium_non_multiple_batch_size {
    PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128
});

create_gpu_parameterized_test!(integer_fast_kreyvium_batched_matches_single {
    PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128
});

fn integer_fast_kreyvium_test_vector_1<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::fast_kreyvium_generate_keystream);
    kreyvium_test_vector_1_test(param, executor);
}

fn integer_fast_kreyvium_comparison<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&CudaServerKey::fast_kreyvium_generate_keystream);
    kreyvium_comparison_test(param, executor);
}

fn integer_fast_kreyvium_stateful_comparison<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new((
        CudaServerKey::fast_kreyvium_init,
        CudaServerKey::fast_kreyvium_next,
    ));
    kreyvium_stateful_comparison_test(param, executor);
}

/// Verifies that `fast_kreyvium_next` rejects a `num_steps` that is not a multiple of the batch
/// size (64): the call must return `Err`, not panic.
fn integer_fast_kreyvium_non_multiple_batch_size<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let streams = CudaStreams::new_multi_gpu();
    let (cks, sks) = gen_keys_radix_gpu(param, 1, &streams);

    let key_bits = vec![0u64; 128];
    let iv_bits = vec![0u64; 128];
    let ct_key = encrypt_bits(&cks, &key_bits, &streams);
    let ct_iv = encrypt_bits(&cks, &iv_bits, &streams);

    let result = sks.fast_kreyvium_generate_keystream(&ct_key, &ct_iv, 65, &streams);
    assert!(
        result.is_err(),
        "Expected Err for num_steps=65 (not a multiple of 64), got Ok"
    );
}

fn integer_fast_kreyvium_batched_matches_single<P>(param: P)
where
    P: Into<TestParameters>,
{
    kreyvium_batched_matches_single_test(param, &CudaServerKey::fast_kreyvium_generate_keystream);
}
