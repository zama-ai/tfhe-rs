use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_unsigned::test_bitonic_shuffle::{
    bitonic_shuffle_test, bitonic_shuffle_with_keys_errors_test,
    bitonic_shuffle_with_keys_invalid_block_counts_test, bitonic_shuffle_with_keys_test,
    unchecked_bitonic_shuffle_with_keys_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::TestParameters;

create_gpu_parameterized_test!(integer_bitonic_shuffle_with_keys {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_unchecked_bitonic_shuffle_with_keys {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_bitonic_shuffle {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_bitonic_shuffle_with_keys_errors {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_bitonic_shuffle_with_keys_invalid_block_counts {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_bitonic_shuffle_with_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(
        &CudaServerKey::bitonic_shuffle_with_keys::<CudaUnsignedRadixCiphertext>,
    );
    bitonic_shuffle_with_keys_test(param, executor);
}

fn integer_unchecked_bitonic_shuffle_with_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&|sks: &CudaServerKey,
                                              data: Vec<CudaUnsignedRadixCiphertext>,
                                              keys: Vec<CudaUnsignedRadixCiphertext>,
                                              streams: &crate::core_crypto::gpu::CudaStreams|
     -> Vec<CudaUnsignedRadixCiphertext> {
        sks.unchecked_bitonic_shuffle_with_keys(data, keys, streams)
    });
    unchecked_bitonic_shuffle_with_keys_test(param, executor);
}

fn integer_bitonic_shuffle<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(
        &|sks: &CudaServerKey,
          data: Vec<CudaUnsignedRadixCiphertext>,
          key_size: crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize,
          seed: tfhe_csprng::seeders::Seed,
          streams: &crate::core_crypto::gpu::CudaStreams|
         -> Result<Vec<CudaUnsignedRadixCiphertext>, crate::Error> {
            let oprf_view = crate::integer::gpu::GenericCudaOprfServerKey::from_borrowed_bsk(
                &sks.bootstrapping_key,
            );
            sks.bitonic_shuffle(&oprf_view, data, key_size, seed, streams)
        },
    );
    bitonic_shuffle_test(param, executor);
}

fn integer_bitonic_shuffle_with_keys_errors<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(
        &CudaServerKey::bitonic_shuffle_with_keys::<CudaUnsignedRadixCiphertext>,
    );
    bitonic_shuffle_with_keys_errors_test(param, executor);
}

fn integer_bitonic_shuffle_with_keys_invalid_block_counts<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(
        &CudaServerKey::bitonic_shuffle_with_keys::<CudaUnsignedRadixCiphertext>,
    );
    bitonic_shuffle_with_keys_invalid_block_counts_test(param, executor);
}
