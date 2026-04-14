use crate::integer::gpu::ciphertext::{CudaSignedRadixCiphertext, CudaUnsignedRadixCiphertext};
use crate::integer::gpu::server_key::radix::tests_unsigned::{
    create_gpu_parameterized_test, GpuFunctionExecutor,
};
use crate::integer::gpu::CudaServerKey;
use crate::integer::server_key::radix_parallel::tests_signed::test_bitonic_shuffle::{
    signed_bitonic_shuffle_test, signed_bitonic_shuffle_with_keys_test,
    signed_unchecked_bitonic_shuffle_with_keys_test,
};
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::TestParameters;

create_gpu_parameterized_test!(integer_signed_bitonic_shuffle_with_keys {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_signed_unchecked_bitonic_shuffle_with_keys {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});
create_gpu_parameterized_test!(integer_signed_bitonic_shuffle {
    TEST_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
});

fn integer_signed_bitonic_shuffle_with_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(
        &CudaServerKey::bitonic_shuffle_with_keys::<CudaSignedRadixCiphertext>,
    );
    signed_bitonic_shuffle_with_keys_test(param, executor);
}

fn integer_signed_unchecked_bitonic_shuffle_with_keys<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(&|sks: &CudaServerKey,
                                              data: Vec<CudaSignedRadixCiphertext>,
                                              keys: Vec<CudaUnsignedRadixCiphertext>,
                                              streams: &crate::core_crypto::gpu::CudaStreams|
     -> Vec<CudaSignedRadixCiphertext> {
        sks.unchecked_bitonic_shuffle_with_keys(data, keys, streams)
    });
    signed_unchecked_bitonic_shuffle_with_keys_test(param, executor);
}

fn integer_signed_bitonic_shuffle<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = GpuFunctionExecutor::new(
        &|sks: &CudaServerKey,
          data: Vec<CudaSignedRadixCiphertext>,
          key_size: crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize,
          seed: tfhe_csprng::seeders::Seed,
          streams: &crate::core_crypto::gpu::CudaStreams|
         -> Result<Vec<CudaSignedRadixCiphertext>, crate::Error> {
            let oprf_view = crate::integer::gpu::GenericCudaOprfServerKey::from_borrowed_bsk(
                &sks.bootstrapping_key,
            );
            sks.bitonic_shuffle(&oprf_view, data, key_size, seed, streams)
        },
    );
    signed_bitonic_shuffle_test(param, executor);
}
