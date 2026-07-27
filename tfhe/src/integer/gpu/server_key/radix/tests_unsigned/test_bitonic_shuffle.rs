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

/// A CPK of the wrong dimension must be rejected, the backend would read out of bounds.
#[test]
fn bitonic_shuffle_rerand_rejects_incompatible_cpk() {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::core_crypto::prelude::LweDimension;
    use crate::integer::ciphertext::PrfReRandomizationContext;
    use crate::integer::gpu::ciphertext::re_randomization::CudaReRandomizationKey;
    use crate::integer::gpu::CudaOprfServerKey;
    use crate::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey};
    use crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize;
    use crate::integer::{ClientKey, CompactPrivateKey, CompactPublicKey, RadixClientKey};
    use crate::shortint::parameters::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use tfhe_csprng::seeders::Seed;

    const NUM_DATA_BLOCKS: usize = 4;

    let cks = ClientKey::new(TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let radix_cks = RadixClientKey::from((cks.clone(), NUM_DATA_BLOCKS));

    let streams = CudaStreams::new_multi_gpu();
    let sks = CudaServerKey::new(&cks, &streams);

    let oprf_priv = OprfPrivateKey::new(&cks);
    let compressed_oprf = CompressedOprfServerKey::new(&oprf_priv, &cks).unwrap();
    let oprf_sks = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf, &streams);

    // Derived compact public key, re-using the compute secret key
    let matching_privk: CompactPrivateKey<&[u64]> = (&cks).try_into().unwrap();
    let matching_cpk = CompactPublicKey::new(&matching_privk);

    let mut smaller_params = PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    smaller_params.encryption_lwe_dimension = LweDimension(1024);
    let mismatched_cpk = CompactPublicKey::new(&CompactPrivateKey::new(smaller_params));
    assert_ne!(
        mismatched_cpk.key.key.lwe_dimension(),
        matching_cpk.key.key.lwe_dimension(),
        "this test needs a compact public key whose dimension differs from the compute key one"
    );

    let prf_rerand_context = PrfReRandomizationContext::default();
    let key_size = BitonicShuffleKeySize::num_bits(32);

    let data = || -> Vec<CudaUnsignedRadixCiphertext> {
        (1..=4u64)
            .map(|v| {
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_cks.encrypt(v), &streams)
            })
            .collect()
    };

    let result = sks.bitonic_shuffle_and_re_randomize(
        &oprf_sks,
        data(),
        key_size,
        Seed(0x5EEDED),
        &CudaReRandomizationKey::DerivedCPKWithoutKeySwitch {
            cpk: &mismatched_cpk,
        },
        &prf_rerand_context,
        &streams,
    );
    match result {
        Ok(_) => panic!("an incompatible compact public key must be rejected"),
        Err(err) => assert!(
            err.to_string().contains("Mismatched LweSize"),
            "unexpected error: {err}"
        ),
    }

    // The matching key must still go through
    if let Err(err) = sks.bitonic_shuffle_and_re_randomize(
        &oprf_sks,
        data(),
        key_size,
        Seed(0x5EEDED),
        &CudaReRandomizationKey::DerivedCPKWithoutKeySwitch { cpk: &matching_cpk },
        &prf_rerand_context,
        &streams,
    ) {
        panic!("a matching compact public key must be accepted: {err}");
    }
}

#[test]
fn bitonic_shuffle_cpu_gpu_same_permutation() {
    use crate::core_crypto::gpu::CudaStreams;
    use crate::integer::gpu::CudaOprfServerKey;
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::oprf::{CompressedOprfServerKey, OprfPrivateKey, OprfServerKey};
    use crate::integer::server_key::radix_parallel::bitonic_shuffle::BitonicShuffleKeySize;
    use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
    use tfhe_csprng::seeders::Seed;

    const NUM_DATA_BLOCKS: usize = 8;

    let param: TestParameters = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into();

    let (cks, cpu_sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NUM_DATA_BLOCKS));

    let oprf_priv = OprfPrivateKey::new(cks.as_ref());
    let cpu_oprf = OprfServerKey::new(&oprf_priv, cks.as_ref()).unwrap();
    let compressed_oprf = CompressedOprfServerKey::new(&oprf_priv, cks.as_ref()).unwrap();

    let streams = CudaStreams::new_multi_gpu();
    let cuda_sks = CudaServerKey::new(cks.as_ref(), &streams);
    streams.synchronize();
    let gpu_oprf = CudaOprfServerKey::decompress_from_cpu(&compressed_oprf, &streams);

    let seed = Seed(0x5EEDED);
    let key_size = BitonicShuffleKeySize::num_bits(32);

    for &len in &[2usize, 5, 8, 17] {
        let clear_data: Vec<u32> = (1..=len as u32).collect();

        let enc_cpu: Vec<RadixCiphertext> =
            clear_data.iter().map(|&v| cks.encrypt(v as u64)).collect();
        let cpu_res = cpu_sks
            .bitonic_shuffle(&cpu_oprf, enc_cpu, key_size, seed)
            .expect("CPU bitonic_shuffle failed");
        let cpu_dec: Vec<u32> = cpu_res
            .iter()
            .map(|ct| cks.decrypt::<u64>(ct) as u32)
            .collect();

        let enc_gpu: Vec<CudaUnsignedRadixCiphertext> = clear_data
            .iter()
            .map(|&v| {
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&cks.encrypt(v as u64), &streams)
            })
            .collect();
        let gpu_res = cuda_sks
            .bitonic_shuffle(&gpu_oprf, enc_gpu, key_size, seed, &streams)
            .expect("GPU bitonic_shuffle failed");
        let gpu_dec: Vec<u32> = gpu_res
            .iter()
            .map(|ct| cks.decrypt::<u64>(&ct.to_radix_ciphertext(&streams)) as u32)
            .collect();

        assert_eq!(
            cpu_dec, gpu_dec,
            "len={len}: CPU and GPU produced different permutations for the same seed"
        );

        let mut sorted = cpu_dec.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, clear_data, "len={len}: result is not a permutation");
    }
}
