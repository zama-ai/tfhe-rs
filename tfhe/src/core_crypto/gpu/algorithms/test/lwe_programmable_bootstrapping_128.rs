use super::assert_gpu_determinism;
pub(crate) use crate::core_crypto::algorithms::test::gen_keys_or_get_from_cache_if_enabled;
use crate::shortint::parameters::v1_3::V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use crate::shortint::parameters::{
    DynamicDistribution, NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::prelude::DecompositionBaseLog;

use crate::core_crypto::algorithms::par_allocate_and_generate_new_lwe_bootstrap_key;
use crate::core_crypto::algorithms::test::{FftBootstrapKeys, TestResources};
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_bootstrap_key::{
    CudaLweBootstrapKey, CudaModulusSwitchNoiseReductionConfiguration,
};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{cuda_programmable_bootstrap_128_lwe_ciphertext, CudaStreams};

use crate::core_crypto::prelude::test::NoiseSquashingTestParams;
use crate::core_crypto::prelude::{
    decrypt_lwe_ciphertext_list, generate_programmable_bootstrap_glwe_lut,
    par_encrypt_lwe_ciphertext_list, CastFrom, CastInto, ContiguousEntityContainer,
    DecompositionLevelCount, GlweCiphertextOwned, GlweSecretKey, LweCiphertextCount,
    LweCiphertextList, LweSecretKey, PlaintextList, SignedDecomposer, UnsignedTorus,
};
use crate::shortint::parameters::{
    ModulusSwitchType, NoiseSquashingClassicParameters, NoiseSquashingParameters,
};
use crate::shortint::MultiBitPBSParameters;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn generate_keys<
    Scalar: UnsignedTorus
        + Sync
        + Send
        + CastFrom<usize>
        + CastFrom<u64>
        + CastInto<usize>
        + Serialize
        + DeserializeOwned,
>(
    params: NoiseSquashingTestParams<Scalar>,
    rsc: &mut TestResources,
) -> FftBootstrapKeys<Scalar> {
    // Generate an LweSecretKey with binary coefficients
    let small_lwe_sk =
        LweSecretKey::generate_new_binary(params.lwe_dimension, &mut rsc.secret_random_generator);

    // Generate a GlweSecretKey with binary coefficients
    let glwe_sk = GlweSecretKey::generate_new_binary(
        params.glwe_dimension,
        params.polynomial_size,
        &mut rsc.secret_random_generator,
    );

    // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    let bsk = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        params.pbs_base_log,
        params.pbs_level,
        params.glwe_noise_distribution,
        params.ciphertext_modulus,
        &mut rsc.encryption_random_generator,
    );

    FftBootstrapKeys {
        small_lwe_sk,
        big_lwe_sk,
        bsk,
    }
}

pub fn execute_bootstrap_u128(
    squash_params: NoiseSquashingParameters,
    input_params: MultiBitPBSParameters,
    num_samples: LweCiphertextCount,
) {
    let NoiseSquashingParameters::Classic(squash_params) = squash_params else {
        panic!("Multi bit noise squashing PBS currently not supported on GPU");
    };

    let glwe_dimension = squash_params.glwe_dimension;
    let polynomial_size = squash_params.polynomial_size;
    let ciphertext_modulus = squash_params.ciphertext_modulus;

    let mut rsc = TestResources::new();

    let noise_squashing_test_params = NoiseSquashingTestParams::<u128> {
        lwe_dimension: input_params.lwe_dimension,
        glwe_dimension: squash_params.glwe_dimension,
        polynomial_size: squash_params.polynomial_size,
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: squash_params.glwe_noise_distribution,
        pbs_base_log: squash_params.decomp_base_log,
        pbs_level: squash_params.decomp_level_count,
        modulus_switch_noise_reduction_params: squash_params.modulus_switch_noise_reduction_params,
        ciphertext_modulus: squash_params.ciphertext_modulus,
    };

    let mut keys_gen = |_params| generate_keys(noise_squashing_test_params, &mut rsc);
    let keys = gen_keys_or_get_from_cache_if_enabled(noise_squashing_test_params, &mut keys_gen);
    let (std_bootstrapping_key, small_lwe_sk, big_lwe_sk) =
        (keys.bsk, keys.small_lwe_sk, keys.big_lwe_sk);
    let output_lwe_dimension = big_lwe_sk.lwe_dimension();

    let input_lwe_secret_key = LweSecretKey::from_container(
        small_lwe_sk
            .into_container()
            .iter()
            .copied()
            .map(|x| x as u64)
            .collect::<Vec<_>>(),
    );

    let gpu_index = 0;
    let stream = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let modulus_switch_noise_reduction_configuration = match squash_params
        .modulus_switch_noise_reduction_params
    {
        ModulusSwitchType::Standard => None,
        ModulusSwitchType::DriftTechniqueNoiseReduction(_modulus_switch_noise_reduction_params) => {
            panic!("Drift noise reduction is not supported on GPU")
        }
        ModulusSwitchType::CenteredMeanNoiseReduction => {
            Some(CudaModulusSwitchNoiseReductionConfiguration::Centered)
        }
    };

    let d_bsk = CudaLweBootstrapKey::from_lwe_bootstrap_key(
        &std_bootstrapping_key,
        modulus_switch_noise_reduction_configuration,
        &stream,
    );

    // Our 4 bits message space
    let message_modulus: u64 = 1 << 4;
    // One distinct message per sample: the LUT below is the identity, so an output that read
    // another sample's slice of a shared buffer decrypts to that sample's message and is caught.
    let input_messages: Vec<u64> = (0..num_samples.0)
        .map(|i| (3 + i as u64) % message_modulus)
        .collect();

    // Delta used to encode 4 bits of message + a bit of padding on Scalar

    let delta: u64 = (1 << (u64::BITS - 1)) / message_modulus;
    let delta_u128: u128 = (1 << (u128::BITS - 1)) / message_modulus as u128;

    // Apply our encoding
    let input_plaintext_list = PlaintextList::from_container(
        input_messages
            .iter()
            .map(|input_message| input_message * delta)
            .collect::<Vec<_>>(),
    );

    let mut lwe_ciphertext_list_in = LweCiphertextList::new(
        0u64,
        input_params.lwe_dimension.to_lwe_size(),
        num_samples,
        input_params.ciphertext_modulus,
    );

    par_encrypt_lwe_ciphertext_list(
        &input_lwe_secret_key,
        &mut lwe_ciphertext_list_in,
        &input_plaintext_list,
        input_params.lwe_noise_distribution,
        &mut rsc.encryption_random_generator,
    );

    let f = |x: u128| x;
    let accumulator: GlweCiphertextOwned<u128> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus.cast_into(),
        ciphertext_modulus,
        delta_u128,
        f,
    );

    let d_lwe_ciphertext_in =
        CudaLweCiphertextList::from_lwe_ciphertext_list(&lwe_ciphertext_list_in, &stream);

    let mut d_out_pbs_ct = CudaLweCiphertextList::new(
        output_lwe_dimension,
        d_lwe_ciphertext_in.lwe_ciphertext_count(),
        ciphertext_modulus,
        &stream,
    );

    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&accumulator, &stream);

    cuda_programmable_bootstrap_128_lwe_ciphertext(
        &d_lwe_ciphertext_in,
        &mut d_out_pbs_ct,
        &d_accumulator,
        &d_bsk,
        &stream,
    );

    let pbs_ct_list = d_out_pbs_ct.to_lwe_ciphertext_list(&stream);

    // Determinism check
    let mut d_out_pbs_ct_bis = CudaLweCiphertextList::new(
        output_lwe_dimension,
        d_lwe_ciphertext_in.lwe_ciphertext_count(),
        ciphertext_modulus,
        &stream,
    );
    cuda_programmable_bootstrap_128_lwe_ciphertext(
        &d_lwe_ciphertext_in,
        &mut d_out_pbs_ct_bis,
        &d_accumulator,
        &d_bsk,
        &stream,
    );
    assert_gpu_determinism(
        pbs_ct_list.as_ref(),
        d_out_pbs_ct_bis.to_lwe_ciphertext_list(&stream).as_ref(),
        "cuda_programmable_bootstrap_128_lwe_ciphertext",
    );

    // Decrypt the PBS result
    let mut output_plaintext_list = PlaintextList::from_container(vec![0u128; num_samples.0]);
    decrypt_lwe_ciphertext_list(&big_lwe_sk, &pbs_ct_list, &mut output_plaintext_list);

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want
    // to round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    for (decrypted, input_message) in output_plaintext_list.iter().zip(input_messages.iter()) {
        // Round and remove our encoding
        let pbs_result: u128 = signed_decomposer.closest_representable(*decrypted.0) / delta_u128;

        assert_eq!(f(*input_message as u128), pbs_result);
    }
}

#[test]
fn test_bootstrap_u128_with_squashing() {
    execute_bootstrap_u128(
        NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        LweCiphertextCount(8),
    );
}

// Exercises the N=4096 classic PBS128 step kernels, the instantiation where
// pbs_128_step_min_blocks_per_sm (see programmable_bootstrap_classic_128.cuh) leaves the launch
// bounds unpinned because its block size differs from the pinned one.
// test_bootstrap_u128_with_squashing above covers the pinned block size.
//
// V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 is the only N=4096 classic
// parameter set available, but execute_bootstrap_u128 panics on its
// ModulusSwitchType::DriftTechniqueNoiseReduction. That choice is unrelated to the kernel under
// test, so this test substitutes ModulusSwitchType::Standard.
#[test]
fn test_bootstrap_u128_with_squashing_n4096() {
    let NoiseSquashingParameters::Classic(n4096_squash_params) =
        V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
    else {
        unreachable!("V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 is a classic parameter set");
    };

    execute_bootstrap_u128(
        NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
            modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
            ..n4096_squash_params
        }),
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        LweCiphertextCount(8),
    );
}
