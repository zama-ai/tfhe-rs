pub(crate) use crate::core_crypto::algorithms::test::gen_keys_or_get_from_cache_if_enabled;
use crate::shortint::parameters::{
    DynamicDistribution, NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
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
    allocate_and_encrypt_new_lwe_ciphertext, decrypt_lwe_ciphertext,
    generate_programmable_bootstrap_glwe_lut, CastFrom, CastInto, DecompositionLevelCount,
    GlweCiphertextOwned, GlweSecretKey, LweCiphertextCount, LweCiphertextOwned, LweSecretKey,
    Plaintext, SignedDecomposer, UnsignedTorus,
};
use crate::shortint::parameters::{ModulusSwitchType, NoiseSquashingParameters};
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
    // Our input message
    let input_message: u64 = 3usize.cast_into();

    // Delta used to encode 4 bits of message + a bit of padding on Scalar

    let delta: u64 = (1 << (u64::BITS - 1)) / message_modulus;
    let delta_u128: u128 = (1 << (u128::BITS - 1)) / message_modulus as u128;

    // Apply our encoding
    let plaintext = Plaintext(input_message * delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &input_lwe_secret_key,
        plaintext,
        input_params.lwe_noise_distribution,
        input_params.ciphertext_modulus,
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
        CudaLweCiphertextList::from_lwe_ciphertext(&lwe_ciphertext_in, &stream);

    let mut d_out_pbs_ct = CudaLweCiphertextList::new(
        output_lwe_dimension,
        LweCiphertextCount(1),
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

    let pbs_ct = d_out_pbs_ct.into_lwe_ciphertext(&stream);

    // Decrypt the PBS result
    let pbs_plaintext: Plaintext<u128> = decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_ct);
    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want
    // to round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    // Round and remove our encoding
    let pbs_result: u128 = signed_decomposer.closest_representable(pbs_plaintext.0) / delta_u128;

    assert_eq!(f(input_message as u128), pbs_result);
}

#[test]
fn test_bootstrap_u128_with_squashing() {
    execute_bootstrap_u128(
        NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );
}
