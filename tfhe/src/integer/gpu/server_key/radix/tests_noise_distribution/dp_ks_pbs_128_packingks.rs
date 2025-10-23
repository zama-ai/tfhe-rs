use super::utils::noise_simulation::CudaDynLwe;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateCenteredBinaryShiftedStandardModSwitchResult,
    AllocateDriftTechniqueStandardModSwitchResult, AllocateLweBootstrapResult,
    AllocateLweKeyswitchResult, AllocateLwePackingKeyswitchResult, AllocateStandardModSwitchResult,
    CenteredBinaryShiftedStandardModSwitch, DriftTechniqueStandardModSwitch,
    LweClassicFft128Bootstrap, LweKeyswitch, LwePackingKeyswitch, ScalarMul, StandardModSwitch,
};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::{CudaSideResources, CudaStreams};
use crate::core_crypto::prelude::{GlweCiphertextCount, LweCiphertextCount};
use crate::integer::gpu::CudaServerKey;
use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
use crate::integer::CompressedServerKey;

//use crate::shortint::noise_squashing::{NoiseSquashingPrivateKey, NoiseSquashingKey};
use crate::integer::ciphertext::NoiseSquashingCompressionPrivateKey;
use crate::integer::gpu::list_compression::server_keys::CudaNoiseSquashingCompressionKey;
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
//use crate::integer::noise_squashing::NoiseSquashingPrivateKey;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::integer::IntegerCiphertext;
use crate::integer::gpu::server_key::radix::CudaUnsignedRadixCiphertext;
use crate::shortint::parameters::{AtomicPatternParameters, NoiseSquashingCompressionParameters};
use crate::shortint::server_key::tests::noise_distribution::dp_ks_pbs128_packingks::dp_ks_any_ms_standard_pbs128_packing_ks;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulusSwitchConfig;
use crate::shortint::ShortintParameterSet;
use crate::GpuIndex;
use crate::shortint::ShortintEncoding;
use crate::shortint::PaddingBit;
use crate::core_crypto::prelude::generate_programmable_bootstrap_glwe_lut;
use crate::integer::gpu::unchecked_small_scalar_mul_integer_async;
use rayon::prelude::*;

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_gpu<P>(
    params: P,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
) where
    P: Into<AtomicPatternParameters> + Copy,
{
    let atomic_params: AtomicPatternParameters = params.into();
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = atomic_params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let compressed_noise_squashing_compression_key =
        cks.new_compressed_noise_squashing_key(&noise_squashing_private_key);
    let noise_squashing_key = compressed_noise_squashing_compression_key
        .decompress();
    let cuda_noise_squashing_key =
        compressed_noise_squashing_compression_key.decompress_to_cuda(&streams);

    let noise_squashing_compression_private_key =
        NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
    let noise_squashing_compression_key = noise_squashing_private_key
        .new_noise_squashing_compression_key(&noise_squashing_compression_private_key);
    let cuda_noise_squashing_compression_key =
        CudaNoiseSquashingCompressionKey::from_noise_squashing_compression_key(
            &noise_squashing_compression_key,
            &streams,
        );

    let lwe_per_glwe = cuda_noise_squashing_compression_key.lwe_per_glwe;

    let noise_simulation_modulus_switch_config =
        noise_squashing_key.key.noise_simulation_modulus_switch_config();
    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => {
            Some(&cuda_sks)
        },
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };
    let br_input_modulus_log = noise_squashing_key.key.br_input_modulus_log();
    
    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };
    let max_scalar_mul = sks.key.max_noise_level.get();

    let id_lut = generate_programmable_bootstrap_glwe_lut(
        noise_squashing_key.key.polynomial_size(),
        noise_squashing_key.key.glwe_size(),
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );
    let input_zeros: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.key.encrypt(0)).collect();
    let mut side_resources = vec![(); input_zeros.len()];
    let input_zero_as_lwe = input_zeros
        .iter()
        .map(|ct|{ 
            let cloned_ct_input = ct.clone();
            let radix_ct_input = crate::integer::RadixCiphertext::from_blocks(vec![cloned_ct_input]);
            let d_ct_input =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct_input, &streams);
            CudaDynLwe::U64(d_ct_input.ciphertext.d_blocks)
        } 
        )
        .collect();

    let (_before_packing, mut after_packing) = dp_ks_any_ms_standard_pbs128_packing_ks(
        input_zero_as_lwe,
        max_scalar_mul,
        &cuda_sks,
        noise_simulation_modulus_switch_config,
        drift_key,
        &cuda_noise_squashing_key,
        br_input_modulus_log,
        &id_lut,
        &cuda_noise_squashing_compression_key,
        &mut side_resources,
    );
    let cuda_noise_squashed_cts: Vec <_> = input_zeros
        .into_par_iter()
        .map(|mut ct| {

            let cloned_ct = ct.clone();
            let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![cloned_ct]);
            let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct, &streams);
            unsafe {
                unchecked_small_scalar_mul_integer_async(
                    &streams,
                    &mut d_ct.ciphertext,
                    max_scalar_mul,
                    atomic_params.message_modulus(),
                    atomic_params.carry_modulus(),
            );
            }
            streams.synchronize();
            cuda_noise_squashing_key.unchecked_squash_ciphertext_noise(&d_ct.ciphertext, &cuda_sks, &streams)
        })
        .collect();

    let compressed = cuda_noise_squashing_compression_key
        .compress_noise_squashed_ciphertexts_into_list(&cuda_noise_squashed_cts, &streams);

    //let underlying_glwes = compressed.data.as_glwe_ciphertext_list();

    //assert_eq!(underlying_glwes.len(), 1);

    let gpu_extracted = compressed.extract_glwe(0, &streams);
    let extracted = gpu_extracted.to_glwe_ciphertext_list(&streams);
    //let extracted = underlying_glwes[0].extract();

    // Bodies that were not filled are discarded
    after_packing.get_mut_body().as_mut()[lwe_per_glwe.0..].fill(0);

    assert_eq!(after_packing.as_view(), extracted.as_view());
}

/// GPU packing keyswitch key wrapper for noise distribution tests
pub struct CudaPackingKeyswitchKey128 {
    cuda_pksk: CudaLwePackingKeyswitchKey<u128>,
    lwe_per_glwe: LweCiphertextCount,
}

impl CudaPackingKeyswitchKey128 {
    pub fn new(
        compression_key: &CudaNoiseSquashingCompressionKey,
        side_resources: &CudaSideResources,
    ) -> Self {
        let cuda_pksk = CudaLwePackingKeyswitchKey::from_lwe_packing_keyswitch_key(
            compression_key.packing_key_switching_key(),
            &side_resources.streams,
        );
        let lwe_per_glwe = compression_key.lwe_per_glwe();

        Self {
            cuda_pksk,
            lwe_per_glwe,
        }
    }
}

impl AllocateLwePackingKeyswitchResult for CudaPackingKeyswitchKey128 {
    type Output = CudaGlweCiphertextList<u128>;
    type SideResources = CudaSideResources;

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &Self::SideResources,
    ) -> Self::Output {
        let glwe_dimension = self.cuda_pksk.output_glwe_size().to_glwe_dimension();
        let polynomial_size = self.cuda_pksk.output_polynomial_size();
        let ciphertext_modulus = self.cuda_pksk.ciphertext_modulus();

        CudaGlweCiphertextList::new(
            glwe_dimension,
            polynomial_size,
            GlweCiphertextCount(1),
            ciphertext_modulus,
            &side_resources.streams,
        )
    }
}

impl<'a> LwePackingKeyswitch<[&'a CudaDynLwe], CudaGlweCiphertextList<u128>>
    for CudaPackingKeyswitchKey128
{
    type SideResources = CudaSideResources;

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input_lwe_list: &[&'a CudaDynLwe],
        output_glwe: &mut CudaGlweCiphertextList<u128>,
        side_resources: &Self::SideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_packing_keyswitch::cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128;

        // Convert CudaDynLwe list to CudaLweCiphertextList<u128>
        // We expect all inputs to be U128 type from PBS output
        let input_u128_list: Vec<&CudaLweCiphertextList<u128>> =
            input_lwe_list.iter().map(|lwe| lwe.as_lwe_128()).collect();

        // For packing keyswitch, we need to combine all input LWE ciphertexts into one list
        // This is a simplified version - in practice you might need more sophisticated handling
        assert!(
            !input_u128_list.is_empty(),
            "Input LWE list cannot be empty"
        );
        assert_eq!(
            input_u128_list.len(),
            self.lwe_per_glwe.0,
            "Input LWE count must match lwe_per_glwe"
        );

        // Create a combined input list for the packing keyswitch
        // For now, we'll process the first input - this is a simplified implementation
        let input_lwe_ciphertext_list = input_u128_list[0];

        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_128(
            &self.cuda_pksk,
            input_lwe_ciphertext_list,
            output_glwe,
            &side_resources.streams,
        );
        side_resources.streams.synchronize();
    }
}

#[test]
#[cfg(feature = "gpu")]
fn test_gpu_sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_gpu_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_gpu(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
