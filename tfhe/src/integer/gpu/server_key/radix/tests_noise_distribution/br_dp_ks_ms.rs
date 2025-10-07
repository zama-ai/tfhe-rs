use super::utils::noise_simulation::CudaDynLwe;
use crate::core_crypto::commons::parameters::CiphertextModulus;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::vec::GpuIndex;
use crate::core_crypto::gpu::{CudaSideResources, CudaStreams};
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_test;
use crate::integer::gpu::server_key::radix::CudaBlockInfo;
use crate::integer::gpu::server_key::CudaServerKey;
use crate::integer::gpu::unchecked_small_scalar_mul_integer_async;
use crate::integer::{CompressedServerKey, IntegerCiphertext};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::NoiseLevel;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::AtomicPatternParameters;
use crate::shortint::server_key::tests::noise_distribution::utils::encrypt_new_noiseless_lwe;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulusSwitchConfig;
use crate::shortint::{Ciphertext, ShortintParameterSet};

use crate::shortint::server_key::tests::noise_distribution::br_dp_ks_ms::br_dp_ks_any_ms_pbs;
/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint for GPU
fn sanity_check_encrypt_br_dp_ks_pbs_gpu<P>(params: P)
where
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

    let noise_simulation_modulus_switch_config = sks.key.noise_simulation_modulus_switch_config();
    let br_input_modulus_log = sks.key.br_input_modulus_log();

    let max_scalar_mul = sks.key.max_noise_level.get();

    let ms_ciphertext_modulus: CiphertextModulus<u64> =
        CiphertextModulus::try_new_power_of_2(br_input_modulus_log.0).unwrap();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let drift_key = match noise_simulation_modulus_switch_config {
        NoiseSimulationModulusSwitchConfig::Standard => None,
        NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction => Some(&cuda_sks),
        NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction => None,
    };

    let small_lwe_sk = match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            standard_atomic_pattern_client_key.lwe_secret_key.as_view()
        }
        AtomicPatternClientKey::KeySwitch32(_) => todo!(),
    };

    let block_info = CudaBlockInfo {
        degree: crate::shortint::parameters::Degree::new(1),
        message_modulus: atomic_params.message_modulus(),
        carry_modulus: atomic_params.carry_modulus(),
        atomic_pattern: crate::shortint::parameters::AtomicPatternKind::Standard(
            crate::shortint::parameters::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let ms_encoding = ShortintEncoding {
        ciphertext_modulus: ms_ciphertext_modulus,
        message_modulus: sks.message_modulus(),
        carry_modulus: sks.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let mut side_resources = CudaSideResources::new(&streams, block_info);

    for _ in 0..10 {
        let input_zero_as_lwe = ShortintEngine::with_thread_local_mut(|engine| {
            encrypt_new_noiseless_lwe(
                &small_lwe_sk,
                ms_ciphertext_modulus,
                0,
                &ms_encoding,
                &mut engine.encryption_generator,
            )
        });

        let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&input_zero_as_lwe, &streams);
        let gpu_sample_input = CudaDynLwe::U64(d_ct_input);

        let (
            _input,
            d_input_pbs_result,
            _after_dp,
            _ks_result,
            _drift_technique_result,
            _ms_result,
            output_pbs_result,
        ) = br_dp_ks_any_ms_pbs(
            gpu_sample_input,
            &cuda_sks,
            max_scalar_mul,
            &cuda_sks,
            noise_simulation_modulus_switch_config,
            drift_key,
            &d_accumulator,
            br_input_modulus_log,
            &mut side_resources,
        );

        let after_pbs_list = output_pbs_result
            .as_lwe_64()
            .to_lwe_ciphertext_list(&streams);
        let after_pbs_ct = LweCiphertext::from_container(
            after_pbs_list.clone().into_container(),
            after_pbs_list.ciphertext_modulus(),
        );
        let input_pbs_result_list = d_input_pbs_result
            .as_lwe_64()
            .to_lwe_ciphertext_list(&streams);
        let input_pbs_result = LweCiphertext::from_container(
            input_pbs_result_list.clone().into_container(),
            input_pbs_result_list.ciphertext_modulus(),
        );
        // Shortint APIs are not granular enough to compare ciphertexts at the MS level
        // and inject arbitrary LWEs as input to the blind rotate step of the PBS.
        // So we start with the output of the input PBS from our test case and finish after
        // the second PBS and not the MS from our dedicated sanity function, which are
        // boundaries that are easily reached with shortint.
        // We don't want to use that dedicated function in statistical tests as it computes
        // 2 PBSes instead of one, the output of the seoncd PBS being of no interest for
        // noise measurement here.

        let shortint_res = Ciphertext::new(
            input_pbs_result,
            id_lut.degree,
            NoiseLevel::NOMINAL,
            sks.key.message_modulus,
            sks.key.carry_modulus,
            sks.key.atomic_pattern.kind(),
        );

        let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![shortint_res]);
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

        let mut after_pbs_shortint_ct: CudaUnsignedRadixCiphertext =
            cuda_sks.create_trivial_zero_radix(1, &streams);
        unsafe {
            cuda_sks.apply_lookup_table_async(
                &mut after_pbs_shortint_ct.ciphertext,
                &d_ct.ciphertext,
                &id_lut,
                0..1,
                &streams,
            );
        }
        streams.synchronize();

        let shortint_res_list = after_pbs_shortint_ct
            .ciphertext
            .d_blocks
            .to_lwe_ciphertext_list(&streams);

        let shortint_res_ct = LweCiphertext::from_container(
            shortint_res_list.clone().into_container(),
            shortint_res_list.ciphertext_modulus(),
        );

        assert_eq!(after_pbs_ct.as_view(), shortint_res_ct.as_view());
    }
}

#[cfg(feature = "gpu")]
create_gpu_parameterized_test!(sanity_check_encrypt_br_dp_ks_pbs_gpu {
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
});
