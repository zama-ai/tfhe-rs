use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::prelude::{GlweCiphertext, LweCiphertextList};
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;

use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    DynLwe, NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey, NoiseSimulationModulusSwitchConfig,
    NoiseSimulationGlwe, NoiseSimulationGenericBootstrapKey,
};
 use crate::shortint::server_key::tests::noise_distribution::br_rerand_dp_ks_ms::br_rerand_dp_ks_any_ms;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::lwe_programmable_bootstrap::LweClassicFftBootstrap;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::lwe_programmable_bootstrap::AllocateLweBootstrapResult;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::math::random::XofSeed;
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, LweCiphertextCount, MonomialDegree,
};
use crate::core_crypto::commons::traits::contiguous_entity_container::ContiguousEntityContainer;
use crate::core_crypto::entities::LweCiphertextOwned;
use crate::shortint::ciphertext::ReRandomizationSeed;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::engine::ShortintEngine;

use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, CompressionParameters, MetaParameters,
    ShortintCompactCiphertextListCastingMode, ShortintKeySwitchingParameters,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use crate::shortint::server_key::tests::noise_distribution::{
    should_run_short_pfail_tests_debug, should_use_single_key_debug,
};
// use crate::shortint::public_key::compact::{CompactPrivateKey, CompactPublicKey};
use crate::integer::gpu::server_key::radix::tests_unsigned::create_gpu_parameterized_stringified_test;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulus;
use crate::shortint::PaddingBit;
use rayon::prelude::*;

use crate::core_crypto::gpu::CudaStreams;
use crate::integer::gpu::ciphertext::compressed_ciphertext_list::CudaCompressedCiphertextListBuilder;
use crate::integer::gpu::key_switching_key::{CudaKeySwitchingKey, CudaKeySwitchingKeyMaterial};
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::noise_simulation::CudaSideResources;
use crate::integer::gpu::CudaServerKey;
use crate::integer::key_switching_key::KeySwitchingKey;
use crate::integer::{CompactPrivateKey, CompactPublicKey, CompressedServerKey, RadixClientKey};
use crate::shortint::ShortintParameterSet;
use crate::GpuIndex;

use crate::integer::ciphertext::DataKind;
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::noise_simulation::CudaDynLwe;
use crate::integer::gpu::unchecked_small_scalar_mul_integer;
use std::num::NonZeroUsize;
//  use crate::shortint::Ciphertext;
use crate::integer::compression_keys::CompressionPrivateKeys;
use crate::integer::gpu::list_compression::server_keys::CudaDecompressionKey;
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::key_switching_test_utils::new_key_switching_key_for_pfail_test;
use crate::integer::gpu::server_key::radix::tests_noise_distribution::utils::rescaling_lut_test_utils::create_rescaling_lut;
use crate::integer::gpu::cuda_backend_rerand_assign;

use crate::core_crypto::gpu::lwe_compact_ciphertext_list::CudaLweCompactCiphertextList;
use crate::core_crypto::prelude::LweCiphertext;
use crate::integer::gpu::server_key::radix::{CudaRadixCiphertext, CudaRadixCiphertextInfo};
use crate::integer::ClientKey;
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::{
    write_empty_json_file, write_to_json_file, NoiseCheckWithNormalityCheck, TestResult,
};

use crate::this_function_name;
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_decomp_br_rerand_dp_ks_any_ms_inner_helper_gpu(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    compression_params: CompressionParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_cuda_ksk_rerand: &CudaKeySwitchingKey<'_>,
    single_comp_private_key: &CompressionPrivateKeys,
    single_cuda_decomp_key: &CudaDecompressionKey,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    (DecryptionAndNoiseResult, DecryptionAndNoiseResult),
    (DecryptionAndNoiseResult, DecryptionAndNoiseResult),
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
    DecryptionAndNoiseResult,
) {
    let mut engine = ShortintEngine::new();
    let num_blocks = 1usize;
    let thread_cpk_private_key;
    let thread_cpk;
    let thread_cuda_rerand_ksk;
    let thread_comp_private_key;
    let _thread_cuda_compression_key;
    let thread_cuda_decompression_key;
    let thread_cuda_ksk_material;
    let thread_cks;
    let thread_sks;
    let thread_cuda_sks;
    let (cpk_private_key, cpk, cuda_ksk_rerand, comp_private_key, cuda_decomp_key, cks, cuda_sks) =
        if should_use_single_key_debug() {
            (
                single_cpk_private_key,
                single_cpk,
                single_cuda_ksk_rerand,
                single_comp_private_key,
                single_cuda_decomp_key,
                single_cks,
                single_cuda_sks,
            )
        } else {
            thread_cpk_private_key = CompactPrivateKey::new(cpk_params);
            thread_cpk = CompactPublicKey::new(&thread_cpk_private_key);

            let block_params: ShortintParameterSet = params.into();
            thread_cks = crate::integer::ClientKey::new(block_params);
            let compressed_server_key =
                CompressedServerKey::new_radix_compressed_server_key(&thread_cks);
            thread_sks = compressed_server_key.decompress();
            thread_cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, streams);

            let radix_cks = RadixClientKey::from((thread_cks.clone(), num_blocks));

            let ksk = new_key_switching_key_for_pfail_test(
                (&thread_cpk_private_key, None),
                (&thread_cks, &thread_sks),
                rerand_ksk_params,
            );
            thread_cuda_ksk_material =
                CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, streams);
            thread_cuda_rerand_ksk = CudaKeySwitchingKey::from_cuda_key_switching_key_material(
                &thread_cuda_ksk_material,
                &thread_cuda_sks,
            );

            thread_comp_private_key = thread_cks.new_compression_private_key(compression_params);
            (_thread_cuda_compression_key, thread_cuda_decompression_key) = radix_cks
                .new_cuda_compression_decompression_keys(&thread_comp_private_key, streams);

            (
                &thread_cpk_private_key,
                &thread_cpk,
                &thread_cuda_rerand_ksk,
                &thread_comp_private_key,
                &thread_cuda_decompression_key,
                &thread_cks,
                &thread_cuda_sks,
            )
        };

    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();

    let ct = comp_private_key
        .key
        .encrypt_noiseless_decompression_input_dyn_lwe(&cks.key, msg, &mut engine);

    let cuda_ct = CudaDynLwe::U64(CudaLweCiphertextList::from_lwe_ciphertext(
        &ct.as_lwe_64(),
        streams,
    ));

    let cpk_ct_zero_rerand = {
        let compact_list = cpk.key.encrypt_iter_with_modulus_with_engine(
            core::iter::once(0),
            cpk.parameters().message_modulus.0,
            &mut engine,
        );
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    let cuda_cpk_ct_zero_rerand = CudaDynLwe::U64(CudaLweCiphertextList::from_lwe_ciphertext(
        &cpk_ct_zero_rerand.as_lwe_64(),
        streams,
    ));

    let decomp_rescale_lut = create_rescaling_lut(
        cuda_decomp_key,
        cuda_sks.ciphertext_modulus,
        cuda_sks.message_modulus,
        CarryModulus(1),
        cuda_sks.message_modulus,
        cuda_sks.carry_modulus,
    );
    let d_accumulator_rescale_lut =
        CudaGlweCiphertextList::from_glwe_ciphertext(&decomp_rescale_lut.acc, streams);

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(streams, cuda_block_info);
    let (
        (d_input, d_after_br),
        (d_input_zero_rerand, d_after_ksed_zero_rerand),
        d_after_rerand,
        d_after_dp,
        d_after_ks,
        d_after_drift,
        d_after_ms,
    ) = br_rerand_dp_ks_any_ms(
        cuda_ct,
        cuda_decomp_key,
        cuda_cpk_ct_zero_rerand,
        cuda_ksk_rerand,
        scalar_for_multiplication,
        cuda_sks,
        modulus_switch_config,
        &d_accumulator_rescale_lut,
        br_input_modulus_log,
        &mut cuda_side_resources,
    );

    let input = d_input.as_ct_64_cpu(streams);
    let after_br = d_after_br.as_ct_64_cpu(streams);
    let input_zero_rerand = d_input_zero_rerand.as_ct_64_cpu(streams);
    let after_ksed_zero_rerand = d_after_ksed_zero_rerand.as_ct_64_cpu(streams);
    let after_rerand = d_after_rerand.as_ct_64_cpu(streams);
    let after_dp = d_after_dp.as_ct_64_cpu(streams);
    let after_ks = d_after_ks.as_ct_64_cpu(streams);
    let after_ms = d_after_ms.as_ct_64_cpu(streams);
    let d_before_ms: &CudaDynLwe = d_after_drift.as_ref().unwrap_or(&d_after_ks);
    let before_ms = d_before_ms.as_ct_64_cpu(streams);

    match &cks.key.atomic_pattern {
        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
            let params = standard_atomic_pattern_client_key.parameters;
            let comp_encoding = ShortintEncoding {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                // Adapt to the compression which has no carry bits
                carry_modulus: CarryModulus(1),
                padding_bit: PaddingBit::Yes,
            };
            let compute_encoding = ShortintEncoding {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                padding_bit: PaddingBit::Yes,
            };

            let cpk_lwe_secret_key = cpk_private_key.key.key();
            let comp_lwe_secret_key = comp_private_key.key.post_packing_ks_key.as_lwe_secret_key();

            let large_compute_lwe_secret_key =
                standard_atomic_pattern_client_key.large_lwe_secret_key();
            let small_compute_lwe_secret_key =
                standard_atomic_pattern_client_key.small_lwe_secret_key();
            (
                (
                    DecryptionAndNoiseResult::new_from_lwe(
                        &input,
                        &comp_lwe_secret_key,
                        msg,
                        &comp_encoding,
                    ),
                    DecryptionAndNoiseResult::new_from_lwe(
                        &after_br,
                        &large_compute_lwe_secret_key,
                        msg,
                        &compute_encoding,
                    ),
                ),
                (
                    DecryptionAndNoiseResult::new_from_lwe(
                        &input_zero_rerand,
                        &cpk_lwe_secret_key,
                        msg,
                        &compute_encoding,
                    ),
                    DecryptionAndNoiseResult::new_from_lwe(
                        &after_ksed_zero_rerand,
                        &large_compute_lwe_secret_key,
                        msg,
                        &compute_encoding,
                    ),
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_rerand,
                    &large_compute_lwe_secret_key,
                    msg,
                    &compute_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_dp,
                    &large_compute_lwe_secret_key,
                    msg,
                    &compute_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ks,
                    &small_compute_lwe_secret_key,
                    msg,
                    &compute_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &before_ms,
                    &small_compute_lwe_secret_key,
                    msg,
                    &compute_encoding,
                ),
                DecryptionAndNoiseResult::new_from_lwe(
                    &after_ms,
                    &small_compute_lwe_secret_key,
                    msg,
                    &compute_encoding,
                ),
            )
        }
        AtomicPatternClientKey::KeySwitch32(_ks32_atomic_pattern_client_key) => {
            panic!("KS32 not available for GPU yet")
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_noise_helper_gpu(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    compression_params: CompressionParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: &CudaKeySwitchingKey<'_>,
    single_comp_private_key: &CompressionPrivateKeys,
    single_decomp_key: &CudaDecompressionKey,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    (NoiseSample, NoiseSample),
    (NoiseSample, NoiseSample),
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
    NoiseSample,
) {
    let (
        (input, after_br),
        (input_zero_rerand, after_ksed_zero_rerand),
        after_rerand,
        after_dp,
        after_ks,
        before_ms,
        after_ms,
    ) = encrypt_decomp_br_rerand_dp_ks_any_ms_inner_helper_gpu(
        params,
        cpk_params,
        rerand_ksk_params,
        compression_params,
        single_cpk_private_key,
        single_cpk,
        single_ksk_rerand,
        single_comp_private_key,
        single_decomp_key,
        single_cks,
        single_cuda_sks,
        msg,
        scalar_for_multiplication,
        br_input_modulus_log,
        streams,
    );

    (
        (
            input
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
            after_br
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
        ),
        (
            input_zero_rerand
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
            after_ksed_zero_rerand
                .get_noise_if_decryption_was_correct()
                .expect("Decryption Failed"),
        ),
        after_rerand
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_dp
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ks
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        before_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
        after_ms
            .get_noise_if_decryption_was_correct()
            .expect("Decryption Failed"),
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_pfail_helper_gpu(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    compression_params: CompressionParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: &CudaKeySwitchingKey<'_>,
    single_comp_private_key: &CompressionPrivateKeys,
    single_decomp_key: &CudaDecompressionKey,
    single_cks: &ClientKey,
    single_cuda_sks: &CudaServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> DecryptionAndNoiseResult {
    let (
        (_input, _after_br),
        (_input_zero_rerand, _after_ksed_zero_rerand),
        _after_rerand,
        _after_dp,
        _after_ks,
        _before_ms,
        after_ms,
    ) = encrypt_decomp_br_rerand_dp_ks_any_ms_inner_helper_gpu(
        params,
        cpk_params,
        rerand_ksk_params,
        compression_params,
        single_cpk_private_key,
        single_cpk,
        single_ksk_rerand,
        single_comp_private_key,
        single_decomp_key,
        single_cks,
        single_cuda_sks,
        msg,
        scalar_for_multiplication,
        br_input_modulus_log,
        streams,
    );

    after_ms
}

fn noise_check_encrypt_br_rerand_dp_ks_ms_noise_gpu(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, rerand_ksk_params, compression_params) = {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
                compute_params.encryption_key_choice().into_pbs_order(),
            );
            cpk_params
        };

        (
            compute_params,
            cpk_params,
            dedicated_cpk_params.re_randomization_parameters.unwrap(),
            meta_params.compression_parameters.unwrap(),
        )
    };

    let gpu_index = 0;
    let num_blocks = 1;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let radix_cks = RadixClientKey::from((cks.clone(), num_blocks));
    let ksk = KeySwitchingKey::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params);
    let cuda_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let cuda_rerand_ksk =
        CudaKeySwitchingKey::from_cuda_key_switching_key_material(&cuda_ksk_material, &cuda_sks);

    let comp_private_key = cks.new_compression_private_key(compression_params);
    let (_cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&comp_private_key, &streams);

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_ksk_rerand =
        NoiseSimulationLweKeyswitchKey::new_from_cpk_params(cpk_params, rerand_ksk_params, params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);
    let noise_simulation_decomp_bsk =
        NoiseSimulationGenericBootstrapKey::new_from_comp_parameters(params, compression_params);

    let modulus_switch_config = sks.key.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.key.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks.key));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));

    let max_scalar_mul = sks.key.max_noise_level.get();

    let (
        (_input_sim, _after_br_sim),
        (_input_zero_rerand_sim, _after_ksed_zero_rerand_sim),
        _after_rerand_sim,
        _after_dp_sim,
        _after_ks_sim,
        _after_drift_sim,
        after_ms_sim,
    ) = {
        // Noiseless LWE already mod switched is the input of the AP for testing
        let noise_simulation_input = NoiseSimulationLwe::new(
            noise_simulation_decomp_bsk.input_lwe_dimension(),
            Variance(0.0),
            NoiseSimulationModulus::Other(1 << compute_br_input_modulus_log.0),
        );
        let noise_simulation_input_zero_rerand = NoiseSimulationLwe::encrypt_with_cpk(&cpk.key);
        let noise_simulation_accumulator = NoiseSimulationGlwe::new(
            noise_simulation_decomp_bsk
                .output_glwe_size()
                .to_glwe_dimension(),
            noise_simulation_decomp_bsk.output_polynomial_size(),
            Variance(0.0),
            noise_simulation_decomp_bsk.modulus(),
        );
        br_rerand_dp_ks_any_ms(
            noise_simulation_input,
            &noise_simulation_decomp_bsk,
            noise_simulation_input_zero_rerand,
            &noise_simulation_ksk_rerand,
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            &noise_simulation_accumulator,
            compute_br_input_modulus_log,
            &mut (),
        )
    };

    let decomp_rescale_lut = create_rescaling_lut(
        &cuda_decompression_key,
        cuda_sks.ciphertext_modulus,
        cuda_sks.message_modulus,
        CarryModulus(1),
        cuda_sks.message_modulus,
        cuda_sks.carry_modulus,
    );
    let d_accumulator_rescale_lut =
        CudaGlweCiphertextList::from_glwe_ciphertext(&decomp_rescale_lut.acc, &streams);

    let sample_input = ShortintEngine::with_thread_local_mut(|engine| {
        comp_private_key
            .key
            .encrypt_noiseless_decompression_input_dyn_lwe(&cks.key, 0, engine)
    });

    let cuda_sample_input = CudaDynLwe::U64(CudaLweCiphertextList::from_lwe_ciphertext(
        &sample_input.as_lwe_64(),
        &streams,
    ));

    let cpk_zero_sample_input = {
        let compact_list = cpk.key.encrypt_slice(&[0]);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };
    let cuda_cpk_zero_sample_input = CudaDynLwe::U64(CudaLweCiphertextList::from_lwe_ciphertext(
        &cpk_zero_sample_input.as_lwe_64(),
        &streams,
    ));
    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(&streams, cuda_block_info);
    let cuda_modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();
    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let (
            (_input, _after_br),
            (_input_zero_rerand, _after_ksed_zero_rerand),
            _after_rerand,
            _after_dp,
            _after_ks,
            _before_ms,
            d_after_ms,
        ) = br_rerand_dp_ks_any_ms(
            cuda_sample_input,
            &cuda_decompression_key,
            cuda_cpk_zero_sample_input,
            &cuda_rerand_ksk,
            max_scalar_mul,
            &cuda_sks,
            cuda_modulus_switch_config,
            &d_accumulator_rescale_lut,
            compute_br_input_modulus_log,
            &mut cuda_side_resources,
        );

        let after_ms = d_after_ms.as_ct_64_cpu(&streams);
        (
            after_ms.lwe_size().to_lwe_dimension(),
            after_ms.ciphertext_modulus().raw_modulus_float(),
        )
    };

    assert_eq!(after_ms_sim.lwe_dimension(), expected_lwe_dimension_out);
    assert_eq!(after_ms_sim.modulus().as_f64(), expected_modulus_f64_out);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_before_ms = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1000;
    let chunk_size = 8;
    let vec_local_streams = (0..chunk_size)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();
    for _ in 0..cleartext_modulus {
        let (current_noise_sample_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..sample_count_per_msg)
            .collect::<Vec<_>>()
            .chunks(chunk_size)
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .collect::<Vec<_>>()
                    .into_par_iter()
                    .map(|i| {
                        let local_stream = &vec_local_streams[*i % chunk_size];
                        let (
                            (_input, _after_br),
                            (_input_zero_rerand, _after_ksed_zero_rerand),
                            _after_rerand,
                            _after_dp,
                            _after_ks,
                            before_ms,
                            after_ms,
                        ) = encrypt_br_rerand_dp_ks_any_ms_noise_helper_gpu(
                            params,
                            cpk_params,
                            rerand_ksk_params,
                            compression_params,
                            &cpk_private_key,
                            &cpk,
                            &cuda_rerand_ksk,
                            &comp_private_key,
                            &cuda_decompression_key,
                            &cks,
                            &cuda_sks,
                            0,
                            max_scalar_mul,
                            compute_br_input_modulus_log,
                            local_stream,
                        );
                        (before_ms.value, after_ms.value)
                    })
                    .collect::<Vec<_>>()
            })
            .unzip();

        noise_samples_before_ms.extend(current_noise_sample_before_ms);
        noise_samples_after_ms.extend(current_noise_samples_after_ms);
    }

    let before_ms_normality = normality_check(&noise_samples_before_ms, "before ms", 0.01);

    let (after_ms_is_ok, bounded_variance_measurement, bounded_mean_measurement) =
        mean_and_variance_check(
            &noise_samples_after_ms,
            "after_ms",
            expected_average_after_ms,
            after_ms_sim.variance(),
            params.lwe_noise_distribution(),
            after_ms_sim.lwe_dimension(),
            after_ms_sim.modulus().as_f64(),
        );
    let before_ms_normality_valid = before_ms_normality.null_hypothesis_is_valid;

    let noise_check_valid = before_ms_normality_valid && after_ms_is_ok;

    let noise_check =
        TestResult::NoiseCheckWithNormalityCheck(Box::new(NoiseCheckWithNormalityCheck::new(
            bounded_variance_measurement,
            bounded_mean_measurement,
            before_ms_normality_valid,
        )));

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        noise_check_valid,
        None,
        noise_check,
    )
    .unwrap();

    assert!(noise_check_valid);
}

create_gpu_parameterized_stringified_test!(noise_check_encrypt_br_rerand_dp_ks_ms_noise_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_br_rerand_dp_ks_ms_pfail_gpu(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, rerand_ksk_params, compression_params) = {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
                compute_params.encryption_key_choice().into_pbs_order(),
            );
            cpk_params
        };

        (
            compute_params,
            cpk_params,
            dedicated_cpk_params.re_randomization_parameters.unwrap(),
            meta_params.compression_parameters.unwrap(),
        )
    };

    let (pfail_test_meta, params, compression_params) = {
        let mut ap_params = params;

        let original_message_modulus = ap_params.message_modulus();
        let original_carry_modulus = ap_params.carry_modulus();

        // For now only allow 2_2 parameters, and see later for heuristics to use
        assert_eq!(original_message_modulus.0, 4);
        assert_eq!(original_carry_modulus.0, 4);

        // Update parameters to fail more frequently by inflating the carry modulus, allows to keep
        // the max multiplication without risks of message overflow
        let (original_pfail_and_precision, new_expected_pfail_and_precision) =
            update_ap_params_for_pfail(
                &mut ap_params,
                original_message_modulus,
                CarryModulus(1 << 5),
            );

        let pfail_test_meta = if should_run_short_pfail_tests_debug() {
            let expected_fails = 200;
            PfailTestMeta::new_with_desired_expected_fails(
                original_pfail_and_precision,
                new_expected_pfail_and_precision,
                expected_fails,
            )
        } else {
            let total_runs = 1_000_000;
            PfailTestMeta::new_with_total_runs(
                original_pfail_and_precision,
                new_expected_pfail_and_precision,
                total_runs,
            )
        };

        (pfail_test_meta, ap_params, compression_params)
    };
    let gpu_index = 0;
    let num_blocks = 1;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let radix_cks = RadixClientKey::from((cks.clone(), num_blocks));

    let ksk = new_key_switching_key_for_pfail_test(
        (&cpk_private_key, None),
        (&cks, &sks),
        rerand_ksk_params,
    );
    let cuda_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let cuda_rerand_ksk =
        CudaKeySwitchingKey::from_cuda_key_switching_key_material(&cuda_ksk_material, &cuda_sks);

    let comp_private_key = cks.new_compression_private_key(compression_params);
    let (_cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&comp_private_key, &streams);

    let max_scalar_mul = sks.key.max_noise_level.get();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();
    let chunk_size = 8;
    let vec_local_streams = (0..chunk_size)
        .map(|_| CudaStreams::new_single_gpu(GpuIndex::new(gpu_index)))
        .collect::<Vec<_>>();
    let br_input_modulus_log = sks.key.br_input_modulus_log();
    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .collect::<Vec<_>>()
        .chunks(chunk_size)
        .flat_map(|chunk| {
            chunk
                .iter()
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|i| {
                    let local_stream = &vec_local_streams[*i as usize % chunk_size];
                    let after_ms_decryption_result =
                        encrypt_br_rerand_dp_ks_any_ms_pfail_helper_gpu(
                            params,
                            cpk_params,
                            rerand_ksk_params,
                            compression_params,
                            &cpk_private_key,
                            &cpk,
                            &cuda_rerand_ksk,
                            &comp_private_key,
                            &cuda_decompression_key,
                            &cks,
                            &cuda_sks,
                            0,
                            max_scalar_mul,
                            br_input_modulus_log,
                            local_stream,
                        );
                    after_ms_decryption_result.failure_as_f64()
                })
                .collect::<Vec<_>>()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(
        &pfail_test_meta,
        test_result,
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    );
}

create_gpu_parameterized_stringified_test!(noise_check_encrypt_br_rerand_dp_ks_ms_pfail_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn sanity_check_encrypt_br_rerand_dp_ks_ms_pbs_gpu(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, rerand_ksk_params, compression_params) = {
        let compute_params = meta_params.compute_parameters;
        let dedicated_cpk_params = meta_params.dedicated_compact_public_key_parameters.unwrap();
        // To avoid the expand logic of shortint which would force a keyswitch + LUT eval after
        // expand
        let cpk_params = {
            let mut cpk_params = dedicated_cpk_params.pke_params;
            cpk_params.expansion_kind = CompactCiphertextListExpansionKind::NoCasting(
                compute_params.encryption_key_choice().into_pbs_order(),
            );
            cpk_params
        };

        (
            compute_params,
            cpk_params,
            dedicated_cpk_params.re_randomization_parameters.unwrap(),
            meta_params.compression_parameters.unwrap(),
        )
    };
    let gpu_index = 0;
    let num_blocks = 1;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));
    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let radix_cks = RadixClientKey::from((cks.clone(), num_blocks));
    let ksk = KeySwitchingKey::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params);
    let cuda_ksk_material = CudaKeySwitchingKeyMaterial::from_key_switching_key(&ksk, &streams);
    let cuda_rerand_ksk =
        CudaKeySwitchingKey::from_cuda_key_switching_key_material(&cuda_ksk_material, &cuda_sks);

    let comp_private_key = cks.new_compression_private_key(compression_params);
    let (cuda_compression_key, cuda_decompression_key) =
        radix_cks.new_cuda_compression_decompression_keys(&comp_private_key, &streams);

    let modulus_switch_config = cuda_sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.key.br_input_modulus_log();

    let max_scalar_mul = cuda_sks.max_noise_level.get();

    let decomp_rescale_lut = create_rescaling_lut(
        &cuda_decompression_key,
        cuda_sks.ciphertext_modulus,
        cuda_sks.message_modulus,
        CarryModulus(1),
        cuda_sks.message_modulus,
        cuda_sks.carry_modulus,
    );

    let d_accumulator_rescale_lut =
        CudaGlweCiphertextList::from_glwe_ciphertext(&decomp_rescale_lut.acc, &streams);

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);
    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(params.message_modulus().0 - 1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: params.atomic_pattern(),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources = CudaSideResources::new(&streams, cuda_block_info);

    type SanityVec = (LweCiphertext<Vec<u64>>, LweCiphertext<Vec<u64>>);
    let mut results: Vec<SanityVec> = Vec::new();
    for idx in 0..10 {
        let seed_bytes = vec![idx as u8; 256 / 8];
        let rerand_xof_seed = XofSeed::new(seed_bytes, *b"TFHE_Enc");

        // Manually build as the seed is made non Clone to protect user normally
        let noise_simulation_rerand_seed = ReRandomizationSeed(rerand_xof_seed.clone());

        let sample_input = ShortintEngine::with_thread_local_mut(|engine| {
            comp_private_key
                .key
                .encrypt_noiseless_decompression_input_dyn_lwe(&cks.key, 0, engine)
        });
        let sample_lwe_dimension = sample_input.lwe_dimension();

        let h_ct_list = LweCiphertextList::from_container(
            sample_input.as_lwe_64().into_container(),
            sample_input.as_lwe_64().lwe_size(),
            sample_input.as_lwe_64().ciphertext_modulus(),
        );
        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(
            &h_ct_list,
            &cuda_side_resources.streams,
        );

        let gpu_sample_ct = CudaUnsignedRadixCiphertext {
            ciphertext: CudaRadixCiphertext {
                d_blocks,
                info: CudaRadixCiphertextInfo {
                    blocks: [cuda_side_resources.block_info].to_vec(),
                },
            },
        };

        let mut builder = CudaCompressedCiphertextListBuilder::new();
        builder.push(gpu_sample_ct, &cuda_side_resources.streams);
        let cuda_compressed_list =
            builder.build(&cuda_compression_key, &cuda_side_resources.streams);

        let cuda_extracted_glwe = cuda_compressed_list
            .packed_list
            .extract_glwe(0, &cuda_side_resources.streams);

        let cpu_extracted_glwe =
            cuda_extracted_glwe.to_glwe_ciphertext_list(&cuda_side_resources.streams);
        let mut tmp = LweCiphertextOwned::new(
            0u64,
            sample_lwe_dimension.to_lwe_size(),
            cpu_extracted_glwe.ciphertext_modulus(),
        );

        let glwe_ct = GlweCiphertext::from_container(
            cpu_extracted_glwe.clone().into_container(),
            cpu_extracted_glwe.polynomial_size(),
            cpu_extracted_glwe.ciphertext_modulus(),
        );
        extract_lwe_sample_from_glwe_ciphertext(&glwe_ct, &mut tmp, MonomialDegree(0));

        let new_cuda_sample_lwe_list = CudaLweCiphertextList::from_lwe_ciphertext(
            &tmp.as_view(),
            &cuda_side_resources.streams,
        );

        let new_sample_pattern = CudaDynLwe::U64(new_cuda_sample_lwe_list);

        let recovered = cuda_decompression_key
            .unpack(
                &cuda_compressed_list.packed_list,
                DataKind::Unsigned(NonZeroUsize::new(num_blocks).unwrap()),
                0,
                0,
                &cuda_side_resources.streams,
            )
            .unwrap();

        let mut cuda_shortint_res = recovered.duplicate(&cuda_side_resources.streams);

        let (cpk_zero_sample_input, cpk_cuda_compact_list) = {
            let compact_list = cpk
                .key
                .prepare_cpk_zero_for_rerand(noise_simulation_rerand_seed, LweCiphertextCount(1));
            let cuda_zeros_compact_list =
                CudaLweCompactCiphertextList::from_lwe_compact_ciphertext_list(
                    &compact_list,
                    &cuda_side_resources.streams,
                );

            let zero_list = compact_list.expand_into_lwe_ciphertext_list();

            let zero = zero_list.get(0);

            let zero_cpu = LweCiphertextOwned::from_container(
                zero.as_ref().to_vec(),
                zero.ciphertext_modulus(),
            );

            (
                CudaDynLwe::U64(CudaLweCiphertextList::from_lwe_ciphertext(
                    &zero_cpu,
                    &cuda_side_resources.streams,
                )),
                cuda_zeros_compact_list,
            )
        };
        let first_info = cuda_shortint_res.info.blocks.first().unwrap();
        let message_modulus = first_info.message_modulus;
        let carry_modulus = first_info.carry_modulus;

        let ct_count = cuda_shortint_res.d_blocks.lwe_ciphertext_count().0 as u32;

        unsafe {
            cuda_backend_rerand_assign(
                &cuda_side_resources.streams,
                &mut cuda_shortint_res.d_blocks,
                &cpk_cuda_compact_list,
                &cuda_ksk_material.lwe_keyswitch_key,
                message_modulus,
                carry_modulus,
                cuda_ksk_material
                    .lwe_keyswitch_key
                    .input_key_lwe_size()
                    .to_lwe_dimension(),
                cuda_ksk_material
                    .lwe_keyswitch_key
                    .output_key_lwe_size()
                    .to_lwe_dimension(),
                cuda_ksk_material
                    .lwe_keyswitch_key
                    .decomposition_level_count(),
                cuda_ksk_material.lwe_keyswitch_key.decomposition_base_log(),
                ct_count,
            );
        }

        unchecked_small_scalar_mul_integer(
            &cuda_side_resources.streams,
            &mut cuda_shortint_res,
            max_scalar_mul,
            cuda_side_resources.block_info.message_modulus,
            cuda_side_resources.block_info.carry_modulus,
        );

        let mut cuda_shortint_after_pbs = cuda_shortint_res.duplicate(&cuda_side_resources.streams);
        cuda_sks.apply_lookup_table(
            &mut cuda_shortint_after_pbs,
            &cuda_shortint_res,
            &id_lut,
            0..1,
            &cuda_side_resources.streams,
        );

        let (
            (_input, _after_br),
            (_input_zero_rerand, _after_ksed_zero_rerand),
            _after_rerand,
            _after_dp,
            _after_ks,
            _before_ms,
            after_ms,
        ) = br_rerand_dp_ks_any_ms(
            new_sample_pattern,
            &cuda_decompression_key,
            cpk_zero_sample_input,
            &cuda_rerand_ksk,
            max_scalar_mul,
            &cuda_sks,
            modulus_switch_config,
            &d_accumulator_rescale_lut,
            compute_br_input_modulus_log,
            &mut cuda_side_resources,
        );

        // Complete the AP by computing the PBS to match shortint
        let mut pbs_result = d_accumulator.allocate_lwe_bootstrap_result(&mut cuda_side_resources);
        cuda_sks.lwe_classic_fft_pbs(
            &after_ms,
            &mut pbs_result,
            &d_accumulator,
            &mut cuda_side_resources,
        );

        let pbs_result_list = pbs_result.as_ct_64_cpu(&streams);
        let shortint_res = CudaDynLwe::U64(cuda_shortint_after_pbs.d_blocks).as_ct_64_cpu(&streams);
        // let shortint_res =
        // cuda_shortint_after_pbs.d_blocks.as_lwe_ciphertext_list(&cuda_side_resources.streams).
        // to_lwe_ciphertext_list(&cuda_side_resources.streams).as_view().to_owned();

        results.push((pbs_result_list, shortint_res));
    }

    let res_cond = results
        .iter()
        .all(|(lhs, rhs)| lhs.as_view() == rhs.as_view());

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        res_cond,
        None,
        TestResult::Empty {},
    )
    .unwrap();
    // We check each step to preserve failure details and print the invalid case if one occurs
    for (after_pbs_ct, shortint_res_ct) in results.iter() {
        assert_eq!(after_pbs_ct.as_view(), shortint_res_ct.as_view());
    }
}

create_gpu_parameterized_stringified_test!(sanity_check_encrypt_br_rerand_dp_ks_ms_pbs_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});
