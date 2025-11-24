use super::utils::noise_simulation::CudaDynLwe;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateLwePackingKeyswitchResult, AllocateStandardModSwitchResult, LwePackingKeyswitch,
    StandardModSwitch,
};
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_packing_keyswitch_key::CudaLwePackingKeyswitchKey;
use crate::core_crypto::gpu::{cuda_modulus_switch_ciphertext, CudaSideResources, CudaStreams};
use crate::core_crypto::prelude::{
    GlweCiphertext, GlweCiphertextCount, LweCiphertext, LweCiphertextCount,
};
use crate::integer::compression_keys::CompressionPrivateKeys;
use crate::integer::gpu::list_compression::server_keys::CudaCompressionKey;
use crate::integer::gpu::server_key::radix::CudaUnsignedRadixCiphertext;
use crate::integer::gpu::CudaServerKey;
use crate::integer::{ClientKey, CompressedServerKey, IntegerCiphertext, ServerKey};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::{Ciphertext, Degree, NoiseLevel};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use crate::shortint::parameters::{CompressionParameters, MetaParameters, Variance};
use crate::shortint::server_key::tests::noise_distribution::br_dp_packingks_ms::br_dp_packing_ks_ms;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::{
    NoiseSimulationGlwe, NoiseSimulationLwe, NoiseSimulationLweFourierBsk,
    NoiseSimulationLwePackingKeyswitchKey, NoiseSimulationModulus,
};
use crate::shortint::server_key::tests::noise_distribution::utils::{
    expected_pfail_for_precision, mean_and_variance_check, normality_check, pfail_check,
    precision_with_padding, update_ap_params_msg_and_carry_moduli, DecryptionAndNoiseResult,
    NoiseSample, PfailAndPrecision, PfailTestMeta, PfailTestResult,
};
use crate::shortint::server_key::tests::noise_distribution::{
    should_run_short_pfail_tests_debug, should_use_single_key_debug,
};
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
use crate::shortint::{
    AtomicPatternParameters, CarryModulus, MessageModulus, PaddingBit, ShortintEncoding,
    ShortintParameterSet,
};
use crate::GpuIndex;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

fn sanity_check_encrypt_br_dp_packing_ks_ms(meta_params: MetaParameters) {
    let (params, comp_params) = (
        meta_params.compute_parameters,
        meta_params.compression_parameters.unwrap(),
    );
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let private_compression_key = cks.new_compression_private_key(comp_params);
    let (compressed_compression_key, compressed_decompression_key) =
        cks.new_compressed_compression_decompression_keys(&private_compression_key);
    let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);
    let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
        cks.parameters().glwe_dimension(),
        cks.parameters().polynomial_size(),
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
        cks.parameters().ciphertext_modulus(),
        &streams,
    );

    let lwe_per_glwe = cuda_compression_key.lwe_per_glwe;
    // The multiplication done in the compression is made to move the message up at the top of the
    // carry space, multiplying by the carry modulus achieves that
    let dp_scalar = params.carry_modulus().0;
    let br_input_modulus_log = sks.key.br_input_modulus_log();
    let storage_modulus_log = cuda_compression_key.storage_log_modulus;

    let id_lut = sks.key.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0)
        .map(|_| {
            cks.key
                .encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0)
        })
        .collect();
    let d_input_zeros: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&ct.as_lwe_64(), &streams);
            CudaDynLwe::U64(d_ct_input)
        })
        .collect();

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources: Vec<CudaSideResources> = (0..input_zeros.len())
        .map(|_| CudaSideResources::new(&streams, cuda_block_info))
        .collect();

    let cuda_packing_key =
        CudaPackingKeyswitchKey64::new(&cuda_compression_key, &mut cuda_side_resources[0]);

    let (d_before_packing, _after_packing, d_after_ms) = br_dp_packing_ks_ms(
        d_input_zeros,
        &cuda_sks,
        &d_accumulator,
        dp_scalar,
        &cuda_packing_key,
        storage_modulus_log,
        &mut cuda_side_resources,
    );

    let compression_inputs: Vec<_> = d_before_packing
        .into_iter()
        .map(|(_input, pbs_result, _dp_result)| {
            let pbs_result_list_cpu = pbs_result.as_lwe_64().to_lwe_ciphertext_list(&streams);
            let pbs_result_cpu = LweCiphertext::from_container(
                pbs_result_list_cpu.clone().into_container(),
                pbs_result_list_cpu.ciphertext_modulus(),
            );
            let cpu_ct = Ciphertext::new(
                pbs_result_cpu,
                Degree::new(sks.message_modulus().0 - 1),
                NoiseLevel::NOMINAL,
                sks.message_modulus(),
                sks.carry_modulus(),
                sks.key.atomic_pattern.kind(),
            );
            let radix_ct = crate::integer::RadixCiphertext::from_blocks(vec![cpu_ct]);
            let mut d_ct = CudaUnsignedRadixCiphertext::from_radix_ciphertext(&radix_ct, &streams);
            d_ct.ciphertext
        })
        .collect();

    let gpu_compressed =
        cuda_compression_key.compress_ciphertexts_into_list(&compression_inputs, &streams);

    let gpu_extracted = gpu_compressed.extract_glwe(0, &streams);
    let extracted_list = gpu_extracted.to_glwe_ciphertext_list(&streams);
    let extracted_glwe = GlweCiphertext::from_container(
        extracted_list.clone().into_container(),
        extracted_list.polynomial_size(),
        extracted_list.ciphertext_modulus(),
    );
    let after_ms_list = d_after_ms.to_glwe_ciphertext_list(&streams);
    let mut after_ms = GlweCiphertext::from_container(
        after_ms_list.clone().into_container(),
        after_ms_list.polynomial_size(),
        after_ms_list.ciphertext_modulus(),
    );
    // Bodies that were not filled are discarded
    after_ms.get_mut_body().as_mut()[lwe_per_glwe.0..].fill(0);

    assert_eq!(after_ms.as_view(), extracted_glwe.as_view());
}

create_parameterized_test!(sanity_check_encrypt_br_dp_packing_ks_ms {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    //TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

#[allow(clippy::type_complexity)]
fn encrypt_br_dp_packing_ks_ms_inner_helper_gpu(
    params: AtomicPatternParameters,
    comp_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_cuda_sks: &CudaServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_cuda_compression_key: &CudaCompressionKey,
    msg: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    Vec<(
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
    )>,
    Vec<DecryptionAndNoiseResult>,
    Vec<DecryptionAndNoiseResult>,
) {
    let mut engine = ShortintEngine::new();
    let thread_cks: crate::integer::ClientKey;
    let thread_sks: crate::integer::ServerKey;
    let thread_cuda_sks: CudaServerKey;
    let thread_sks;
    let thread_compression_private_key;
    let thread_cuda_compression_key;
    let (cks, sks, cuda_sks, compression_private_key, cuda_compression_key) =
        if should_use_single_key_debug() {
            (
                single_cks,
                single_sks,
                single_cuda_sks,
                single_compression_private_key,
                single_cuda_compression_key,
            )
        } else {
            let block_params: ShortintParameterSet = params.into();
            thread_cks = crate::integer::ClientKey::new(block_params);
            let compressed_server_key =
                CompressedServerKey::new_radix_compressed_server_key(&thread_cks);
            thread_sks = compressed_server_key.decompress();
            thread_cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

            thread_compression_private_key = thread_cks.new_compression_private_key(comp_params);
            let (compressed_compression_key, compressed_decompression_key) = thread_cks
                .new_compressed_compression_decompression_keys(&thread_compression_private_key);
            thread_cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);

            (
                &thread_cks,
                &thread_sks,
                &thread_cuda_sks,
                &thread_compression_private_key,
                &thread_cuda_compression_key,
            )
        };

    let lwe_per_glwe = cuda_compression_key.lwe_per_glwe;

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0)
        .map(|_| {
            cks.key.encrypt_noiseless_pbs_input_dyn_lwe_with_engine(
                br_input_modulus_log,
                msg,
                &mut engine,
            )
        })
        .collect();

    let d_input_zeros: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&ct.as_lwe_64(), &streams);
            CudaDynLwe::U64(d_ct_input)
        })
        .collect();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources: Vec<CudaSideResources> = (0..input_zeros.len())
        .map(|_| CudaSideResources::new(&streams, cuda_block_info))
        .collect();

    let cuda_packing_key =
        CudaPackingKeyswitchKey64::new(&cuda_compression_key, &mut cuda_side_resources[0]);

    //let mut side_resources = vec![(); input_zeros.len()];
    let dp_scalar = params.carry_modulus().0;
    let storage_modulus_log = cuda_compression_key.storage_log_modulus;

    let (d_before_packing, d_after_packing, d_after_ms) = br_dp_packing_ks_ms(
        d_input_zeros,
        cuda_sks,
        &d_accumulator,
        dp_scalar,
        &cuda_packing_key,
        storage_modulus_log,
        &mut cuda_side_resources,
    );

    let compute_large_lwe_secret_key = cks.key.encryption_key();
    let compression_glwe_secret_key = &compression_private_key.key.post_packing_ks_key;

    let compute_encoding = sks.key.encoding(PaddingBit::Yes);
    let compression_encoding = ShortintEncoding {
        carry_modulus: CarryModulus(1),
        ..compute_encoding
    };
    let after_packing_list = d_after_packing.to_glwe_ciphertext_list(&streams);
    let after_packing = GlweCiphertext::from_container(
        after_packing_list.clone().into_container(),
        after_packing_list.polynomial_size(),
        after_packing_list.ciphertext_modulus(),
    );
    let after_ms_list = d_after_ms.to_glwe_ciphertext_list(&streams);
    let after_ms = GlweCiphertext::from_container(
        after_ms_list.clone().into_container(),
        after_ms_list.polynomial_size(),
        after_ms_list.ciphertext_modulus(),
    );
    (
        d_before_packing
            .into_iter()
            .map(|(d_input, d_pbs_result, d_dp_result)| {
                let input_list = d_input.as_lwe_64().to_lwe_ciphertext_list(&streams);
                let input = LweCiphertext::from_container(
                    input_list.clone().into_container(),
                    input_list.ciphertext_modulus(),
                );
                let pbs_result_list = d_pbs_result.as_lwe_64().to_lwe_ciphertext_list(&streams);
                let pbs_result = LweCiphertext::from_container(
                    pbs_result_list.clone().into_container(),
                    pbs_result_list.ciphertext_modulus(),
                );
                let dp_result_list = d_dp_result.as_lwe_64().to_lwe_ciphertext_list(&streams);
                let dp_result = LweCiphertext::from_container(
                    dp_result_list.clone().into_container(),
                    dp_result_list.ciphertext_modulus(),
                );
                (
                    match &cks.key.atomic_pattern {
                        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
                            DecryptionAndNoiseResult::new_from_lwe(
                                &input,
                                &standard_atomic_pattern_client_key.lwe_secret_key,
                                msg,
                                &compute_encoding,
                            )
                        }
                        AtomicPatternClientKey::KeySwitch32(ks32_atomic_pattern_client_key) => {
                            panic!("KS32 Atomic Pattern not supported on GPU tests yet");
                            // let ks32_params = ks32_atomic_pattern_client_key.parameters;
                            // let compute_encoding_32 = ShortintEncoding {
                            //     ciphertext_modulus:
                            // ks32_params.post_keyswitch_ciphertext_modulus,
                            //     message_modulus: ks32_params.message_modulus,
                            //     carry_modulus: ks32_params.carry_modulus,
                            //     padding_bit: PaddingBit::Yes,
                            // };

                            // DecryptionAndNoiseResult::new_from_lwe(
                            //     input.as_ref_32(),
                            //     &ks32_atomic_pattern_client_key.lwe_secret_key,
                            //     msg.try_into().unwrap(),
                            //     &compute_encoding_32,
                            // )
                        }
                    },
                    DecryptionAndNoiseResult::new_from_lwe(
                        &pbs_result,
                        &compute_large_lwe_secret_key,
                        msg,
                        &compute_encoding,
                    ),
                    DecryptionAndNoiseResult::new_from_lwe(
                        &dp_result,
                        &compute_large_lwe_secret_key,
                        msg,
                        &compression_encoding,
                    ),
                )
            })
            .collect(),
        DecryptionAndNoiseResult::new_from_glwe(
            &after_packing,
            compression_glwe_secret_key,
            compression_private_key.key.params.lwe_per_glwe(),
            msg,
            &compression_encoding,
        ),
        DecryptionAndNoiseResult::new_from_glwe(
            &after_ms,
            compression_glwe_secret_key,
            compression_private_key.key.params.lwe_per_glwe(),
            msg,
            &compression_encoding,
        ),
    )
}

#[allow(clippy::type_complexity)]
fn encrypt_br_dp_packing_ks_ms_noise_helper_gpu(
    params: AtomicPatternParameters,
    comp_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_cuda_sks: &CudaServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_cuda_compression_key: &CudaCompressionKey,
    msg: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> (
    Vec<(NoiseSample, NoiseSample, NoiseSample)>,
    Vec<NoiseSample>,
    Vec<NoiseSample>,
) {
    let (before_packing, after_packing, after_ms) = encrypt_br_dp_packing_ks_ms_inner_helper_gpu(
        params,
        comp_params,
        single_cks,
        single_sks,
        single_cuda_sks,
        single_compression_private_key,
        single_cuda_compression_key,
        msg,
        br_input_modulus_log,
        streams,
    );

    (
        before_packing
            .into_iter()
            .map(|(input, after_pbs, after_dp)| {
                (
                    input
                        .get_noise_if_decryption_was_correct()
                        .expect("Decryption Failed"),
                    after_pbs
                        .get_noise_if_decryption_was_correct()
                        .expect("Decryption Failed"),
                    after_dp
                        .get_noise_if_decryption_was_correct()
                        .expect("Decryption Failed"),
                )
            })
            .collect(),
        after_packing
            .into_iter()
            .map(|x| {
                x.get_noise_if_decryption_was_correct()
                    .expect("Decryption Failed")
            })
            .collect(),
        after_ms
            .into_iter()
            .map(|x| {
                x.get_noise_if_decryption_was_correct()
                    .expect("Decryption Failed")
            })
            .collect(),
    )
}

#[allow(clippy::type_complexity)]
fn encrypt_br_dp_packing_ks_ms_pfail_helper_gpu(
    params: AtomicPatternParameters,
    comp_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_cuda_sks: &CudaServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_cuda_compression_key: &CudaCompressionKey,
    msg: u64,
    br_input_modulus_log: CiphertextModulusLog,
    streams: &CudaStreams,
) -> Vec<DecryptionAndNoiseResult> {
    let (_before_packing, _after_packing, after_ms) = encrypt_br_dp_packing_ks_ms_inner_helper_gpu(
        params,
        comp_params,
        single_cks,
        single_sks,
        single_cuda_sks,
        single_compression_private_key,
        single_cuda_compression_key,
        msg,
        br_input_modulus_log,
        streams,
    );

    after_ms
}

fn noise_check_encrypt_br_dp_packing_ks_ms_noise_gpu(meta_params: MetaParameters) {
    let (params, comp_params) = (
        meta_params.compute_parameters,
        meta_params.compression_parameters.unwrap(),
    );
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let private_compression_key = cks.new_compression_private_key(comp_params);
    let (compressed_compression_key, compressed_decompression_key) =
        cks.new_compressed_compression_decompression_keys(&private_compression_key);
    let compression_key = compressed_compression_key.decompress();
    let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);
    let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
        cks.parameters().glwe_dimension(),
        cks.parameters().polynomial_size(),
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
        cks.parameters().ciphertext_modulus(),
        &streams,
    );

    let noise_simulation_bsk =
        NoiseSimulationLweFourierBsk::new_from_atomic_pattern_parameters(params);
    let noise_simulation_packing_key =
        NoiseSimulationLwePackingKeyswitchKey::new_from_comp_parameters(params, comp_params);

    assert!(noise_simulation_bsk.matches_actual_shortint_server_key(&sks.key));
    assert!(noise_simulation_packing_key.matches_actual_shortint_comp_key(&compression_key.key));

    // The multiplication done in the compression is made to move the message up at the top of the
    // carry space, multiplying by the carry modulus achieves that
    let dp_scalar = params.carry_modulus().0;

    let noise_simulation_accumulator = NoiseSimulationGlwe::new(
        noise_simulation_bsk.output_glwe_size().to_glwe_dimension(),
        noise_simulation_bsk.output_polynomial_size(),
        Variance(0.0),
        noise_simulation_bsk.modulus(),
    );

    let lwe_per_glwe = cuda_compression_key.lwe_per_glwe;
    let storage_modulus_log = cuda_compression_key.storage_log_modulus;
    let br_input_modulus_log = sks.key.br_input_modulus_log();

    let (_before_packing_sim, _after_packing_sim, after_ms_sim) = {
        let noise_simulation = NoiseSimulationLwe::new(
            cks.parameters().lwe_dimension(),
            Variance(0.0),
            NoiseSimulationModulus::from_ciphertext_modulus(cks.parameters().ciphertext_modulus()),
        );
        br_dp_packing_ks_ms(
            vec![noise_simulation; lwe_per_glwe.0],
            &noise_simulation_bsk,
            &noise_simulation_accumulator,
            dp_scalar,
            &noise_simulation_packing_key,
            storage_modulus_log,
            &mut vec![(); lwe_per_glwe.0],
        )
    };

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0)
        .map(|_| {
            cks.key
                .encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0)
        })
        .collect();

    let d_input_zeros: Vec<_> = input_zeros
        .iter()
        .map(|ct| {
            let d_ct_input = CudaLweCiphertextList::from_lwe_ciphertext(&ct.as_lwe_64(), &streams);
            CudaDynLwe::U64(d_ct_input)
        })
        .collect();

    let id_lut = cuda_sks.generate_lookup_table(|x| x);
    let d_accumulator = CudaGlweCiphertextList::from_glwe_ciphertext(&id_lut.acc, &streams);

    let cuda_block_info = crate::integer::gpu::ciphertext::info::CudaBlockInfo {
        degree: crate::shortint::ciphertext::Degree::new(1),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        atomic_pattern: crate::shortint::AtomicPatternKind::Standard(
            crate::shortint::PBSOrder::KeyswitchBootstrap,
        ),
        noise_level: crate::shortint::parameters::NoiseLevel::NOMINAL,
    };
    let mut cuda_side_resources: Vec<CudaSideResources> = (0..input_zeros.len())
        .map(|_| CudaSideResources::new(&streams, cuda_block_info))
        .collect();

    let cuda_packing_key =
        CudaPackingKeyswitchKey64::new(&cuda_compression_key, &mut cuda_side_resources[0]);
    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_glwe_size_out, expected_polynomial_size_out, expected_modulus_f64_out) = {
        let (_before_packing_sim, _after_packing, after_ms) = br_dp_packing_ks_ms(
            d_input_zeros,
            &cuda_sks,
            &d_accumulator,
            dp_scalar,
            &cuda_packing_key,
            storage_modulus_log,
            &mut cuda_side_resources,
        );

        (
            after_ms.glwe_dimension().to_glwe_size(),
            after_ms.polynomial_size(),
            after_ms.ciphertext_modulus().raw_modulus_float(),
        )
    };

    assert_eq!(after_ms_sim.glwe_size(), expected_glwe_size_out);
    assert_eq!(after_ms_sim.polynomial_size(), expected_polynomial_size_out);
    assert_eq!(after_ms_sim.modulus().as_f64(), expected_modulus_f64_out);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_before_ms = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1; //00usize;

    for _ in 0..cleartext_modulus {
        let (current_noise_samples_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) =
            (0..sample_count_per_msg)
                .into_par_iter()
                .map(|_| {
                    let (_before_packing, after_packing, after_ms) =
                        encrypt_br_dp_packing_ks_ms_noise_helper_gpu(
                            params,
                            comp_params,
                            &cks,
                            &sks,
                            &cuda_sks,
                            &private_compression_key,
                            &cuda_compression_key,
                            0,
                            br_input_modulus_log,
                            &streams,
                        );
                    (after_packing, after_ms)
                })
                .flatten()
                .unzip();

        noise_samples_before_ms
            .extend(current_noise_samples_before_ms.into_iter().map(|x| x.value));
        noise_samples_after_ms.extend(current_noise_samples_after_ms.into_iter().map(|x| x.value));
    }

    let before_ms_normality = normality_check(&noise_samples_before_ms, "before ms", 0.01);

    let after_ms_is_ok = mean_and_variance_check(
        &noise_samples_after_ms,
        "after_ms",
        0.0,
        after_ms_sim.variance_per_occupied_slot(),
        comp_params.packing_ks_key_noise_distribution(),
        after_ms_sim
            .glwe_dimension()
            .to_equivalent_lwe_dimension(after_ms_sim.polynomial_size()),
        after_ms_sim.modulus().as_f64(),
    );

    assert!(before_ms_normality.null_hypothesis_is_valid && after_ms_is_ok);
}
create_parameterized_test!(noise_check_encrypt_br_dp_packing_ks_ms_noise_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    //    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_br_dp_packing_ks_ms_pfail_gpu(meta_params: MetaParameters) {
    let (pfail_test_meta, params, comp_params) = {
        let (mut params, comp_params) = (
            meta_params.compute_parameters,
            meta_params.compression_parameters.unwrap(),
        );

        let original_message_modulus = params.message_modulus();
        let original_carry_modulus = params.carry_modulus();

        // For now only allow 2_2 parameters, and see later for heuristics to use
        assert_eq!(original_message_modulus.0, 4);
        assert_eq!(original_carry_modulus.0, 4);

        let noise_simulation_bsk =
            NoiseSimulationLweFourierBsk::new_from_atomic_pattern_parameters(params);
        let noise_simulation_packing_key =
            NoiseSimulationLwePackingKeyswitchKey::new_from_comp_parameters(params, comp_params);

        // The multiplication done in the compression is made to move the message up at the top of
        // the carry space, multiplying by the carry modulus achieves that
        let dp_scalar = params.carry_modulus().0;

        let noise_simulation_accumulator = NoiseSimulationGlwe::new(
            noise_simulation_bsk.output_glwe_size().to_glwe_dimension(),
            noise_simulation_bsk.output_polynomial_size(),
            Variance(0.0),
            noise_simulation_bsk.modulus(),
        );

        let lwe_per_glwe = comp_params.lwe_per_glwe();
        let storage_modulus_log = comp_params.storage_log_modulus();

        let (_before_packing_sim, _after_packing_sim, after_ms_sim) = {
            let noise_simulation = NoiseSimulationLwe::new(
                params.lwe_dimension(),
                Variance(0.0),
                NoiseSimulationModulus::from_ciphertext_modulus(params.ciphertext_modulus()),
            );
            br_dp_packing_ks_ms(
                vec![noise_simulation; lwe_per_glwe.0],
                &noise_simulation_bsk,
                &noise_simulation_accumulator,
                dp_scalar,
                &noise_simulation_packing_key,
                storage_modulus_log,
                &mut vec![(); lwe_per_glwe.0],
            )
        };

        let expected_variance_after_storage = after_ms_sim.variance_per_occupied_slot();

        let compression_carry_mod = CarryModulus(1);
        let compression_message_mod = original_message_modulus;
        let compression_precision_with_padding =
            precision_with_padding(compression_message_mod, compression_carry_mod);
        let expected_pfail_for_storage = expected_pfail_for_precision(
            compression_precision_with_padding,
            expected_variance_after_storage,
        );

        let original_pfail_and_precision = PfailAndPrecision::new(
            expected_pfail_for_storage,
            compression_message_mod,
            compression_carry_mod,
        );

        // Here we update the message modulus only:
        // - because the message modulus matches for the compression encoding and compute encoding
        // - so that the carry modulus stays the same and we apply the same dot product as normal
        //   for 2_2
        // - so that the effective encoding after the storage is the one we used to evaluate the
        //   pfail
        let updated_message_mod = MessageModulus(1 << 6);
        let updated_carry_mod = compression_carry_mod;

        update_ap_params_msg_and_carry_moduli(&mut params, updated_message_mod, updated_carry_mod);

        assert!(
            (params.message_modulus().0 * params.carry_modulus().0).ilog2()
                <= comp_params.storage_log_modulus().0 as u32,
            "Compression storage modulus cannot store enough bits for pfail estimation"
        );

        let updated_precision_with_padding =
            precision_with_padding(updated_message_mod, updated_carry_mod);

        let new_expected_pfail_for_storage = expected_pfail_for_precision(
            updated_precision_with_padding,
            expected_variance_after_storage,
        );

        let new_expected_pfail_and_precision = PfailAndPrecision::new(
            new_expected_pfail_for_storage,
            updated_message_mod,
            updated_carry_mod,
        );

        let pfail_test_meta = if should_run_short_pfail_tests_debug() {
            // To have the same amount of keys generated as the case where a single run is a single
            // sample
            let expected_fails = 200 * lwe_per_glwe.0 as u32;
            PfailTestMeta::new_with_desired_expected_fails(
                original_pfail_and_precision,
                new_expected_pfail_and_precision,
                expected_fails,
            )
        } else {
            // To guarantee 1_000_000 keysets are generated
            let total_runs = 1_000_000 * lwe_per_glwe.0 as u32;
            PfailTestMeta::new_with_total_runs(
                original_pfail_and_precision,
                new_expected_pfail_and_precision,
                total_runs,
            )
        };

        (pfail_test_meta, params, comp_params)
    };
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let block_params: ShortintParameterSet = params.into();
    let cks = crate::integer::ClientKey::new(block_params);
    let compressed_server_key = CompressedServerKey::new_radix_compressed_server_key(&cks);
    let sks = compressed_server_key.decompress();
    let cuda_sks = CudaServerKey::decompress_from_cpu(&compressed_server_key, &streams);

    let private_compression_key = cks.new_compression_private_key(comp_params);
    let (compressed_compression_key, compressed_decompression_key) =
        cks.new_compressed_compression_decompression_keys(&private_compression_key);
    //let compression_key = compressed_compression_key.decompress();
    let cuda_compression_key = compressed_compression_key.decompress_to_cuda(&streams);
    let cuda_decompression_key = compressed_decompression_key.decompress_to_cuda(
        cks.parameters().glwe_dimension(),
        cks.parameters().polynomial_size(),
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
        cks.parameters().ciphertext_modulus(),
        &streams,
    );

    // let cks = ClientKey::new(params);
    // let sks = ServerKey::new(&cks);
    // let compression_private_key = cks.new_compression_private_key(comp_params);
    // let compression_key = cks.new_compression_key(&compression_private_key);

    let lwe_per_glwe = cuda_compression_key.lwe_per_glwe;

    let total_runs_for_expected_fails = 2; // pfail_test_meta
                                           // .total_runs_for_expected_fails()
                                           // .div_ceil(lwe_per_glwe.0.try_into().unwrap());

    println!(
        "Actual runs with {} samples per run: {total_runs_for_expected_fails}",
        lwe_per_glwe.0
    );

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|i| {
            println!("Starting run {}/{}", i + 1, total_runs_for_expected_fails);
            let after_ms_decryption_result = encrypt_br_dp_packing_ks_ms_pfail_helper_gpu(
                params,
                comp_params,
                &cks,
                &sks,
                &cuda_sks,
                &private_compression_key,
                &cuda_compression_key,
                0,
                sks.key.br_input_modulus_log(),
                &streams,
            );
            after_ms_decryption_result
                .into_iter()
                .map(|x| x.failure_as_f64())
                .sum::<f64>()
        })
        .sum();

    let test_result = PfailTestResult { measured_fails };

    pfail_check(&pfail_test_meta, test_result);
}

create_parameterized_test!(noise_check_encrypt_br_dp_packing_ks_ms_pfail_gpu {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    //TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

/// Wrapper struct for CudaCompressionKey to implement packing keyswitch traits
pub struct CudaPackingKeyswitchKey64<'a> {
    cuda_pksk: &'a CudaLwePackingKeyswitchKey<u64>,
    lwe_per_glwe: LweCiphertextCount,
}

impl<'a> CudaPackingKeyswitchKey64<'a> {
    pub fn new(
        compression_key: &'a CudaCompressionKey,
        _side_resources: &CudaSideResources,
    ) -> Self {
        let lwe_per_glwe = compression_key.lwe_per_glwe;

        Self {
            cuda_pksk: &compression_key.packing_key_switching_key,
            lwe_per_glwe,
        }
    }
}

impl<'a> AllocateLwePackingKeyswitchResult for CudaPackingKeyswitchKey64<'a> {
    type Output = CudaGlweCiphertextList<u64>;
    type SideResources = CudaSideResources;

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
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

impl<'pksk> LwePackingKeyswitch<[&CudaDynLwe], CudaGlweCiphertextList<u64>>
    for CudaPackingKeyswitchKey64<'pksk>
{
    type SideResources = CudaSideResources;

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&CudaDynLwe],
        output: &mut CudaGlweCiphertextList<u64>,
        side_resources: &mut CudaSideResources,
    ) {
        use crate::core_crypto::gpu::algorithms::lwe_packing_keyswitch::cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64;
        let input_lwe_ciphertext_list = CudaLweCiphertextList::from_vec_cuda_lwe_ciphertexts_list(
            input.iter().map(|ciphertext| ciphertext.as_lwe_64()),
            &side_resources.streams,
        );

        cuda_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_64(
            self.cuda_pksk,
            &input_lwe_ciphertext_list,
            output,
            &side_resources.streams,
        );
    }
}

// Implement StandardModSwitch traits for CudaGlweCiphertextList<u64>
impl AllocateStandardModSwitchResult for CudaGlweCiphertextList<u64> {
    type Output = CudaGlweCiphertextList<u64>;
    type SideResources = CudaSideResources;

    fn allocate_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        CudaGlweCiphertextList::new(
            self.glwe_dimension(),
            self.polynomial_size(),
            self.glwe_ciphertext_count(),
            self.ciphertext_modulus(),
            &side_resources.streams,
        )
    }
}

impl StandardModSwitch<Self> for CudaGlweCiphertextList<u64> {
    type SideResources = CudaSideResources;

    fn standard_mod_switch(
        &self,
        storage_log_modulus: CiphertextModulusLog,
        output: &mut Self,
        side_resources: &mut CudaSideResources,
    ) {
        let mut internal_output = self.duplicate(&side_resources.streams);

        cuda_modulus_switch_ciphertext(
            &mut internal_output.0.d_vec,
            storage_log_modulus.0 as u32,
            &side_resources.streams,
        );
        side_resources.streams.synchronize();
        let mut cpu_glwe = internal_output.to_glwe_ciphertext_list(&side_resources.streams);

        let shift_to_map_to_native = u64::BITS - storage_log_modulus.0 as u32;
        for val in cpu_glwe.as_mut_view().into_container().iter_mut() {
            *val <<= shift_to_map_to_native;
        }
        let d_after_ms =
            CudaGlweCiphertextList::from_glwe_ciphertext_list(&cpu_glwe, &side_resources.streams);

        *output = d_after_ms;
    }
}
