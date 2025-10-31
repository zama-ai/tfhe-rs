use super::utils::noise_simulation::*;
use super::utils::traits::*;
use super::utils::{
    expected_pfail_for_precision, mean_and_variance_check, normality_check, pfail_check,
    precision_with_padding, DecryptionAndNoiseResult, NoiseSample, PfailAndPrecision,
    PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::{Ciphertext, Degree, NoiseLevel};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{CompressionKey, CompressionPrivateKeys};
use crate::shortint::parameters::test_params::{
    TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CiphertextModulusLog, CompressionParameters,
    MessageModulus, PBSParameters, Variance,
};
use crate::shortint::server_key::ServerKey;
use crate::shortint::{PaddingBit, ShortintEncoding};
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn br_dp_packing_ks_ms<
    InputCt,
    PBSResult,
    PBSKey,
    Accumulator,
    DPScalar,
    DPResult,
    PackingKsk,
    PackingKsResult,
    MsResult,
    Resources,
>(
    input: Vec<InputCt>,
    bsk: &PBSKey,
    accumulator: &Accumulator,
    scalar: DPScalar,
    packing_ksk: &PackingKsk,
    storage_modulus_log: CiphertextModulusLog,
    side_resources: &mut [Resources],
) -> (
    Vec<(InputCt, PBSResult, DPResult)>,
    PackingKsResult,
    MsResult,
)
where
    Accumulator: AllocateLweBootstrapResult<Output = PBSResult, SideResources = Resources> + Sync,
    PBSKey:
        LweClassicFftBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources> + Sync,
    PBSResult: ScalarMul<DPScalar, Output = DPResult, SideResources = Resources> + Send,
    PackingKsk: AllocateLwePackingKeyswitchResult<Output = PackingKsResult, SideResources = Resources>
        + for<'a> LwePackingKeyswitch<[&'a DPResult], PackingKsResult, SideResources = Resources>,
    PackingKsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>,
    InputCt: Send,
    DPResult: Send,
    DPScalar: Copy + Send + Sync,
    Resources: Send,
{
    let res: Vec<_> = input
        .into_par_iter()
        .zip(side_resources.par_iter_mut())
        .map(|(input, side_resources)| {
            let mut pbs_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
            bsk.lwe_classic_fft_pbs(&input, &mut pbs_result, accumulator, side_resources);
            let after_dp = pbs_result.scalar_mul(scalar, side_resources);

            (input, pbs_result, after_dp)
        })
        .collect();

    let after_dp: Vec<_> = res
        .iter()
        .map(|(_input, _pbs_result, after_dp)| after_dp)
        .collect();

    let mut packing_result =
        packing_ksk.allocate_lwe_packing_keyswitch_result(&mut side_resources[0]);
    packing_ksk.keyswitch_lwes_and_pack_in_glwe(
        after_dp.as_slice(),
        &mut packing_result,
        &mut side_resources[0],
    );

    let mut ms_result = packing_result.allocate_standard_mod_switch_result(&mut side_resources[0]);
    packing_result.standard_mod_switch(storage_modulus_log, &mut ms_result, &mut side_resources[0]);

    (res, packing_result, ms_result)
}

fn sanity_check_encrypt_br_dp_packing_ks_ms<P>(params: P, comp_params: CompressionParameters)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let compression_private_key = cks.new_compression_private_key(comp_params);
    let compression_key = cks.new_compression_key(&compression_private_key);

    let lwe_per_glwe = compression_key.lwe_per_glwe;
    // The multiplication done in the compression is made to move the message up at the top of the
    // carry space, multiplying by the carry modulus achieves that
    let dp_scalar = params.carry_modulus().0;
    let br_input_modulus_log = sks.br_input_modulus_log();
    let storage_modulus_log = compression_key.storage_log_modulus;

    let id_lut = sks.generate_lookup_table(|x| x);

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0)
        .map(|_| cks.encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0))
        .collect();
    let mut side_resources = vec![(); input_zeros.len()];

    let (before_packing, _after_packing, mut after_ms) = br_dp_packing_ks_ms(
        input_zeros,
        &sks,
        &id_lut,
        dp_scalar,
        &compression_key,
        storage_modulus_log,
        &mut side_resources,
    );

    let compression_inputs: Vec<_> = before_packing
        .into_iter()
        .map(|(_input, pbs_result, _dp_result)| {
            Ciphertext::new(
                pbs_result.into_lwe_64(),
                Degree::new(sks.message_modulus.0 - 1),
                NoiseLevel::NOMINAL,
                sks.message_modulus,
                sks.carry_modulus,
                sks.atomic_pattern.kind(),
            )
        })
        .collect();

    let compressed = compression_key.compress_ciphertexts_into_list(&compression_inputs);

    let underlying_glwes = compressed.modulus_switched_glwe_ciphertext_list;

    assert_eq!(underlying_glwes.len(), 1);

    let extracted = underlying_glwes[0].extract();

    // Bodies that were not filled are discarded
    after_ms.get_mut_body().as_mut()[lwe_per_glwe.0..].fill(0);

    assert_eq!(after_ms.as_view(), extracted.as_view());
}

#[test]
fn test_sanity_check_encrypt_br_dp_packing_ks_ms_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_br_dp_packing_ks_ms(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_sanity_check_encrypt_br_dp_packing_ks_ms_test_param_message_2_carry_2_ks32_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_br_dp_packing_ks_ms(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[allow(clippy::type_complexity)]
fn encrypt_br_dp_packing_ks_ms_inner_helper(
    params: AtomicPatternParameters,
    comp_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CompressionKey,
    msg: u64,
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
    let thread_cks;
    let thread_sks;
    let thread_compression_private_key;
    let thread_compression_key;
    let (cks, sks, compression_private_key, compression_key) = if should_use_single_key_debug() {
        (
            single_cks,
            single_sks,
            single_compression_private_key,
            single_compression_key,
        )
    } else {
        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);

        thread_compression_private_key =
            thread_cks.new_compression_private_key_with_engine(comp_params, &mut engine);
        thread_compression_key = thread_cks.new_compression_key(&thread_compression_private_key);

        (
            &thread_cks,
            &thread_sks,
            &thread_compression_private_key,
            &thread_compression_key,
        )
    };

    let br_input_modulus_log = sks.br_input_modulus_log();
    let lwe_per_glwe = compression_key.lwe_per_glwe;

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0)
        .map(|_| {
            cks.encrypt_noiseless_pbs_input_dyn_lwe_with_engine(
                br_input_modulus_log,
                msg,
                &mut engine,
            )
        })
        .collect();

    let id_lut = sks.generate_lookup_table(|x| x);
    let mut side_resources = vec![(); input_zeros.len()];
    let dp_scalar = params.carry_modulus().0;
    let storage_modulus_log = compression_key.storage_log_modulus;

    let (before_packing, after_packing, after_ms) = br_dp_packing_ks_ms(
        input_zeros,
        sks,
        &id_lut,
        dp_scalar,
        compression_key,
        storage_modulus_log,
        &mut side_resources,
    );

    let compute_large_lwe_secret_key = cks.encryption_key();
    let compression_glwe_secret_key = &compression_private_key.post_packing_ks_key;

    let compute_encoding = sks.encoding(PaddingBit::Yes);
    let compression_encoding = ShortintEncoding {
        carry_modulus: CarryModulus(1),
        ..compute_encoding
    };

    (
        before_packing
            .into_iter()
            .map(|(input, pbs_result, dp_result)| {
                (
                    match &cks.atomic_pattern {
                        AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
                            DecryptionAndNoiseResult::new_from_lwe(
                                input.as_ref_64(),
                                &standard_atomic_pattern_client_key.lwe_secret_key,
                                msg,
                                &compute_encoding,
                            )
                        }
                        AtomicPatternClientKey::KeySwitch32(ks32_atomic_pattern_client_key) => {
                            let ks32_params = ks32_atomic_pattern_client_key.parameters;
                            let compute_encoding_32 = ShortintEncoding {
                                ciphertext_modulus: ks32_params.post_keyswitch_ciphertext_modulus,
                                message_modulus: ks32_params.message_modulus,
                                carry_modulus: ks32_params.carry_modulus,
                                padding_bit: PaddingBit::Yes,
                            };

                            DecryptionAndNoiseResult::new_from_lwe(
                                input.as_ref_32(),
                                &ks32_atomic_pattern_client_key.lwe_secret_key,
                                msg.try_into().unwrap(),
                                &compute_encoding_32,
                            )
                        }
                    },
                    DecryptionAndNoiseResult::new_from_lwe(
                        pbs_result.as_ref_64(),
                        &compute_large_lwe_secret_key,
                        msg,
                        &compute_encoding,
                    ),
                    DecryptionAndNoiseResult::new_from_lwe(
                        dp_result.as_ref_64(),
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
            compression_private_key.params.lwe_per_glwe(),
            msg,
            &compression_encoding,
        ),
        DecryptionAndNoiseResult::new_from_glwe(
            &after_ms,
            compression_glwe_secret_key,
            compression_private_key.params.lwe_per_glwe(),
            msg,
            &compression_encoding,
        ),
    )
}

#[allow(clippy::type_complexity)]
fn encrypt_br_dp_packing_ks_ms_noise_helper(
    params: AtomicPatternParameters,
    comp_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CompressionKey,
    msg: u64,
) -> (
    Vec<(NoiseSample, NoiseSample, NoiseSample)>,
    Vec<NoiseSample>,
    Vec<NoiseSample>,
) {
    let (before_packing, after_packing, after_ms) = encrypt_br_dp_packing_ks_ms_inner_helper(
        params,
        comp_params,
        single_cks,
        single_sks,
        single_compression_private_key,
        single_compression_key,
        msg,
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
fn encrypt_br_dp_packing_ks_ms_pfail_helper(
    params: AtomicPatternParameters,
    comp_params: CompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_compression_private_key: &CompressionPrivateKeys,
    single_compression_key: &CompressionKey,
    msg: u64,
) -> Vec<DecryptionAndNoiseResult> {
    let (_before_packing, _after_packing, after_ms) = encrypt_br_dp_packing_ks_ms_inner_helper(
        params,
        comp_params,
        single_cks,
        single_sks,
        single_compression_private_key,
        single_compression_key,
        msg,
    );

    after_ms
}

fn noise_check_encrypt_br_dp_packing_ks_ms_noise<P>(params: P, comp_params: CompressionParameters)
where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let compression_private_key = cks.new_compression_private_key(comp_params);
    let compression_key = cks.new_compression_key(&compression_private_key);

    let noise_simulation_bsk =
        NoiseSimulationLweFourierBsk::new_from_atomic_pattern_parameters(params);
    let noise_simulation_packing_key =
        NoiseSimulationLwePackingKeyswitchKey::new_from_comp_parameters(params, comp_params);

    assert!(noise_simulation_bsk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_packing_key.matches_actual_shortint_comp_key(&compression_key));

    // The multiplication done in the compression is made to move the message up at the top of the
    // carry space, multiplying by the carry modulus achieves that
    let dp_scalar = params.carry_modulus().0;

    let noise_simulation_accumulator = NoiseSimulationGlwe::new(
        noise_simulation_bsk.output_glwe_size().to_glwe_dimension(),
        noise_simulation_bsk.output_polynomial_size(),
        Variance(0.0),
        noise_simulation_bsk.modulus(),
    );

    let lwe_per_glwe = compression_key.lwe_per_glwe;
    let storage_modulus_log = compression_key.storage_log_modulus;
    let br_input_modulus_log = sks.br_input_modulus_log();

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
        .map(|_| cks.encrypt_noiseless_pbs_input_dyn_lwe(br_input_modulus_log, 0))
        .collect();
    let id_lut = sks.generate_lookup_table(|x| x);
    let mut side_resources = vec![(); input_zeros.len()];

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_glwe_size_out, expected_polynomial_size_out, expected_modulus_f64_out) = {
        let (_before_packing_sim, _after_packing, after_ms) = br_dp_packing_ks_ms(
            input_zeros,
            &sks,
            &id_lut,
            dp_scalar,
            &compression_key,
            storage_modulus_log,
            &mut side_resources,
        );

        (
            after_ms.glwe_size(),
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

    let sample_count_per_msg = 1000usize.div_ceil(compression_key.lwe_per_glwe.0);

    for _ in 0..cleartext_modulus {
        let (current_noise_samples_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) =
            (0..sample_count_per_msg)
                .into_par_iter()
                .map(|_| {
                    let (_before_packing, after_packing, after_ms) =
                        encrypt_br_dp_packing_ks_ms_noise_helper(
                            params,
                            comp_params,
                            &cks,
                            &sks,
                            &compression_private_key,
                            &compression_key,
                            0,
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

#[test]
fn test_noise_check_encrypt_br_dp_packing_ks_ms_noise_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    noise_check_encrypt_br_dp_packing_ks_ms_noise(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_encrypt_br_dp_packing_ks_ms_noise_test_param_message_2_carry_2_ks32_pbs_tuniform_2m128(
) {
    noise_check_encrypt_br_dp_packing_ks_ms_noise(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

fn noise_check_encrypt_br_dp_packing_ks_ms_pfail<P>(params: P, comp_params: CompressionParameters)
where
    P: Into<AtomicPatternParameters>,
{
    let (pfail_test_meta, params) = {
        let mut params: AtomicPatternParameters = params.into();

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

        let updated_message_mod = MessageModulus(1 << 6);
        let updated_carry_mod = compression_carry_mod;

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

        // Here we update the message modulus only:
        // - because the message modulus matches for the compression encoding and compute encoding
        // - so that the carry modulus stays the same and we apply the same dot product as normal
        //   for 2_2
        // - so that the effective encoding after the storage is the one we used to evaluate the
        //   pfail
        // TODO: do something about this
        match &mut params {
            AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
                PBSParameters::PBS(classic_pbsparameters) => {
                    classic_pbsparameters.message_modulus = updated_message_mod
                }
                PBSParameters::MultiBitPBS(multi_bit_pbsparameters) => {
                    multi_bit_pbsparameters.message_modulus = updated_message_mod
                }
            },
            AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                key_switch32_pbsparameters.message_modulus = updated_message_mod
            }
        }

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

        (pfail_test_meta, params)
    };

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let compression_private_key = cks.new_compression_private_key(comp_params);
    let compression_key = cks.new_compression_key(&compression_private_key);

    let lwe_per_glwe = compression_key.lwe_per_glwe;

    let total_runs_for_expected_fails = pfail_test_meta
        .total_runs_for_expected_fails()
        .div_ceil(lwe_per_glwe.0.try_into().unwrap());

    println!(
        "Actual runs with {} samples per run: {total_runs_for_expected_fails}",
        lwe_per_glwe.0
    );

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let after_ms_decryption_result = encrypt_br_dp_packing_ks_ms_pfail_helper(
                params,
                comp_params,
                &cks,
                &sks,
                &compression_private_key,
                &compression_key,
                0,
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

#[test]
fn test_noise_check_encrypt_br_dp_packing_ks_ms_pfail_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    noise_check_encrypt_br_dp_packing_ks_ms_pfail(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

#[test]
fn test_noise_check_encrypt_br_dp_packing_ks_ms_pfail_test_param_message_2_carry_2_ks32_pbs_tuniform_2m128(
) {
    noise_check_encrypt_br_dp_packing_ks_ms_pfail(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
        TEST_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
