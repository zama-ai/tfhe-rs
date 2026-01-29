use super::dp_ks_ms::any_ms;
use super::utils::noise_simulation::{
    DynLwe, DynLweSecretKeyView, NoiseSimulationGenericBootstrapKey, NoiseSimulationGlwe,
    NoiseSimulationLwe, NoiseSimulationLweKeyswitchKey, NoiseSimulationModulusSwitchConfig,
};
use super::utils::to_json::{write_to_json_file, TestResult};
use super::utils::traits::*;
use super::utils::{
    mean_and_variance_check, normality_check, pfail_check, update_ap_params_for_pfail,
    DecryptionAndNoiseResult, NoiseSample, PfailTestMeta, PfailTestResult,
};
use super::{should_run_short_pfail_tests_debug, should_use_single_key_debug};
use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::math::random::XofSeed;
use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, LweCiphertextCount, MonomialDegree,
};
use crate::core_crypto::commons::traits::contiguous_entity_container::ContiguousEntityContainer;
use crate::core_crypto::entities::compressed_modulus_switched_glwe_ciphertext::CompressedModulusSwitchedGlweCiphertext;
use crate::core_crypto::entities::LweCiphertextOwned;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::{
    CompressedCiphertextList, CompressedCiphertextListMeta, ReRandomizationSeed,
};
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::ShortintEncoding;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::{KeySwitchingKeyBuildHelper, KeySwitchingKeyView};
use crate::shortint::list_compression::{CompressionPrivateKeys, DecompressionKey};
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactCiphertextListExpansionKind,
    CompactPublicKeyEncryptionParameters, CompressionParameters, MetaParameters,
    ShortintCompactCiphertextListCastingMode, ShortintKeySwitchingParameters,
};
use crate::shortint::public_key::compact::{CompactPrivateKey, CompactPublicKey};
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulus;
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::write_empty_json_file;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;
use crate::shortint::server_key::ServerKey;
use crate::shortint::{Ciphertext, PaddingBit};
use crate::this_function_name;
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn br_rerand_dp_ks_any_ms<
    InputCt,
    InputZeroRerand,
    KsKeyRerand,
    KsedZeroReRand,
    PBSResult,
    ReRandCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    DecompPBSKey,
    DPScalar,
    KsKey,
    DriftKey,
    Accumulator,
    Resources,
>(
    input: InputCt,
    decomp_bsk: &DecompPBSKey,
    input_zero_rerand: InputZeroRerand,
    ksk_rerand: &KsKeyRerand,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    decomp_accumulator: &Accumulator,
    br_input_modulus_log: CiphertextModulusLog,
    side_resources: &mut Resources,
) -> (
    (InputCt, PBSResult),
    (InputZeroRerand, KsedZeroReRand),
    ReRandCt,
    ScalarMulResult,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
)
where
    Accumulator: AllocateLweBootstrapResult<Output = PBSResult, SideResources = Resources>,
    DecompPBSKey: LweGenericBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources>,
    KsKeyRerand: AllocateLweKeyswitchResult<Output = KsedZeroReRand, SideResources = Resources>
        + LweKeyswitch<InputZeroRerand, KsedZeroReRand, SideResources = Resources>,
    PBSResult: for<'a> LweUncorrelatedAdd<
        &'a KsedZeroReRand,
        Output = ReRandCt,
        SideResources = Resources,
    >,
    ReRandCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    KsKey: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
    KsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>
        + AllocateCenteredBinaryShiftedStandardModSwitchResult<
            Output = MsResult,
            SideResources = Resources,
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>
        + AllocateMultiBitModSwitchResult<Output = MsResult, SideResources = Resources>
        + MultiBitModSwitch<MsResult, SideResources = Resources>,
    DriftKey: AllocateDriftTechniqueStandardModSwitchResult<
            AfterDriftOutput = DriftTechniqueResult,
            AfterMsOutput = MsResult,
            SideResources = Resources,
        > + DriftTechniqueStandardModSwitch<
            KsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        >,
{
    // BR to decomp
    let mut br_result = decomp_accumulator.allocate_lwe_bootstrap_result(side_resources);
    decomp_bsk.lwe_generic_bootstrap(&input, &mut br_result, decomp_accumulator, side_resources);

    // Ks the CPK encryption of 0 to be added to BR result
    let mut ksed_zero_rerand = ksk_rerand.allocate_lwe_keyswitch_result(side_resources);
    ksk_rerand.lwe_keyswitch(&input_zero_rerand, &mut ksed_zero_rerand, side_resources);

    // ReRand is done here
    let rerand_ct = br_result.lwe_uncorrelated_add(&ksed_zero_rerand, side_resources);

    // DP
    let dp_result = rerand_ct.scalar_mul(scalar, side_resources);

    let mut ks_result = ksk.allocate_lwe_keyswitch_result(side_resources);
    ksk.lwe_keyswitch(&dp_result, &mut ks_result, side_resources);

    // MS
    let (drift_technique_result, ms_result) = any_ms(
        &ks_result,
        modulus_switch_configuration,
        br_input_modulus_log,
        side_resources,
    );

    (
        (input, br_result),
        (input_zero_rerand, ksed_zero_rerand),
        rerand_ct,
        dp_result,
        ks_result,
        drift_technique_result,
        ms_result,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_decomp_br_rerand_dp_ks_any_ms_inner_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    compression_params: CompressionParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: &KeySwitchingKeyView<'_>,
    single_comp_private_key: &CompressionPrivateKeys,
    single_decomp_key: &DecompressionKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
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
    let thread_cpk_private_key;
    let thread_cpk;
    let thread_ksk_rerand_builder;
    let thread_ksk_rerand;
    let thread_comp_private_key;
    let thread_decomp_key;
    let thread_cks;
    let thread_sks;
    let (cpk_private_key, cpk, ksk_rerand, comp_private_key, decomp_key, cks, sks) =
        if should_use_single_key_debug() {
            (
                single_cpk_private_key,
                single_cpk,
                single_ksk_rerand,
                single_comp_private_key,
                single_decomp_key,
                single_cks,
                single_sks,
            )
        } else {
            thread_cpk_private_key = CompactPrivateKey::new_with_engine(cpk_params, &mut engine);
            thread_cpk = CompactPublicKey::new_with_engine(&thread_cpk_private_key, &mut engine);
            thread_cks = engine.new_client_key(params);
            thread_sks = engine.new_server_key(&thread_cks);

            thread_ksk_rerand_builder = KeySwitchingKeyBuildHelper::new_with_engine(
                (&thread_cpk_private_key, None),
                (&thread_cks, &thread_sks),
                rerand_ksk_params,
                &mut engine,
            );
            thread_ksk_rerand = thread_ksk_rerand_builder.as_key_switching_key_view();

            thread_comp_private_key =
                thread_cks.new_compression_private_key_with_engine(compression_params, &mut engine);
            thread_decomp_key = thread_cks.new_decompression_key_with_params_and_engine(
                &thread_comp_private_key,
                compression_params,
                &mut engine,
            );

            (
                &thread_cpk_private_key,
                &thread_cpk,
                &thread_ksk_rerand,
                &thread_comp_private_key,
                &thread_decomp_key,
                &thread_cks,
                &thread_sks,
            )
        };

    let br_input_modulus_log = sks.br_input_modulus_log();
    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();

    let ct = comp_private_key.encrypt_noiseless_decompression_input_dyn_lwe(cks, msg, &mut engine);

    let cpk_ct_zero_rerand = {
        let compact_list = cpk.encrypt_iter_with_modulus_with_engine(
            core::iter::once(0),
            cpk.parameters.message_modulus.0,
            &mut engine,
        );
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

    let decomp_rescale_lut = decomp_key.rescaling_lut(
        sks.ciphertext_modulus,
        sks.message_modulus,
        CarryModulus(1),
        sks.message_modulus,
        sks.carry_modulus,
    );

    let (
        (input, after_br),
        (input_zero_rerand, after_ksed_zero_rerand),
        after_rerand,
        after_dp,
        after_ks,
        after_drift,
        after_ms,
    ) = br_rerand_dp_ks_any_ms(
        ct,
        decomp_key,
        cpk_ct_zero_rerand,
        ksk_rerand,
        scalar_for_multiplication,
        sks,
        modulus_switch_config,
        &decomp_rescale_lut,
        br_input_modulus_log,
        &mut (),
    );

    let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

    let params = cks.parameters();
    let compute_encoding = ShortintEncoding {
        ciphertext_modulus: params.ciphertext_modulus(),
        message_modulus: params.message_modulus(),
        carry_modulus: params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };
    let comp_encoding = ShortintEncoding {
        // Adapt to the compression which has no carry bits
        carry_modulus: CarryModulus(1),
        ..compute_encoding
    };

    let cpk_lwe_secret_key_dyn = cpk_private_key.lwe_secret_key_as_dyn();
    let comp_lwe_secret_key = comp_private_key.post_packing_ks_key.as_lwe_secret_key();
    let comp_lwe_secret_key_dyn = DynLweSecretKeyView::U64 {
        key: comp_lwe_secret_key,
        encoding: comp_encoding,
    };

    let large_compute_lwe_secret_key_dyn = cks.large_lwe_secret_key_as_dyn();
    let small_compute_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

    (
        (
            DecryptionAndNoiseResult::new_from_dyn_lwe(&input, &comp_lwe_secret_key_dyn, msg),
            DecryptionAndNoiseResult::new_from_dyn_lwe(
                &after_br,
                &large_compute_lwe_secret_key_dyn,
                msg,
            ),
        ),
        (
            DecryptionAndNoiseResult::new_from_dyn_lwe(
                &input_zero_rerand,
                &cpk_lwe_secret_key_dyn,
                msg,
            ),
            DecryptionAndNoiseResult::new_from_dyn_lwe(
                &after_ksed_zero_rerand,
                &large_compute_lwe_secret_key_dyn,
                msg,
            ),
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &after_rerand,
            &large_compute_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &after_dp,
            &large_compute_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            &after_ks,
            &small_compute_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_lwe(
            before_ms,
            &small_compute_lwe_secret_key_dyn,
            msg,
        ),
        DecryptionAndNoiseResult::new_from_dyn_modswitched_lwe(
            &after_ms,
            &small_compute_lwe_secret_key_dyn,
            msg,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_br_rerand_dp_ks_any_ms_noise_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    compression_params: CompressionParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: &KeySwitchingKeyView<'_>,
    single_comp_private_key: &CompressionPrivateKeys,
    single_decomp_key: &DecompressionKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
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
    ) = encrypt_decomp_br_rerand_dp_ks_any_ms_inner_helper(
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
        single_sks,
        msg,
        scalar_for_multiplication,
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
fn encrypt_br_rerand_dp_ks_any_ms_pfail_helper(
    params: AtomicPatternParameters,
    cpk_params: CompactPublicKeyEncryptionParameters,
    rerand_ksk_params: ShortintKeySwitchingParameters,
    compression_params: CompressionParameters,
    single_cpk_private_key: &CompactPrivateKey<Vec<u64>>,
    single_cpk: &CompactPublicKey,
    single_ksk_rerand: &KeySwitchingKeyView<'_>,
    single_comp_private_key: &CompressionPrivateKeys,
    single_decomp_key: &DecompressionKey,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> DecryptionAndNoiseResult {
    let (
        (_input, _after_br),
        (_input_zero_rerand, _after_ksed_zero_rerand),
        _after_rerand,
        _after_dp,
        _after_ks,
        _before_ms,
        after_ms,
    ) = encrypt_decomp_br_rerand_dp_ks_any_ms_inner_helper(
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
        single_sks,
        msg,
        scalar_for_multiplication,
    );

    after_ms
}

fn noise_check_encrypt_br_rerand_dp_ks_ms_noise(
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
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();
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

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let comp_private_key = cks.new_compression_private_key(compression_params);
    let decomp_key = cks.new_decompression_key_with_params(&comp_private_key, compression_params);

    let ksk_rerand_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params);
    let ksk_rerand: KeySwitchingKeyView<'_> = ksk_rerand_builder.as_key_switching_key_view();

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_ksk_rerand =
        NoiseSimulationLweKeyswitchKey::new_from_cpk_params(cpk_params, rerand_ksk_params, params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);
    let noise_simulation_decomp_bsk =
        NoiseSimulationGenericBootstrapKey::new_from_comp_parameters(params, compression_params);

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();
    let expected_average_after_ms =
        modulus_switch_config.expected_average_after_ms(params.polynomial_size());

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_ksk_rerand.matches_actual_shortint_keyswitching_key(&ksk_rerand));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_server_key_modulus_switch_config(modulus_switch_config));
    assert!(noise_simulation_decomp_bsk.matches_actual_shortint_decomp_key(&decomp_key));

    let max_scalar_mul = sks.max_noise_level.get();

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
        let noise_simulation_input_zero_rerand = NoiseSimulationLwe::encrypt_with_cpk(&cpk);
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

    let decomp_rescale_lut = decomp_key.rescaling_lut(
        sks.ciphertext_modulus,
        sks.message_modulus,
        CarryModulus(1),
        sks.message_modulus,
        sks.carry_modulus,
    );

    let sample_input = ShortintEngine::with_thread_local_mut(|engine| {
        comp_private_key.encrypt_noiseless_decompression_input_dyn_lwe(&cks, 0, engine)
    });
    let cpk_zero_sample_input = {
        let compact_list = cpk.encrypt_slice(&[0]);
        let mut expanded = compact_list
            .expand(ShortintCompactCiphertextListCastingMode::NoCasting)
            .unwrap();
        assert_eq!(expanded.len(), 1);

        DynLwe::U64(expanded.pop().unwrap().ct)
    };

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
            after_ms,
        ) = br_rerand_dp_ks_any_ms(
            sample_input,
            &decomp_key,
            cpk_zero_sample_input,
            &ksk_rerand,
            max_scalar_mul,
            &sks,
            modulus_switch_config,
            &decomp_rescale_lut,
            compute_br_input_modulus_log,
            &mut (),
        );

        (after_ms.lwe_dimension(), after_ms.raw_modulus_float())
    };

    assert_eq!(after_ms_sim.lwe_dimension(), expected_lwe_dimension_out);
    assert_eq!(after_ms_sim.modulus().as_f64(), expected_modulus_f64_out);

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_before_ms = vec![];
    let mut noise_samples_after_ms = vec![];

    let sample_count_per_msg = 1000;

    for _ in 0..cleartext_modulus {
        let (current_noise_sample_before_ms, current_noise_samples_after_ms): (Vec<_>, Vec<_>) = (0
            ..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let (
                    (_input, _after_br),
                    (_input_zero_rerand, _after_ksed_zero_rerand),
                    _after_rerand,
                    _after_dp,
                    _after_ks,
                    before_ms,
                    after_ms,
                ) = encrypt_br_rerand_dp_ks_any_ms_noise_helper(
                    params,
                    cpk_params,
                    rerand_ksk_params,
                    compression_params,
                    &cpk_private_key,
                    &cpk,
                    &ksk_rerand,
                    &comp_private_key,
                    &decomp_key,
                    &cks,
                    &sks,
                    0,
                    max_scalar_mul,
                );
                (before_ms.value, after_ms.value)
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

    let noise_check = TestResult::NoiseCheckWithNormalityCheck(Box::new(
        super::utils::to_json::NoiseCheckWithNormalityCheck::new(
            bounded_variance_measurement,
            bounded_mean_measurement,
            before_ms_normality_valid,
        ),
    ));

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

create_parameterized_stringified_test!(noise_check_encrypt_br_rerand_dp_ks_ms_noise {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn noise_check_encrypt_br_rerand_dp_ks_ms_pfail(
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
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();
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

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let comp_private_key = cks.new_compression_private_key(compression_params);
    let decomp_key = cks.new_decompression_key_with_params(&comp_private_key, compression_params);

    let ksk_rerand_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params);
    let ksk_rerand: KeySwitchingKeyView<'_> = ksk_rerand_builder.as_key_switching_key_view();

    let max_scalar_mul = sks.max_noise_level.get();

    let total_runs_for_expected_fails = pfail_test_meta.total_runs_for_expected_fails();

    let measured_fails: f64 = (0..total_runs_for_expected_fails)
        .into_par_iter()
        .map(|_| {
            let after_ms_decryption_result = encrypt_br_rerand_dp_ks_any_ms_pfail_helper(
                params,
                cpk_params,
                rerand_ksk_params,
                compression_params,
                &cpk_private_key,
                &cpk,
                &ksk_rerand,
                &comp_private_key,
                &decomp_key,
                &cks,
                &sks,
                0,
                max_scalar_mul,
            );
            after_ms_decryption_result.failure_as_f64()
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

create_parameterized_stringified_test!(noise_check_encrypt_br_rerand_dp_ks_ms_pfail {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

fn sanity_check_encrypt_br_rerand_dp_ks_ms_pbs(meta_params: MetaParameters, filename_suffix: &str) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, cpk_params, rerand_ksk_params, compression_params) = {
        let compute_params = meta_params
            .compute_parameters
            .with_deterministic_execution();
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

    let cpk_private_key = CompactPrivateKey::new(cpk_params);
    let cpk = CompactPublicKey::new(&cpk_private_key);
    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let comp_private_key = cks.new_compression_private_key(compression_params);
    let decomp_key = cks.new_decompression_key_with_params(&comp_private_key, compression_params);

    let ksk_rerand_builder =
        KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (&cks, &sks), rerand_ksk_params);
    let ksk_rerand: KeySwitchingKeyView<'_> = ksk_rerand_builder.as_key_switching_key_view();

    let modulus_switch_config = sks.noise_simulation_modulus_switch_config();
    let compute_br_input_modulus_log = sks.br_input_modulus_log();

    let max_scalar_mul = sks.max_noise_level.get();

    let decomp_rescale_lut = decomp_key.rescaling_lut(
        sks.ciphertext_modulus,
        sks.message_modulus,
        CarryModulus(1),
        sks.message_modulus,
        sks.carry_modulus,
    );

    let storage_modulus = comp_private_key.params.storage_log_modulus();

    let id_lut = sks.generate_lookup_table(|x| x);

    let mut results: Vec<(DynLwe, Ciphertext)> = Vec::new();

    for idx in 0..10 {
        let seed_bytes = vec![idx as u8; 256 / 8];
        let rerand_xof_seed = XofSeed::new(seed_bytes, *b"TFHE_Enc");

        // Manually build as the seed is made non Clone to protect user normally
        let noise_simulation_rerand_seed = ReRandomizationSeed(rerand_xof_seed.clone());
        let shortint_rerand_seed = ReRandomizationSeed(rerand_xof_seed);

        // Easier to start with a GLWE and get the LWE for noise simulation + shortint
        // rather than trying to have an LWE be inserted back in a GLWE
        let sample_input_as_glwe = ShortintEngine::with_thread_local_mut(|engine| {
            comp_private_key.encrypt_noiseless_glwe(&cks, 0, engine)
        });

        let glwe_for_shortint_list = CompressedModulusSwitchedGlweCiphertext::compress(
            &sample_input_as_glwe,
            storage_modulus,
            LweCiphertextCount(1),
        );

        let sample_input = {
            let mut tmp = LweCiphertextOwned::new(
                0u64,
                sample_input_as_glwe
                    .glwe_size()
                    .to_glwe_dimension()
                    .to_equivalent_lwe_dimension(sample_input_as_glwe.polynomial_size())
                    .to_lwe_size(),
                sample_input_as_glwe.ciphertext_modulus(),
            );

            extract_lwe_sample_from_glwe_ciphertext(
                &sample_input_as_glwe,
                &mut tmp,
                MonomialDegree(0),
            );

            DynLwe::U64(tmp)
        };

        let shortint_compressed_list = CompressedCiphertextList {
            modulus_switched_glwe_ciphertext_list: vec![glwe_for_shortint_list],
            meta: Some(CompressedCiphertextListMeta {
                ciphertext_modulus: params.ciphertext_modulus(),
                message_modulus: params.message_modulus(),
                carry_modulus: params.carry_modulus(),
                atomic_pattern: sks.atomic_pattern.kind(),
                lwe_per_glwe: compression_params.lwe_per_glwe(),
            }),
        };

        let recovered = decomp_key.unpack(&shortint_compressed_list, 0).unwrap();
        let mut shortint_res = recovered.clone();

        let cpk_zero_sample_input = {
            let compact_list = cpk
                .prepare_cpk_zero_for_rerand(noise_simulation_rerand_seed, LweCiphertextCount(1));
            let zero_list = compact_list.expand_into_lwe_ciphertext_list();

            let zero = zero_list.get(0);

            DynLwe::U64(LweCiphertextOwned::from_container(
                zero.as_ref().to_vec(),
                zero.ciphertext_modulus(),
            ))
        };

        cpk.re_randomize_ciphertexts(
            core::slice::from_mut(&mut shortint_res),
            &ksk_rerand.key_switching_key_material,
            shortint_rerand_seed,
        )
        .unwrap();

        sks.unchecked_scalar_mul_assign(&mut shortint_res, max_scalar_mul.try_into().unwrap());
        sks.apply_lookup_table_assign(&mut shortint_res, &id_lut);

        let (
            (_input, _after_br),
            (_input_zero_rerand, _after_ksed_zero_rerand),
            _after_rerand,
            _after_dp,
            _after_ks,
            _before_ms,
            after_ms,
        ) = br_rerand_dp_ks_any_ms(
            sample_input,
            &decomp_key,
            cpk_zero_sample_input,
            &ksk_rerand,
            max_scalar_mul,
            &sks,
            modulus_switch_config,
            &decomp_rescale_lut,
            compute_br_input_modulus_log,
            &mut (),
        );

        // Complete the AP by computing the PBS to match shortint
        let mut pbs_result = id_lut.allocate_lwe_bootstrap_result(&mut ());
        sks.apply_generic_blind_rotation(&after_ms, &mut pbs_result, &id_lut);

        results.push((pbs_result, shortint_res));
    }

    let all_result_match = results
        .iter()
        .all(|(lhs, rhs)| lhs.as_lwe_64() == rhs.ct.as_view());

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        all_result_match,
        None,
        TestResult::Empty {},
    )
    .unwrap();

    // We check each step to preserve failure details and print the invalid case if one occurs
    for (pbs_result, shortint_res) in results.iter() {
        assert_eq!(pbs_result.as_lwe_64(), shortint_res.ct.as_view());
    }
}

create_parameterized_stringified_test!(sanity_check_encrypt_br_rerand_dp_ks_ms_pbs {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});
