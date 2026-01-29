use super::dp_ks_ms::any_ms;
use super::should_use_single_key_debug;
use super::utils::noise_simulation::*;
use super::utils::to_json::{write_to_json_file, TestResult};
use super::utils::traits::*;
use super::utils::{mean_and_variance_check, DecryptionAndNoiseResult, NoiseSample};
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{
    NoiseSquashingCompressionKey, NoiseSquashingCompressionPrivateKey,
};
use crate::shortint::noise_squashing::{NoiseSquashingKey, NoiseSquashingPrivateKey};
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::test_params::{
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, MetaParameters, NoiseSquashingCompressionParameters,
};
use crate::shortint::server_key::tests::noise_distribution::utils::to_json::write_empty_json_file;
use crate::shortint::server_key::tests::parameterized_test::create_parameterized_stringified_test;
use crate::shortint::server_key::ServerKey;
use crate::this_function_name;
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
pub fn dp_ks_any_ms_standard_pbs128<
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PbsResult,
    DPScalar,
    KsKey,
    DriftKey,
    Bsk,
    Accumulator,
    Resources,
>(
    input: InputCt,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    bsk_128: &Bsk,
    br_input_modulus_log: CiphertextModulusLog,
    accumulator: &Accumulator,
    side_resources: &mut Resources,
) -> (
    InputCt,
    ScalarMulResult,
    KsResult,
    Option<DriftTechniqueResult>,
    MsResult,
    PbsResult,
)
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
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
    // We need to be able to allocate the result and apply drift technique + mod switch it
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
    // The accumulator has the information about the output size and modulus, therefore it is the
    // one to allocate the blind rotation result
    Accumulator: AllocateLweBootstrapResult<Output = PbsResult, SideResources = Resources>,
    // We need to be able to apply the PBS
    Bsk: LweGenericBlindRotate128<MsResult, PbsResult, Accumulator, SideResources = Resources>,
{
    let after_dp = input.scalar_mul(scalar, side_resources);
    let mut ks_result = ksk.allocate_lwe_keyswitch_result(side_resources);
    ksk.lwe_keyswitch(&after_dp, &mut ks_result, side_resources);

    let (drift_technique_result, ms_result) = any_ms(
        &ks_result,
        modulus_switch_configuration,
        br_input_modulus_log,
        side_resources,
    );

    let mut pbs_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
    bsk_128.lwe_generic_blind_rotate_128(&ms_result, &mut pbs_result, accumulator, side_resources);
    (
        input,
        after_dp,
        ks_result,
        drift_technique_result,
        ms_result,
        pbs_result,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn dp_ks_any_ms_standard_pbs128_packing_ks<
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PbsResult,
    PackingResult,
    DPScalar,
    KsKey,
    DriftKey,
    Bsk,
    PackingKey,
    Accumulator,
    Resources,
>(
    input: Vec<InputCt>,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig<&DriftKey>,
    bsk_128: &Bsk,
    br_input_modulus_log: CiphertextModulusLog,
    accumulator: &Accumulator,
    packing_ksk: &PackingKey,
    side_resources: &mut [Resources],
) -> (
    Vec<(
        InputCt,
        ScalarMulResult,
        KsResult,
        Option<DriftTechniqueResult>,
        MsResult,
        PbsResult,
    )>,
    PackingResult,
)
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources> + Send,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, KsResult, SideResources = Resources>
        + Sync,
    KsResult: AllocateStandardModSwitchResult<Output = MsResult, SideResources = Resources>
        + StandardModSwitch<MsResult, SideResources = Resources>
        + AllocateCenteredBinaryShiftedStandardModSwitchResult<
            Output = MsResult,
            SideResources = Resources,
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>
        + AllocateMultiBitModSwitchResult<Output = MsResult, SideResources = Resources>
        + MultiBitModSwitch<MsResult, SideResources = Resources>,
    // We need to be able to allocate the result and apply drift technique + mod switch it
    DriftKey: AllocateDriftTechniqueStandardModSwitchResult<
            AfterDriftOutput = DriftTechniqueResult,
            AfterMsOutput = MsResult,
            SideResources = Resources,
        > + DriftTechniqueStandardModSwitch<
            KsResult,
            DriftTechniqueResult,
            MsResult,
            SideResources = Resources,
        > + Sync,
    // The accumulator has the information about the output size and modulus, therefore it is the
    // one to allocate the blind rotation result
    Accumulator: AllocateLweBootstrapResult<Output = PbsResult, SideResources = Resources> + Sync,
    // We need to be able to apply the PBS
    Bsk: LweGenericBlindRotate128<MsResult, PbsResult, Accumulator, SideResources = Resources>
        + Sync,
    PackingKey: AllocateLwePackingKeyswitchResult<Output = PackingResult, SideResources = Resources>
        + for<'a> LwePackingKeyswitch<[&'a PbsResult], PackingResult, SideResources = Resources>,
    Resources: Send,
    ScalarMulResult: Send,
    KsResult: Send,
    DriftTechniqueResult: Send,
    MsResult: Send,
    PbsResult: Send,
    DPScalar: Copy + Sync + Send,
{
    let res: Vec<_> = input
        .into_par_iter()
        .zip(side_resources.par_iter_mut())
        .map(|(input, side_resources)| {
            let (input, after_dp, ks_result, drift_technique_result, ms_result, pbs_result) =
                dp_ks_any_ms_standard_pbs128(
                    input,
                    scalar,
                    ksk,
                    modulus_switch_configuration,
                    bsk_128,
                    br_input_modulus_log,
                    accumulator,
                    side_resources,
                );

            (
                input,
                after_dp,
                ks_result,
                drift_technique_result,
                ms_result,
                pbs_result,
            )
        })
        .collect();

    let pbs_results: Vec<_> = res
        .iter()
        .map(
            |(_input, _after_dp, _ks_result, _drift_technique_result, _ms_result, pbs_result)| {
                pbs_result
            },
        )
        .collect();

    let mut packing_result =
        packing_ksk.allocate_lwe_packing_keyswitch_result(&mut side_resources[0]);
    packing_ksk.keyswitch_lwes_and_pack_in_glwe(
        pbs_results.as_slice(),
        &mut packing_result,
        &mut side_resources[0],
    );

    (res, packing_result)
}

/// Test function to verify that the noise checking tools match the actual atomic patterns
/// implemented in shortint
fn sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();

    let (params, noise_squashing_params, noise_squashing_compression_params) = {
        let meta_noise_squashing_params = meta_params.noise_squashing_parameters.unwrap();
        (
            meta_params
                .compute_parameters
                .with_deterministic_execution(),
            meta_noise_squashing_params
                .parameters
                .with_deterministic_execution(),
            meta_noise_squashing_params.compression_parameters.unwrap(),
        )
    };

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);
    let noise_squashing_compression_private_key =
        NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
    let noise_squashing_compression_key = NoiseSquashingCompressionKey::new(
        &noise_squashing_private_key,
        &noise_squashing_compression_private_key,
    );

    let lwe_per_glwe = noise_squashing_compression_key.lwe_per_glwe();

    let modulus_switch_config = noise_squashing_key.noise_simulation_modulus_switch_config();

    let br_input_modulus_log = noise_squashing_key.br_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let max_scalar_mul = sks.max_noise_level.get();

    let id_lut = generate_programmable_bootstrap_glwe_lut(
        noise_squashing_key.polynomial_size(),
        noise_squashing_key.glwe_size(),
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let input_zeros: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.encrypt(0)).collect();
    let mut side_resources = vec![(); input_zeros.len()];
    let input_zero_as_lwe: Vec<_> = input_zeros
        .iter()
        .map(|ct| DynLwe::U64(ct.ct.clone()))
        .collect();

    let (_before_packing, mut after_packing) = dp_ks_any_ms_standard_pbs128_packing_ks(
        input_zero_as_lwe,
        max_scalar_mul,
        &sks,
        modulus_switch_config,
        &noise_squashing_key,
        br_input_modulus_log,
        &id_lut,
        &noise_squashing_compression_key,
        &mut side_resources,
    );

    let noise_squashed: Vec<_> = input_zeros
        .into_par_iter()
        .map(|mut ct| {
            sks.unchecked_scalar_mul_assign(&mut ct, max_scalar_mul.try_into().unwrap());
            noise_squashing_key.squash_ciphertext_noise(&ct, &sks)
        })
        .collect();

    let compressed = noise_squashing_compression_key
        .compress_noise_squashed_ciphertexts_into_list(&noise_squashed);

    let underlying_glwes = &compressed.glwe_ciphertext_list;

    assert_eq!(underlying_glwes.len(), 1);

    let extracted = underlying_glwes[0].extract();

    // Bodies that were not filled are discarded
    after_packing.get_mut_body().as_mut()[compressed.len()..].fill(0);

    let sanity_check_valid = after_packing.as_view() == extracted.as_view();

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        sanity_check_valid,
        None,
        TestResult::Empty {},
    )
    .unwrap();

    assert_eq!(after_packing.as_view(), extracted.as_view());
}

create_parameterized_stringified_test!(sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks {
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
});

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_dp_ks_standard_pbs128_packing_ks_inner_helper(
    params: AtomicPatternParameters,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_noise_squashing_private_key: &NoiseSquashingPrivateKey,
    single_noise_squashing_key: &NoiseSquashingKey,
    single_noise_squashing_compression_private_key: &NoiseSquashingCompressionPrivateKey,
    single_noise_squashing_compression_key: &NoiseSquashingCompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (
    Vec<(
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
        DecryptionAndNoiseResult,
    )>,
    Vec<DecryptionAndNoiseResult>,
) {
    let mut engine = ShortintEngine::new();
    let thread_cks;
    let thread_sks;
    let thread_private_noise_squashing_key;
    let thread_noise_squashing_key;
    let thread_private_noise_squashing_compression_key;
    let thread_noise_squashing_compression_key;
    let (
        cks,
        sks,
        noise_squashing_private_key,
        noise_squashing_key,
        noise_squashing_compression_private_key,
        noise_squashing_compression_key,
    ) = if should_use_single_key_debug() {
        (
            single_cks,
            single_sks,
            single_noise_squashing_private_key,
            single_noise_squashing_key,
            single_noise_squashing_compression_private_key,
            single_noise_squashing_compression_key,
        )
    } else {
        thread_cks = engine.new_client_key(params);
        thread_sks = engine.new_server_key(&thread_cks);
        thread_private_noise_squashing_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
        thread_noise_squashing_key =
            NoiseSquashingKey::new(&thread_cks, &thread_private_noise_squashing_key);
        thread_private_noise_squashing_compression_key =
            NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
        thread_noise_squashing_compression_key = NoiseSquashingCompressionKey::new(
            &thread_private_noise_squashing_key,
            &thread_private_noise_squashing_compression_key,
        );

        (
            &thread_cks,
            &thread_sks,
            &thread_private_noise_squashing_key,
            &thread_noise_squashing_key,
            &thread_private_noise_squashing_compression_key,
            &thread_noise_squashing_compression_key,
        )
    };

    let modulus_switch_config = noise_squashing_key.noise_simulation_modulus_switch_config();

    let bsk_polynomial_size = noise_squashing_key.polynomial_size();
    let bsk_glwe_size = noise_squashing_key.glwe_size();
    let br_input_modulus_log = noise_squashing_key.br_input_modulus_log();

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let id_lut = generate_programmable_bootstrap_glwe_lut(
        bsk_polynomial_size,
        bsk_glwe_size,
        u128_encoding
            .cleartext_space_without_padding()
            .try_into()
            .unwrap(),
        u128_encoding.ciphertext_modulus,
        u128_encoding.delta(),
        |x| x,
    );

    let lwe_per_glwe = noise_squashing_compression_key.lwe_per_glwe();

    let inputs: Vec<_> = (0..lwe_per_glwe.0)
        .map(|_| DynLwe::U64(cks.encrypt(msg).ct))
        .collect();
    let mut side_resources = vec![(); inputs.len()];

    let (before_packing, after_packing) = dp_ks_any_ms_standard_pbs128_packing_ks(
        inputs,
        scalar_for_multiplication,
        sks,
        modulus_switch_config,
        noise_squashing_key,
        br_input_modulus_log,
        &id_lut,
        noise_squashing_compression_key,
        side_resources.as_mut_slice(),
    );

    let before_packing: Vec<_> = before_packing
        .into_iter()
        .map(
            |(input, after_dp, after_ks, after_drift, after_ms, after_pbs128)| {
                let before_ms = after_drift.as_ref().unwrap_or(&after_ks);

                let large_lwe_secret_key_dyn = cks.large_lwe_secret_key_as_dyn();
                let small_lwe_secret_key_dyn = cks.small_lwe_secret_key_as_dyn();

                (
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &input,
                        &large_lwe_secret_key_dyn,
                        msg,
                    ),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &after_dp,
                        &large_lwe_secret_key_dyn,
                        msg,
                    ),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        &after_ks,
                        &small_lwe_secret_key_dyn,
                        msg,
                    ),
                    DecryptionAndNoiseResult::new_from_dyn_lwe(
                        before_ms,
                        &small_lwe_secret_key_dyn,
                        msg,
                    ),
                    DecryptionAndNoiseResult::new_from_dyn_modswitched_lwe(
                        &after_ms,
                        &small_lwe_secret_key_dyn,
                        msg,
                    ),
                    // This one is a "raw" LWE given today we don't need to manage several unsigned
                    // integer types after a PBS128
                    DecryptionAndNoiseResult::new_from_lwe(
                        &after_pbs128,
                        &noise_squashing_private_key.post_noise_squashing_lwe_secret_key(),
                        msg.into(),
                        &u128_encoding,
                    ),
                )
            },
        )
        .collect();

    let after_packing = DecryptionAndNoiseResult::new_from_glwe(
        &after_packing,
        noise_squashing_compression_private_key.post_packing_ks_key(),
        lwe_per_glwe,
        msg.into(),
        &u128_encoding,
    );

    assert_eq!(after_packing.len(), lwe_per_glwe.0);

    (before_packing, after_packing)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn encrypt_dp_ks_standard_pbs128_packing_ks_noise_helper(
    params: AtomicPatternParameters,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
    single_cks: &ClientKey,
    single_sks: &ServerKey,
    single_noise_squashing_private_key: &NoiseSquashingPrivateKey,
    single_noise_squashing_key: &NoiseSquashingKey,
    single_noise_squashing_compression_private_key: &NoiseSquashingCompressionPrivateKey,
    single_noise_squashing_compression_key: &NoiseSquashingCompressionKey,
    msg: u64,
    scalar_for_multiplication: u64,
) -> (
    Vec<(
        NoiseSample,
        NoiseSample,
        NoiseSample,
        NoiseSample,
        NoiseSample,
        NoiseSample,
    )>,
    Vec<NoiseSample>,
) {
    let (before_compression, after_compression) =
        encrypt_dp_ks_standard_pbs128_packing_ks_inner_helper(
            params,
            noise_squashing_params,
            noise_squashing_compression_params,
            single_cks,
            single_sks,
            single_noise_squashing_private_key,
            single_noise_squashing_key,
            single_noise_squashing_compression_private_key,
            single_noise_squashing_compression_key,
            msg,
            scalar_for_multiplication,
        );

    (
        before_compression
            .into_iter()
            .map(
                |(input, after_dp, after_ks, after_drift, after_ms, after_pbs)| {
                    (
                        input
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_dp
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_ks
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_drift
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_ms
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                        after_pbs
                            .get_noise_if_decryption_was_correct()
                            .expect("Decryption Failed"),
                    )
                },
            )
            .collect(),
        after_compression
            .into_iter()
            .map(|after_compression| {
                after_compression
                    .get_noise_if_decryption_was_correct()
                    .expect("Decryption Failed")
            })
            .collect(),
    )
}

fn noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise(
    meta_params: MetaParameters,
    filename_suffix: &str,
) {
    write_empty_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
    )
    .unwrap();
    let (params, noise_squashing_params, noise_squashing_compression_params) = {
        let meta_noise_squashing_params = meta_params.noise_squashing_parameters.unwrap();
        (
            meta_params
                .compute_parameters
                .with_deterministic_execution(),
            meta_noise_squashing_params
                .parameters
                .with_deterministic_execution(),
            meta_noise_squashing_params.compression_parameters.unwrap(),
        )
    };

    let cks = ClientKey::new(params);
    let sks = ServerKey::new(&cks);
    let noise_squashing_private_key = NoiseSquashingPrivateKey::new(noise_squashing_params);
    let noise_squashing_key = NoiseSquashingKey::new(&cks, &noise_squashing_private_key);
    let noise_squashing_compression_private_key =
        NoiseSquashingCompressionPrivateKey::new(noise_squashing_compression_params);
    let noise_squashing_compression_key = NoiseSquashingCompressionKey::new(
        &noise_squashing_private_key,
        &noise_squashing_compression_private_key,
    );

    let noise_simulation_ksk =
        NoiseSimulationLweKeyswitchKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_modulus_switch_config =
        NoiseSimulationModulusSwitchConfig::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk128 =
        NoiseSimulationGenericBootstrapKey128::new_from_parameters(params, noise_squashing_params);
    let noise_simulation_packing_key =
        NoiseSimulationLwePackingKeyswitchKey::new_from_noise_squashing_parameters(
            noise_squashing_params,
            noise_squashing_compression_params,
        );

    let modulus_switch_config = noise_squashing_key.noise_simulation_modulus_switch_config();

    assert!(noise_simulation_ksk.matches_actual_shortint_server_key(&sks));
    assert!(noise_simulation_modulus_switch_config
        .matches_shortint_noise_squashing_modulus_switch_config(modulus_switch_config));
    assert!(
        noise_simulation_bsk128.matches_actual_shortint_noise_squashing_key(&noise_squashing_key)
    );
    assert!(noise_simulation_packing_key
        .matches_actual_pksk(noise_squashing_compression_key.packing_key_switching_key()));

    let br_input_modulus_log = noise_squashing_key.br_input_modulus_log();

    let max_scalar_mul = sks.max_noise_level.get();

    let noise_simulation_accumulator = NoiseSimulationGlwe::new(
        noise_simulation_bsk128
            .output_glwe_size()
            .to_glwe_dimension(),
        noise_simulation_bsk128.output_polynomial_size(),
        Variance(0.0),
        noise_simulation_bsk128.modulus(),
    );

    let (_before_packing_sim, after_packing_sim) = {
        let noise_simulation = NoiseSimulationLwe::encrypt(&cks, 0);
        dp_ks_any_ms_standard_pbs128_packing_ks(
            vec![noise_simulation; noise_squashing_compression_key.lwe_per_glwe().0],
            max_scalar_mul,
            &noise_simulation_ksk,
            noise_simulation_modulus_switch_config.as_ref(),
            &noise_simulation_bsk128,
            br_input_modulus_log,
            &noise_simulation_accumulator,
            &noise_simulation_packing_key,
            &mut vec![(); noise_squashing_compression_key.lwe_per_glwe().0],
        )
    };

    let after_packing_sim = after_packing_sim.into_lwe();

    // Check that the circuit is correct with respect to core implementation, i.e. does not crash on
    // dimension checks
    let (expected_lwe_dimension_out, expected_modulus_f64_out) = {
        let pksk = noise_squashing_compression_key.packing_key_switching_key();

        let out_glwe_dim = pksk.output_key_glwe_dimension();
        let out_poly_size = pksk.output_key_polynomial_size();

        (
            out_glwe_dim.to_equivalent_lwe_dimension(out_poly_size),
            pksk.ciphertext_modulus().raw_modulus_float(),
        )
    };

    assert_eq!(
        after_packing_sim.lwe_dimension(),
        expected_lwe_dimension_out
    );
    assert_eq!(
        after_packing_sim.modulus().as_f64(),
        expected_modulus_f64_out
    );

    let cleartext_modulus = params.message_modulus().0 * params.carry_modulus().0;
    let mut noise_samples_after_packing = vec![];

    let sample_count_per_msg = 1000usize.div_ceil(noise_squashing_compression_key.lwe_per_glwe().0);

    for _ in 0..cleartext_modulus {
        let current_noise_samples_after_packing: Vec<_> = (0..sample_count_per_msg)
            .into_par_iter()
            .map(|_| {
                let (_before_packing, after_packing) =
                    encrypt_dp_ks_standard_pbs128_packing_ks_noise_helper(
                        params,
                        noise_squashing_params,
                        noise_squashing_compression_params,
                        &cks,
                        &sks,
                        &noise_squashing_private_key,
                        &noise_squashing_key,
                        &noise_squashing_compression_private_key,
                        &noise_squashing_compression_key,
                        0,
                        max_scalar_mul,
                    );
                after_packing
            })
            .flatten()
            .collect();

        noise_samples_after_packing.extend(
            current_noise_samples_after_packing
                .into_iter()
                .map(|x| x.value),
        );
    }

    let (after_packing_is_ok, bounded_variance_measurement, bounded_mean_measurement) =
        mean_and_variance_check(
            &noise_samples_after_packing,
            "after_packing",
            0.0,
            after_packing_sim.variance(),
            noise_squashing_compression_params.packing_ks_key_noise_distribution,
            after_packing_sim.lwe_dimension(),
            after_packing_sim.modulus().as_f64(),
        );

    let noise_check = TestResult::NoiseCheckWithoutNormalityCheck(Box::new(
        super::utils::to_json::NoiseCheckWithoutNormalityCheck::new(
            bounded_variance_measurement,
            bounded_mean_measurement,
        ),
    ));

    write_to_json_file(
        &meta_params,
        filename_suffix,
        this_function_name!().as_str(),
        after_packing_is_ok,
        None,
        noise_check,
    )
    .unwrap();

    assert!(after_packing_is_ok);
}

create_parameterized_stringified_test!(
    noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise {
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    }
);
