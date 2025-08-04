use super::should_use_single_key_debug;
use super::utils::noise_simulation::*;
use super::utils::traits::*;
use super::utils::{mean_and_variance_check, DecryptionAndNoiseResult, NoiseSample};
use crate::core_crypto::algorithms::lwe_programmable_bootstrapping::generate_programmable_bootstrap_glwe_lut;
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::CiphertextModulusLog;
use crate::shortint::atomic_pattern::AtomicPatternServerKey;
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::encoding::{PaddingBit, ShortintEncoding};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::{
    NoiseSquashingCompressionKey, NoiseSquashingCompressionPrivateKey,
};
use crate::shortint::noise_squashing::{
    NoiseSquashingKey, NoiseSquashingPrivateKey, Shortint128BootstrappingKey,
};
use crate::shortint::parameters::noise_squashing::NoiseSquashingParameters;
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{AtomicPatternParameters, NoiseSquashingCompressionParameters};
use crate::shortint::server_key::{ModulusSwitchConfiguration, ServerKey};
use rayon::prelude::*;

#[allow(clippy::too_many_arguments)]
fn dp_ks_standard_pbs128<
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
    mod_switch_noise_reduction_key_128: &DriftKey,
    bsk_128: &Bsk,
    br_input_modulus_log: CiphertextModulusLog,
    accumulator: &Accumulator,
    side_resources: &mut Resources,
) -> (
    InputCt,
    ScalarMulResult,
    KsResult,
    DriftTechniqueResult,
    MsResult,
    PbsResult,
)
where
    // InputCt needs to be multipliable by the given scalar
    InputCt: ScalarMul<DPScalar, Output = ScalarMulResult, SideResources = Resources>,
    // We need to be able to allocate the result and keyswitch the result of the ScalarMul
    KsKey: AllocateLweKeyswitchResult<Output = KsResult, SideResources = Resources>
        + LweKeyswitch<ScalarMulResult, KsResult, SideResources = Resources>,
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
    Bsk: LweStandardFft128Bootstrap<MsResult, PbsResult, Accumulator, SideResources = Resources>,
{
    let after_dp = input.scalar_mul(scalar, side_resources);
    let mut ks_result = ksk.allocate_lwe_keyswitch_result(side_resources);
    ksk.lwe_keyswitch(&after_dp, &mut ks_result, side_resources);
    let (mut drift_technique_result, mut ms_result) = mod_switch_noise_reduction_key_128
        .allocate_drift_technique_standard_mod_switch_result(side_resources);
    mod_switch_noise_reduction_key_128.drift_technique_and_standard_mod_switch(
        br_input_modulus_log,
        &ks_result,
        &mut drift_technique_result,
        &mut ms_result,
        side_resources,
    );

    let mut pbs_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
    bsk_128.lwe_standard_fft_128_pbs(&ms_result, &mut pbs_result, accumulator, side_resources);
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
fn dp_ks_standard_pbs128_packing_ks<
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
    mod_switch_noise_reduction_key_128: &DriftKey,
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
        DriftTechniqueResult,
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
    Bsk: LweStandardFft128Bootstrap<MsResult, PbsResult, Accumulator, SideResources = Resources>
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
                dp_ks_standard_pbs128(
                    input,
                    scalar,
                    ksk,
                    mod_switch_noise_reduction_key_128,
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
fn sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks<P>(
    params: P,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
) where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
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

    let u128_encoding = ShortintEncoding {
        ciphertext_modulus: noise_squashing_params.ciphertext_modulus(),
        message_modulus: noise_squashing_params.message_modulus(),
        carry_modulus: noise_squashing_params.carry_modulus(),
        padding_bit: PaddingBit::Yes,
    };

    let max_scalar_mul = sks.max_noise_level.get();

    match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            let ksk = &standard_atomic_pattern_server_key.key_switching_key;
            let bsk = noise_squashing_key.bootstrapping_key();
            let (fbsk, drift_key) = match bsk {
                Shortint128BootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key,
                } => (bsk, modulus_switch_noise_reduction_key),
                Shortint128BootstrappingKey::MultiBit { .. } => todo!(),
            };
            let drift_key = {
                match drift_key {
                    ModulusSwitchConfiguration::Standard => None,
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    ) => Some(modulus_switch_noise_reduction_key),
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction => None,
                }
                .unwrap()
            };
            let pksk = noise_squashing_compression_key.packing_key_switching_key();

            let id_lut = generate_programmable_bootstrap_glwe_lut(
                fbsk.polynomial_size(),
                fbsk.glwe_size(),
                u128_encoding
                    .cleartext_space_without_padding()
                    .try_into()
                    .unwrap(),
                u128_encoding.ciphertext_modulus,
                u128_encoding.delta(),
                |x| x,
            );

            let br_input_modulus_log = fbsk.polynomial_size().to_blind_rotation_input_modulus_log();

            let input_zeros: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.encrypt(0)).collect();
            let mut side_resources = vec![(); input_zeros.len()];
            let input_zero_as_lwe: Vec<_> = input_zeros.iter().map(|ct| ct.ct.clone()).collect();

            let (_before_packing, mut after_packing) = dp_ks_standard_pbs128_packing_ks(
                input_zero_as_lwe,
                max_scalar_mul,
                ksk,
                drift_key,
                fbsk,
                br_input_modulus_log,
                &id_lut,
                pksk,
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

            let underlying_glwes = compressed.glwe_ciphertext_list;

            assert_eq!(underlying_glwes.len(), 1);

            let extracted = underlying_glwes[0].extract();

            // Bodies that were not filled are discarded
            after_packing.get_mut_body().as_mut()[lwe_per_glwe.0..].fill(0);

            assert_eq!(after_packing.as_view(), extracted.as_view());
        }
        AtomicPatternServerKey::KeySwitch32(_ks32_atomic_pattern_server_key) => {
            todo!();
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    }
}

#[test]
fn test_sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks_test_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    sanity_check_encrypt_dp_ks_standard_pbs128_packing_ks(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}

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

    let ksk = match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            &standard_atomic_pattern_server_key.key_switching_key
        }
        AtomicPatternServerKey::KeySwitch32(_) => {
            todo!()
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    };

    let (bsk_128, drift_key) = {
        let (bsk, drift_key) = match noise_squashing_key.bootstrapping_key() {
            Shortint128BootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key,
            } => (bsk, modulus_switch_noise_reduction_key),
            Shortint128BootstrappingKey::MultiBit { .. } => todo!(),
        };

        let drift_key = match drift_key {
            ModulusSwitchConfiguration::Standard => None,
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                modulus_switch_noise_reduction_key,
            ) => Some(modulus_switch_noise_reduction_key),
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => None,
        }
        .unwrap();

        (bsk, drift_key)
    };

    let bsk_polynomial_size = bsk_128.polynomial_size();
    let bsk_glwe_size = bsk_128.glwe_size();
    let br_input_modulus_log = bsk_128
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();

    let compression_pksk = noise_squashing_compression_key.packing_key_switching_key();

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

    let inputs: Vec<_> = (0..lwe_per_glwe.0).map(|_| cks.encrypt(msg).ct).collect();
    let mut side_resources = vec![(); inputs.len()];

    let (before_packing, after_packing) = dp_ks_standard_pbs128_packing_ks(
        inputs,
        scalar_for_multiplication,
        ksk,
        drift_key,
        bsk_128,
        br_input_modulus_log,
        &id_lut,
        compression_pksk,
        side_resources.as_mut_slice(),
    );

    let u64_encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);

    let before_packing: Vec<_> = before_packing
        .into_iter()
        .map(
            |(input, after_dp, after_ks, after_drift, after_ms, after_pbs128)| match &cks
                .atomic_pattern
            {
                AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => (
                    DecryptionAndNoiseResult::new(
                        &input,
                        &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                        msg,
                        &u64_encoding,
                    ),
                    DecryptionAndNoiseResult::new(
                        &after_dp,
                        &standard_atomic_pattern_client_key.large_lwe_secret_key(),
                        msg,
                        &u64_encoding,
                    ),
                    DecryptionAndNoiseResult::new(
                        &after_ks,
                        &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                        msg,
                        &u64_encoding,
                    ),
                    DecryptionAndNoiseResult::new(
                        &after_drift,
                        &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                        msg,
                        &u64_encoding,
                    ),
                    DecryptionAndNoiseResult::new(
                        &after_ms,
                        &standard_atomic_pattern_client_key.small_lwe_secret_key(),
                        msg,
                        &u64_encoding,
                    ),
                    DecryptionAndNoiseResult::new(
                        &after_pbs128,
                        &noise_squashing_private_key.post_noise_squashing_lwe_secret_key(),
                        msg.into(),
                        &u128_encoding,
                    ),
                ),
                AtomicPatternClientKey::KeySwitch32(_) => todo!(),
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

fn noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise<P>(
    params: P,
    noise_squashing_params: NoiseSquashingParameters,
    noise_squashing_compression_params: NoiseSquashingCompressionParameters,
) where
    P: Into<AtomicPatternParameters>,
{
    let params: AtomicPatternParameters = params.into();
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

    let noise_simulation_ksk = NoiseSimulationLweKsk::new_from_atomic_pattern_parameters(params);
    let noise_simulation_drift_key =
        NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);
    let noise_simulation_bsk128 =
        NoiseSimulationLweFourier128Bsk::new_from_parameters(params, noise_squashing_params);
    let noise_simulation_packing_key = NoiseSimulationLwePackingKeyswitchKey::new_from_params(
        noise_squashing_params,
        noise_squashing_compression_params,
    );

    let fbsk_128 = match noise_squashing_key.bootstrapping_key() {
        Shortint128BootstrappingKey::Classic {
            bsk,
            modulus_switch_noise_reduction_key: _,
        } => bsk,
        Shortint128BootstrappingKey::MultiBit { .. } => todo!(),
    };

    assert!(noise_simulation_bsk128.matches_actual_bsk(fbsk_128));
    assert!(noise_simulation_packing_key
        .matches_actual_pksk(noise_squashing_compression_key.packing_key_switching_key()));

    let br_input_modulus_log = noise_squashing_key
        .bootstrapping_key()
        .polynomial_size()
        .to_blind_rotation_input_modulus_log();

    match &sks.atomic_pattern {
        AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&standard_atomic_pattern_server_key.key_switching_key));
        }
        AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
            assert!(noise_simulation_ksk
                .matches_actual_ksk(&ks32_atomic_pattern_server_key.key_switching_key));
        }
        AtomicPatternServerKey::Dynamic(_) => unimplemented!(),
    }

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
        dp_ks_standard_pbs128_packing_ks(
            vec![noise_simulation; noise_squashing_compression_key.lwe_per_glwe().0],
            max_scalar_mul,
            &noise_simulation_ksk,
            &noise_simulation_drift_key,
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

    let after_packing_is_ok = mean_and_variance_check(
        &noise_samples_after_packing,
        "after_packing",
        0.0,
        after_packing_sim.variance(),
        noise_squashing_compression_params.packing_ks_key_noise_distribution,
        after_packing_sim.lwe_dimension(),
        after_packing_sim.modulus().as_f64(),
    );

    assert!(after_packing_is_ok);
}

#[test]
fn test_noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise_param_message_2_carry_2_ks_pbs_tuniform_2m128(
) {
    noise_check_encrypt_dp_ks_standard_pbs128_packing_ks_noise(
        TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        TEST_PARAM_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    )
}
