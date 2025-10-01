use super::utils::traits::*;
use crate::shortint::parameters::CiphertextModulusLog;
use crate::shortint::server_key::tests::noise_distribution::utils::noise_simulation::NoiseSimulationModulusSwitchConfig;

#[allow(clippy::too_many_arguments)]
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
    PBSKey,
    DPScalar,
    KsKey,
    DriftKey,
    Accumulator,
    Resources,
>(
    input: InputCt,
    bsk: &PBSKey,
    input_zero_rerand: InputZeroRerand,
    ksk_rerand: &KsKeyRerand,
    scalar: DPScalar,
    ksk: &KsKey,
    modulus_switch_configuration: NoiseSimulationModulusSwitchConfig,
    mod_switch_noise_reduction_key: Option<&DriftKey>,
    accumulator: &Accumulator,
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
    PBSKey: LweClassicFftBootstrap<InputCt, PBSResult, Accumulator, SideResources = Resources>,
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
        > + CenteredBinaryShiftedStandardModSwitch<MsResult, SideResources = Resources>,
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
    let mut br_result = accumulator.allocate_lwe_bootstrap_result(side_resources);
    bsk.lwe_classic_fft_pbs(&input, &mut br_result, accumulator, side_resources);

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
    let (drift_technique_result, ms_result) =
        match (modulus_switch_configuration, mod_switch_noise_reduction_key) {
            (
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction,
                Some(mod_switch_noise_reduction_key),
            ) => {
                let (mut drift_technique_result, mut ms_result) = mod_switch_noise_reduction_key
                    .allocate_drift_technique_standard_mod_switch_result(side_resources);
                mod_switch_noise_reduction_key.drift_technique_and_standard_mod_switch(
                    br_input_modulus_log,
                    &ks_result,
                    &mut drift_technique_result,
                    &mut ms_result,
                    side_resources,
                );

                (Some(drift_technique_result), ms_result)
            }
            (NoiseSimulationModulusSwitchConfig::Standard, None) => {
                let mut ms_result = ks_result.allocate_standard_mod_switch_result(side_resources);
                ks_result.standard_mod_switch(br_input_modulus_log, &mut ms_result, side_resources);

                (None, ms_result)
            }
            (NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction, None) => {
                let mut ms_result = ks_result
                    .allocate_centered_binary_shifted_standard_mod_switch_result(side_resources);
                ks_result.centered_binary_shifted_and_standard_mod_switch(
                    br_input_modulus_log,
                    &mut ms_result,
                    side_resources,
                );

                (None, ms_result)
            }
            _ => panic!("Inconsistent modulus switch and drift key configuration"),
        };

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
