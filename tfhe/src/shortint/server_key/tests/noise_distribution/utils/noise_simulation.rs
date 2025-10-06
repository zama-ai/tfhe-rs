pub use crate::core_crypto::commons::noise_formulas::noise_simulation::*;

use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::noise_formulas::generalized_modulus_switch::generalized_modulus_switch_additive_variance;
use crate::core_crypto::commons::noise_formulas::noise_simulation::traits::{
    AllocateCenteredBinaryShiftedStandardModSwitchResult,
    AllocateDriftTechniqueStandardModSwitchResult, AllocateLweBootstrapResult,
    AllocateLweKeyswitchResult, AllocateLwePackingKeyswitchResult, AllocateStandardModSwitchResult,
    CenteredBinaryShiftedStandardModSwitch, DriftTechniqueStandardModSwitch,
    LweClassicFft128Bootstrap, LweClassicFftBootstrap, LweKeyswitch, LwePackingKeyswitch,
    LweUncorrelatedAdd, LweUncorrelatedSub, ScalarMul, StandardModSwitch,
};
use crate::core_crypto::commons::numeric::{CastInto, UnsignedInteger};
use crate::core_crypto::commons::parameters::{
    CiphertextModulus, CiphertextModulusLog, DynamicDistribution, GlweSize, LweDimension, LweSize,
    PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut};
use crate::core_crypto::entities::{
    GlweCiphertext, GlweCiphertextOwned, LweCiphertext, LweCiphertextOwned, LweCiphertextView,
};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::list_compression::NoiseSquashingCompressionKey;
use crate::shortint::noise_squashing::atomic_pattern::AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    NoiseSquashingKey, Shortint128BootstrappingKey, StandardNoiseSquashingKeyView,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, ModulusSwitchType, NoiseSquashingCompressionParameters,
    NoiseSquashingParameters, PBSParameters,
};
use crate::shortint::server_key::tests::noise_distribution::utils::encrypt_new_noiseless_lwe;
use crate::shortint::server_key::{
    AtomicPatternServerKey, LookupTable, ModulusSwitchConfiguration,
    ModulusSwitchNoiseReductionKey, ServerKey, ShortintBootstrappingKey,
};
use crate::shortint::{PaddingBit, ShortintEncoding};

#[derive(Clone, PartialEq, Eq)]
pub enum DynLwe {
    U32(LweCiphertextOwned<u32>),
    U64(LweCiphertextOwned<u64>),
    U128(LweCiphertextOwned<u128>),
}

impl DynLwe {
    pub fn lwe_size(&self) -> LweSize {
        match self {
            Self::U32(lwe_ciphertext) => lwe_ciphertext.lwe_size(),
            Self::U64(lwe_ciphertext) => lwe_ciphertext.lwe_size(),
            Self::U128(lwe_ciphertext) => lwe_ciphertext.lwe_size(),
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.lwe_size().to_lwe_dimension()
    }

    pub fn raw_modulus_float(&self) -> f64 {
        match self {
            Self::U32(lwe_ciphertext) => lwe_ciphertext.ciphertext_modulus().raw_modulus_float(),
            Self::U64(lwe_ciphertext) => lwe_ciphertext.ciphertext_modulus().raw_modulus_float(),
            Self::U128(lwe_ciphertext) => lwe_ciphertext.ciphertext_modulus().raw_modulus_float(),
        }
    }

    pub fn try_into_lwe_32(self) -> Option<LweCiphertextOwned<u32>> {
        match self {
            Self::U32(lwe_ciphertext) => Some(lwe_ciphertext),
            Self::U64(_) => None,
            Self::U128(_) => None,
        }
    }

    pub fn try_into_lwe_64(self) -> Option<LweCiphertextOwned<u64>> {
        match self {
            Self::U32(_) => None,
            Self::U64(lwe_ciphertext) => Some(lwe_ciphertext),
            Self::U128(_) => None,
        }
    }

    pub fn try_into_lwe_128(self) -> Option<LweCiphertextOwned<u128>> {
        match self {
            Self::U32(_) => None,
            Self::U64(_) => None,
            Self::U128(lwe_ciphertext) => Some(lwe_ciphertext),
        }
    }

    #[track_caller]
    pub fn into_lwe_32(self) -> LweCiphertextOwned<u32> {
        self.try_into_lwe_32().unwrap()
    }

    #[track_caller]
    pub fn into_lwe_64(self) -> LweCiphertextOwned<u64> {
        self.try_into_lwe_64().unwrap()
    }

    #[track_caller]
    pub fn into_lwe_128(self) -> LweCiphertextOwned<u128> {
        self.try_into_lwe_128().unwrap()
    }

    #[track_caller]
    pub fn as_lwe_32(&self) -> LweCiphertextView<'_, u32> {
        match self {
            Self::U32(lwe_ciphertext) => lwe_ciphertext.as_view(),
            Self::U64(_) => panic!("Tried getting a u64 LweCiphertext as u32."),
            Self::U128(_) => panic!("Tried getting a u128 LweCiphertext as u32."),
        }
    }

    #[track_caller]
    pub fn as_lwe_64(&self) -> LweCiphertextView<'_, u64> {
        match self {
            Self::U32(_) => panic!("Tried getting a u32 LweCiphertext as u64."),
            Self::U64(lwe_ciphertext) => lwe_ciphertext.as_view(),
            Self::U128(_) => panic!("Tried getting a u128 LweCiphertext as u64."),
        }
    }

    #[track_caller]
    pub fn as_lwe_128(&self) -> LweCiphertextView<'_, u128> {
        match self {
            Self::U32(_) => panic!("Tried getting a u32 LweCiphertext as u128."),
            Self::U64(_) => panic!("Tried getting a u64 LweCiphertext as u128."),
            Self::U128(lwe_ciphertext) => lwe_ciphertext.as_view(),
        }
    }
}

impl<Scalar: CastInto<u32> + CastInto<u64> + CastInto<u128>> ScalarMul<Scalar> for DynLwe {
    type Output = Self;
    type SideResources = ();

    fn scalar_mul(&self, rhs: Scalar, side_resources: &mut Self::SideResources) -> Self::Output {
        match self {
            Self::U32(lwe_ciphertext) => {
                Self::U32(lwe_ciphertext.scalar_mul(rhs.cast_into(), side_resources))
            }
            Self::U64(lwe_ciphertext) => {
                Self::U64(lwe_ciphertext.scalar_mul(rhs.cast_into(), side_resources))
            }
            Self::U128(lwe_ciphertext) => {
                Self::U128(lwe_ciphertext.scalar_mul(rhs.cast_into(), side_resources))
            }
        }
    }
}

impl<'rhs> LweUncorrelatedAdd<&'rhs Self> for DynLwe {
    type Output = Self;
    type SideResources = ();

    fn lwe_uncorrelated_add(
        &self,
        rhs: &'rhs Self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match (self, rhs) {
            (DynLwe::U32(lhs), DynLwe::U32(rhs)) => {
                DynLwe::U32(lhs.lwe_uncorrelated_add(rhs, side_resources))
            }
            (DynLwe::U64(lhs), DynLwe::U64(rhs)) => {
                DynLwe::U64(lhs.lwe_uncorrelated_add(rhs, side_resources))
            }
            (DynLwe::U128(lhs), DynLwe::U128(rhs)) => {
                DynLwe::U128(lhs.lwe_uncorrelated_add(rhs, side_resources))
            }
            _ => panic!("Inconsistent lhs and rhs"),
        }
    }
}

impl<'rhs> LweUncorrelatedSub<&'rhs Self> for DynLwe {
    type Output = Self;
    type SideResources = ();

    fn lwe_uncorrelated_sub(
        &self,
        rhs: &'rhs Self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match (self, rhs) {
            (DynLwe::U32(lhs), DynLwe::U32(rhs)) => {
                DynLwe::U32(lhs.lwe_uncorrelated_sub(rhs, side_resources))
            }
            (DynLwe::U64(lhs), DynLwe::U64(rhs)) => {
                DynLwe::U64(lhs.lwe_uncorrelated_sub(rhs, side_resources))
            }
            (DynLwe::U128(lhs), DynLwe::U128(rhs)) => {
                DynLwe::U128(lhs.lwe_uncorrelated_sub(rhs, side_resources))
            }
            _ => panic!("Inconsistent lhs and rhs"),
        }
    }
}

impl AllocateStandardModSwitchResult for DynLwe {
    type Output = Self;
    type SideResources = ();

    fn allocate_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match self {
            Self::U32(lwe_ciphertext) => {
                Self::U32(lwe_ciphertext.allocate_standard_mod_switch_result(side_resources))
            }
            Self::U64(lwe_ciphertext) => {
                Self::U64(lwe_ciphertext.allocate_standard_mod_switch_result(side_resources))
            }
            Self::U128(lwe_ciphertext) => {
                Self::U128(lwe_ciphertext.allocate_standard_mod_switch_result(side_resources))
            }
        }
    }
}

impl StandardModSwitch<Self> for DynLwe {
    type SideResources = ();

    fn standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Self,
        side_resources: &mut Self::SideResources,
    ) {
        match (self, output) {
            (Self::U32(input), Self::U32(output)) => {
                input.standard_mod_switch(output_modulus_log, output, side_resources)
            }
            (Self::U64(input), Self::U64(output)) => {
                input.standard_mod_switch(output_modulus_log, output, side_resources)
            }
            (Self::U128(input), Self::U128(output)) => {
                input.standard_mod_switch(output_modulus_log, output, side_resources)
            }
            _ => panic!("Inconsistent inputs/ouptuts for DynLwe StandardModSwitch"),
        }
    }
}

impl AllocateCenteredBinaryShiftedStandardModSwitchResult for DynLwe {
    type Output = Self;
    type SideResources = ();

    fn allocate_centered_binary_shifted_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match self {
            Self::U32(lwe_ciphertext) => Self::U32(
                lwe_ciphertext
                    .allocate_centered_binary_shifted_standard_mod_switch_result(side_resources),
            ),
            Self::U64(lwe_ciphertext) => Self::U64(
                lwe_ciphertext
                    .allocate_centered_binary_shifted_standard_mod_switch_result(side_resources),
            ),
            Self::U128(lwe_ciphertext) => Self::U128(
                lwe_ciphertext
                    .allocate_centered_binary_shifted_standard_mod_switch_result(side_resources),
            ),
        }
    }
}

impl CenteredBinaryShiftedStandardModSwitch<Self> for DynLwe {
    type SideResources = ();

    fn centered_binary_shifted_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Self,
        side_resources: &mut Self::SideResources,
    ) {
        match (self, output) {
            (Self::U32(input), Self::U32(output)) => input
                .centered_binary_shifted_and_standard_mod_switch(
                    output_modulus_log,
                    output,
                    side_resources,
                ),
            (Self::U64(input), Self::U64(output)) => input
                .centered_binary_shifted_and_standard_mod_switch(
                    output_modulus_log,
                    output,
                    side_resources,
                ),
            (Self::U128(input), Self::U128(output)) => input
                .centered_binary_shifted_and_standard_mod_switch(
                    output_modulus_log,
                    output,
                    side_resources,
                ),
            _ => panic!("Inconsistent inputs/ouptuts for DynLwe StandardModSwitch"),
        }
    }
}

impl ClientKey {
    pub fn encrypt_noiseless_pbs_input_dyn_lwe(
        &self,
        modulus_log: CiphertextModulusLog,
        msg: u64,
    ) -> DynLwe {
        match &self.atomic_pattern {
            AtomicPatternClientKey::Standard(standard_atomic_pattern_client_key) => {
                let params = standard_atomic_pattern_client_key.parameters;
                let encoding = ShortintEncoding {
                    ciphertext_modulus: params.ciphertext_modulus(),
                    message_modulus: params.message_modulus(),
                    carry_modulus: params.carry_modulus(),
                    padding_bit: PaddingBit::Yes,
                };

                ShortintEngine::with_thread_local_mut(|engine| {
                    DynLwe::U64(encrypt_new_noiseless_lwe(
                        &standard_atomic_pattern_client_key.lwe_secret_key,
                        CiphertextModulus::try_new_power_of_2(modulus_log.0).unwrap(),
                        msg,
                        &encoding,
                        &mut engine.encryption_generator,
                    ))
                })
            }
            AtomicPatternClientKey::KeySwitch32(ks32_atomic_pattern_client_key) => {
                let params = ks32_atomic_pattern_client_key.parameters;
                let encoding = ShortintEncoding {
                    ciphertext_modulus: params.post_keyswitch_ciphertext_modulus(),
                    message_modulus: params.message_modulus(),
                    carry_modulus: params.carry_modulus(),
                    padding_bit: PaddingBit::Yes,
                };

                ShortintEngine::with_thread_local_mut(|engine| {
                    DynLwe::U32(encrypt_new_noiseless_lwe(
                        &ks32_atomic_pattern_client_key.lwe_secret_key,
                        CiphertextModulus::try_new_power_of_2(modulus_log.0).unwrap(),
                        msg.try_into().unwrap(),
                        &encoding,
                        &mut engine.encryption_generator,
                    ))
                })
            }
        }
    }
}

impl AllocateLweKeyswitchResult for ServerKey {
    type Output = DynLwe;
    type SideResources = ();

    fn allocate_lwe_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => DynLwe::U64(
                standard_atomic_pattern_server_key
                    .key_switching_key
                    .allocate_lwe_keyswitch_result(side_resources),
            ),
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => DynLwe::U32(
                ks32_atomic_pattern_server_key
                    .key_switching_key
                    .allocate_lwe_keyswitch_result(side_resources),
            ),
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseSimulationModulusSwitchConfig {
    Standard,
    DriftTechniqueNoiseReduction,
    CenteredMeanNoiseReduction,
}

impl NoiseSimulationModulusSwitchConfig {
    pub fn expected_average_after_ms(self, polynomial_size: PolynomialSize) -> f64 {
        match self {
            Self::Standard => 0.0f64,
            Self::DriftTechniqueNoiseReduction => 0.0f64,
            Self::CenteredMeanNoiseReduction => {
                // Half case subtracted before entering the blind rotate
                -1.0f64 / (4.0 * polynomial_size.0 as f64)
            }
        }
    }
}

impl<Scalar: UnsignedInteger> From<&ModulusSwitchConfiguration<Scalar>>
    for NoiseSimulationModulusSwitchConfig
{
    fn from(value: &ModulusSwitchConfiguration<Scalar>) -> Self {
        match value {
            ModulusSwitchConfiguration::Standard => Self::Standard,
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(_) => {
                Self::DriftTechniqueNoiseReduction
            }
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => {
                Self::CenteredMeanNoiseReduction
            }
        }
    }
}

impl ServerKey {
    pub fn br_input_modulus_log(&self) -> CiphertextModulusLog {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                standard_atomic_pattern_server_key
                    .bootstrapping_key
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log()
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                ks32_atomic_pattern_server_key
                    .bootstrapping_key
                    .polynomial_size()
                    .to_blind_rotation_input_modulus_log()
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }

    pub fn noise_simulation_modulus_switch_config(&self) -> NoiseSimulationModulusSwitchConfig {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => modulus_switch_noise_reduction_key.into(),
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        todo!("Unsupported ShortintBootstrappingKey::MultiBit for noise simulation")
                    }
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => modulus_switch_noise_reduction_key.into(),
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        todo!("Unsupported ShortintBootstrappingKey::MultiBit for noise simulation")
                    }
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl LweKeyswitch<DynLwe, DynLwe> for ServerKey {
    type SideResources = ();

    fn lwe_keyswitch(
        &self,
        input: &DynLwe,
        output: &mut DynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match (input, output) {
                    (DynLwe::U64(input), DynLwe::U64(output)) => standard_atomic_pattern_server_key
                        .key_switching_key
                        .lwe_keyswitch(input, output, side_resources),
                    _ => panic!("AtomicPatternServerKey::Standard only supports DynLwe::U64"),
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match (input, output) {
                    (DynLwe::U64(input), DynLwe::U32(output)) => ks32_atomic_pattern_server_key
                        .key_switching_key
                        .lwe_keyswitch(input, output, side_resources),
                    _ => panic!(
                        "AtomicPatternServerKey::KeySwitch32 \
                        only supports DynLwe::U64 input and DynLwe::U32 output"
                    ),
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for ServerKey {
    type AfterDriftOutput = DynLwe;
    type AfterMsOutput = DynLwe;
    type SideResources = ();

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => match modulus_switch_noise_reduction_key {
                        ModulusSwitchConfiguration::Standard => panic!(
                            "ModulusSwitchConfiguration::Standard \
                            does not support the drift technique"
                        ),
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ) => {
                            let (after_drift, after_ms) = modulus_switch_noise_reduction_key
                                .allocate_drift_technique_standard_mod_switch_result(
                                    side_resources,
                                );

                            (DynLwe::U64(after_drift), DynLwe::U64(after_ms))
                        }
                        ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                            "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                            does not support the drift technique"
                        ),
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support the drift technique")
                    }
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => match modulus_switch_noise_reduction_key {
                        ModulusSwitchConfiguration::Standard => panic!(
                            "ModulusSwitchConfiguration::Standard \
                            does not support the drift technique"
                        ),
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ) => {
                            let (after_drift, after_ms) = modulus_switch_noise_reduction_key
                                .allocate_drift_technique_standard_mod_switch_result(
                                    side_resources,
                                );

                            (DynLwe::U32(after_drift), DynLwe::U32(after_ms))
                        }
                        ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                            "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                            does not support the drift technique"
                        ),
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support the drift technique")
                    }
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl DriftTechniqueStandardModSwitch<DynLwe, DynLwe, DynLwe> for ServerKey {
    type SideResources = ();

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &DynLwe,
        after_drift_technique: &mut DynLwe,
        after_mod_switch: &mut DynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => match modulus_switch_noise_reduction_key {
                        ModulusSwitchConfiguration::Standard => panic!(
                            "ModulusSwitchConfiguration::Standard \
                            does not support the drift technique"
                        ),
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ) => match (input, after_drift_technique, after_mod_switch) {
                            (
                                DynLwe::U64(input),
                                DynLwe::U64(after_drift_technique),
                                DynLwe::U64(after_mod_switch),
                            ) => {
                                modulus_switch_noise_reduction_key
                                    .drift_technique_and_standard_mod_switch(
                                        output_modulus_log,
                                        input,
                                        after_drift_technique,
                                        after_mod_switch,
                                        side_resources,
                                    );
                            }
                            _ => {
                                panic!("AtomicPatternServerKey::Standard only supports DynLwe::U64")
                            }
                        },
                        ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                            "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                            does not support the drift technique"
                        ),
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support the drift technique")
                    }
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => {
                        match modulus_switch_noise_reduction_key {
                            ModulusSwitchConfiguration::Standard => panic!(
                                "ModulusSwitchConfiguration::Standard \
                            does not support the drift technique"
                            ),
                            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                                modulus_switch_noise_reduction_key,
                            ) => match (input, after_drift_technique, after_mod_switch) {
                                (
                                    DynLwe::U32(input),
                                    DynLwe::U32(after_drift_technique),
                                    DynLwe::U32(after_mod_switch),
                                ) => {
                                    modulus_switch_noise_reduction_key
                                        .drift_technique_and_standard_mod_switch(
                                            output_modulus_log,
                                            input,
                                            after_drift_technique,
                                            after_mod_switch,
                                            side_resources,
                                        );
                                }
                                _ => {
                                    panic!("AtomicPatternServerKey::KeySwitch32 only supports DynLwe::U32")
                                }
                            },
                            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                                "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                            does not support the drift technique"
                            ),
                        }
                    }
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support the drift technique")
                    }
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl<C: Container<Element = u64>> AllocateLweBootstrapResult for LookupTable<C> {
    type Output = DynLwe;
    type SideResources = ();

    fn allocate_lwe_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        DynLwe::U64(self.acc.allocate_lwe_bootstrap_result(side_resources))
    }
}

impl<C: Container<Element = u64>> LweClassicFftBootstrap<DynLwe, DynLwe, LookupTable<C>>
    for ServerKey
{
    type SideResources = ();

    fn lwe_classic_fft_pbs(
        &self,
        input: &DynLwe,
        output: &mut DynLwe,
        accumulator: &LookupTable<C>,
        side_resources: &mut Self::SideResources,
    ) {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk,
                        // Only the PBS is executed here, drift technique is managed separately
                        modulus_switch_noise_reduction_key: _,
                    } => match (input, output) {
                        (DynLwe::U64(input), DynLwe::U64(output)) => {
                            bsk.lwe_classic_fft_pbs(input, output, &accumulator.acc, side_resources)
                        }
                        _ => {
                            panic!("AtomicPatternServerKey::Standard only supports DynLwe::U64")
                        }
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support classic PBS")
                    }
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk,
                        // Only the PBS is executed here, drift technique is managed separately
                        modulus_switch_noise_reduction_key: _,
                    } => match (input, output) {
                        (DynLwe::U32(input), DynLwe::U64(output)) => {
                            bsk.lwe_classic_fft_pbs(input, output, &accumulator.acc, side_resources)
                        }
                        _ => {
                            panic!(
                                "AtomicPatternServerKey::KeySwitch32 \
                                only supports DynLwe::U32 input and DynLwe::U64 output"
                            )
                        }
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support classic PBS")
                    }
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl NoiseSquashingKey {
    pub fn noise_simulation_modulus_switch_config(&self) -> NoiseSimulationModulusSwitchConfig {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => match &standard_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => modulus_switch_noise_reduction_key.into(),
                Shortint128BootstrappingKey::MultiBit { .. } => {
                    panic!("MultiBit ServerKey does not support the drift technique")
                }
            },
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => match &ks32_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => modulus_switch_noise_reduction_key.into(),
                Shortint128BootstrappingKey::MultiBit { .. } => {
                    panic!("MultiBit ServerKey does not support the drift technique")
                }
            },
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => standard_atomic_pattern_noise_squashing_key
                .bootstrapping_key()
                .polynomial_size(),
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => ks32_atomic_pattern_noise_squashing_key
                .bootstrapping_key()
                .polynomial_size(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => standard_atomic_pattern_noise_squashing_key
                .bootstrapping_key()
                .glwe_size(),
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => ks32_atomic_pattern_noise_squashing_key
                .bootstrapping_key()
                .glwe_size(),
        }
    }

    pub fn br_input_modulus_log(&self) -> CiphertextModulusLog {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => standard_atomic_pattern_noise_squashing_key
                .bootstrapping_key()
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => ks32_atomic_pattern_noise_squashing_key
                .bootstrapping_key()
                .polynomial_size()
                .to_blind_rotation_input_modulus_log(),
        }
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for NoiseSquashingKey {
    type AfterDriftOutput = DynLwe;
    type AfterMsOutput = DynLwe;
    type SideResources = ();

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let nsk = StandardNoiseSquashingKeyView::try_from(self.as_view())
            .expect("Noise tests only support standard atomic pattern");

        match nsk.bootstrapping_key() {
            Shortint128BootstrappingKey::Classic {
                bsk: _,
                modulus_switch_noise_reduction_key,
            } => match modulus_switch_noise_reduction_key {
                ModulusSwitchConfiguration::Standard => panic!(
                    "ModulusSwitchConfiguration::Standard does not support the drift technique"
                ),
                ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                    modulus_switch_noise_reduction_key,
                ) => {
                    let (after_drift, after_ms) = modulus_switch_noise_reduction_key
                        .allocate_drift_technique_standard_mod_switch_result(side_resources);

                    (DynLwe::U64(after_drift), DynLwe::U64(after_ms))
                }
                ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                    "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                    does not support the drift technique"
                ),
            },
            Shortint128BootstrappingKey::MultiBit { .. } => {
                panic!("MultiBit ServerKey does support the drift technique")
            }
        }
    }
}

impl DriftTechniqueStandardModSwitch<DynLwe, DynLwe, DynLwe> for NoiseSquashingKey {
    type SideResources = ();

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &DynLwe,
        after_drift_technique: &mut DynLwe,
        after_mod_switch: &mut DynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => match standard_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => match modulus_switch_noise_reduction_key {
                    ModulusSwitchConfiguration::Standard => panic!(
                        "ModulusSwitchConfiguration::Standard \
                            does not support the drift technique"
                    ),
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    ) => match (input, after_drift_technique, after_mod_switch) {
                        (
                            DynLwe::U64(input),
                            DynLwe::U64(after_drift_technique),
                            DynLwe::U64(after_mod_switch),
                        ) => {
                            modulus_switch_noise_reduction_key
                                .drift_technique_and_standard_mod_switch(
                                    output_modulus_log,
                                    input,
                                    after_drift_technique,
                                    after_mod_switch,
                                    side_resources,
                                );
                        }
                        _ => {
                            panic!("AtomicPatternServerKey::Standard only supports DynLwe::U64")
                        }
                    },
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                        "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                            does not support the drift technique"
                    ),
                },
                Shortint128BootstrappingKey::MultiBit { .. } => {
                    panic!("MultiBit ServerKey does support the drift technique")
                }
            },
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => match ks32_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => match modulus_switch_noise_reduction_key {
                    ModulusSwitchConfiguration::Standard => panic!(
                        "ModulusSwitchConfiguration::Standard \
                            does not support the drift technique"
                    ),
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    ) => match (input, after_drift_technique, after_mod_switch) {
                        (
                            DynLwe::U32(input),
                            DynLwe::U32(after_drift_technique),
                            DynLwe::U32(after_mod_switch),
                        ) => {
                            modulus_switch_noise_reduction_key
                                .drift_technique_and_standard_mod_switch(
                                    output_modulus_log,
                                    input,
                                    after_drift_technique,
                                    after_mod_switch,
                                    side_resources,
                                );
                        }
                        _ => {
                            panic!(
                                "AtomicPatternNoiseSquashingKey::KeySwitch32 \
                                only supports DynLwe::U32"
                            )
                        }
                    },
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction => panic!(
                        "ModulusSwitchConfiguration::CenteredMeanNoiseReduction \
                            does not support the drift technique"
                    ),
                },
                Shortint128BootstrappingKey::MultiBit { .. } => {
                    panic!("MultiBit ServerKey does support the drift technique")
                }
            },
        }
    }
}

impl<OutputCont, AccCont>
    LweClassicFft128Bootstrap<DynLwe, LweCiphertext<OutputCont>, GlweCiphertext<AccCont>>
    for NoiseSquashingKey
where
    OutputCont: ContainerMut<Element = u128>,
    AccCont: Container<Element = u128>,
{
    type SideResources = ();

    fn lwe_classic_fft_128_pbs(
        &self,
        input: &DynLwe,
        output: &mut LweCiphertext<OutputCont>,
        accumulator: &GlweCiphertext<AccCont>,
        side_resources: &mut Self::SideResources,
    ) {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(std_nsk) => {
                match std_nsk.bootstrapping_key() {
                    Shortint128BootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: _,
                    } => match input {
                        DynLwe::U64(input) => {
                            bsk.lwe_classic_fft_128_pbs(input, output, accumulator, side_resources)
                        }
                        _ => panic!(
                            "AtomicPatternNoiseSquashingKey::Standard \
                            only supports DynLwe::U64 input"
                        ),
                    },
                    Shortint128BootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support classic PBS")
                    }
                }
            }
            AtomicPatternNoiseSquashingKey::KeySwitch32(ks32_nsk) => {
                match ks32_nsk.bootstrapping_key() {
                    Shortint128BootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: _,
                    } => match input {
                        DynLwe::U32(input) => {
                            bsk.lwe_classic_fft_128_pbs(input, output, accumulator, side_resources)
                        }
                        _ => panic!(
                            "AtomicPatternNoiseSquashingKey::KeySwitch32 \
                            only supports DynLwe::U32 input"
                        ),
                    },
                    Shortint128BootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does support classic PBS")
                    }
                }
            }
        }
    }
}

impl AllocateLwePackingKeyswitchResult for NoiseSquashingCompressionKey {
    type Output = GlweCiphertextOwned<u128>;
    type SideResources = ();

    fn allocate_lwe_packing_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        self.packing_key_switching_key()
            .allocate_lwe_packing_keyswitch_result(side_resources)
    }
}

impl<'a, InputCont, OutputCont>
    LwePackingKeyswitch<[&'a LweCiphertext<InputCont>], GlweCiphertext<OutputCont>>
    for NoiseSquashingCompressionKey
where
    InputCont: Container<Element = u128>,
    OutputCont: ContainerMut<Element = u128>,
{
    type SideResources = ();

    fn keyswitch_lwes_and_pack_in_glwe(
        &self,
        input: &[&'a LweCiphertext<InputCont>],
        output: &mut GlweCiphertext<OutputCont>,
        side_resources: &mut Self::SideResources,
    ) {
        self.packing_key_switching_key()
            .keyswitch_lwes_and_pack_in_glwe(input, output, side_resources);
    }
}

impl NoiseSimulationLwe {
    pub fn encrypt(key: &ClientKey, _msg: u64) -> Self {
        let (encryption_key, encryption_noise_distribution) = key.encryption_key_and_noise();
        let enc_var = match encryption_noise_distribution {
            DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
            DynamicDistribution::TUniform(tuniform) => {
                tuniform.variance(key.parameters().ciphertext_modulus().raw_modulus_float())
            }
        };

        Self::new(
            encryption_key.lwe_dimension(),
            enc_var,
            NoiseSimulationModulus::from_ciphertext_modulus(key.parameters().ciphertext_modulus()),
        )
    }
}

impl NoiseSimulationLweKeyswitchKey {
    // We can't really build a key from an already generated key as we need to know what the noise
    // distribution is.
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Self {
        // KeySwitch from big key to small key
        Self::new(
            params
                .glwe_dimension()
                .to_equivalent_lwe_dimension(params.polynomial_size()),
            params.lwe_dimension(),
            params.ks_base_log(),
            params.ks_level(),
            params.lwe_noise_distribution(),
            match params {
                AtomicPatternParameters::Standard(pbsparameters) => {
                    NoiseSimulationModulus::from_ciphertext_modulus(
                        pbsparameters.ciphertext_modulus(),
                    )
                }
                AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                    NoiseSimulationModulus::from_ciphertext_modulus(
                        key_switch32_pbsparameters.post_keyswitch_ciphertext_modulus(),
                    )
                }
            },
        )
    }
}

#[derive(Clone, Copy)]
pub struct NoiseSimulationDriftTechniqueKey {
    lwe_dimension: LweDimension,
    noise_distribution: DynamicDistribution<u64>,
    modulus: NoiseSimulationModulus,
}

impl NoiseSimulationDriftTechniqueKey {
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Option<Self> {
        match params {
            AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
                PBSParameters::PBS(classic_pbsparameters) => {
                    match classic_pbsparameters.modulus_switch_noise_reduction_params {
                        ModulusSwitchType::Standard => None,
                        ModulusSwitchType::DriftTechniqueNoiseReduction(_) => Some(Self {
                            lwe_dimension: classic_pbsparameters.lwe_dimension,
                            noise_distribution: classic_pbsparameters.lwe_noise_distribution,
                            modulus: NoiseSimulationModulus::from_ciphertext_modulus(
                                classic_pbsparameters.ciphertext_modulus,
                            ),
                        }),
                        ModulusSwitchType::CenteredMeanNoiseReduction => None,
                    }
                }
                PBSParameters::MultiBitPBS(_) => None,
            },
            AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                match &key_switch32_pbsparameters.modulus_switch_noise_reduction_params {
                    ModulusSwitchType::Standard => None,
                    ModulusSwitchType::DriftTechniqueNoiseReduction(_) => Some(Self {
                        lwe_dimension: key_switch32_pbsparameters.lwe_dimension,
                        noise_distribution: key_switch32_pbsparameters
                            .lwe_noise_distribution
                            .to_u64_distribution(),
                        modulus: NoiseSimulationModulus::from_ciphertext_modulus(
                            key_switch32_pbsparameters.post_keyswitch_ciphertext_modulus,
                        ),
                    }),
                    ModulusSwitchType::CenteredMeanNoiseReduction => None,
                }
            }
        }
    }

    pub fn matches_actual_drift_key<Scalar: UnsignedInteger>(
        &self,
        drift_key: &ModulusSwitchNoiseReductionKey<Scalar>,
    ) -> bool {
        let Self {
            lwe_dimension,
            noise_distribution: _,
            modulus,
        } = *self;

        let drift_key_lwe_dimension = drift_key.modulus_switch_zeros.lwe_size().to_lwe_dimension();
        let drift_key_modulus = NoiseSimulationModulus::from_ciphertext_modulus(
            drift_key.modulus_switch_zeros.ciphertext_modulus(),
        );

        lwe_dimension == drift_key_lwe_dimension && modulus == drift_key_modulus
    }
}

impl AllocateDriftTechniqueStandardModSwitchResult for NoiseSimulationDriftTechniqueKey {
    type AfterDriftOutput = NoiseSimulationLwe;
    type AfterMsOutput = NoiseSimulationLwe;
    type SideResources = ();

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput) {
        let after_drift =
            NoiseSimulationLwe::new(self.lwe_dimension, Variance(f64::NAN), self.modulus);
        let after_ms = after_drift.allocate_standard_mod_switch_result(side_resources);
        (after_drift, after_ms)
    }
}

impl DriftTechniqueStandardModSwitch<NoiseSimulationLwe, NoiseSimulationLwe, NoiseSimulationLwe>
    for NoiseSimulationDriftTechniqueKey
{
    type SideResources = ();

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &NoiseSimulationLwe,
        after_drift_technique: &mut NoiseSimulationLwe,
        after_mod_switch: &mut NoiseSimulationLwe,
        _side_resources: &mut Self::SideResources,
    ) {
        assert_eq!(self.modulus, input.modulus());

        let simulation_after_mod_switch_modulus =
            NoiseSimulationModulus::from_ciphertext_modulus_log(output_modulus_log);

        let drift_technique_added_var = match self.noise_distribution {
            DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
            DynamicDistribution::TUniform(tuniform) => tuniform.variance(self.modulus.as_f64()),
        };

        *after_drift_technique = NoiseSimulationLwe::new(
            input.lwe_dimension(),
            Variance(input.variance().0 + drift_technique_added_var.0),
            input.modulus(),
        );

        let before_ms_modulus_f64 = after_drift_technique.modulus().as_f64();
        let after_ms_modulus_f64 = simulation_after_mod_switch_modulus.as_f64();

        assert!(after_ms_modulus_f64 < before_ms_modulus_f64);

        *after_mod_switch = NoiseSimulationLwe::new(
            after_drift_technique.lwe_dimension(),
            Variance(
                after_drift_technique.variance().0
                    + generalized_modulus_switch_additive_variance(
                        after_drift_technique.lwe_dimension(),
                        before_ms_modulus_f64,
                        after_ms_modulus_f64,
                    )
                    .0,
            ),
            after_drift_technique.modulus(),
        );
    }
}

impl NoiseSimulationLweFourier128Bsk {
    // We can't really build a key from an already generated key as we need to know what the noise
    // distribution is.
    pub fn new_from_parameters(
        params: AtomicPatternParameters,
        noise_squashing_params: NoiseSquashingParameters,
    ) -> Self {
        Self::new(
            params.lwe_dimension(),
            noise_squashing_params.glwe_dimension().to_glwe_size(),
            noise_squashing_params.polynomial_size(),
            noise_squashing_params.decomp_base_log(),
            noise_squashing_params.decomp_level_count(),
            noise_squashing_params.glwe_noise_distribution(),
            NoiseSimulationModulus::from_ciphertext_modulus(
                noise_squashing_params.ciphertext_modulus(),
            ),
        )
    }
}

impl NoiseSimulationLweFourierBsk {
    // We can't really build a key from an already generated key as we need to know what the noise
    // distribution is.
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Self {
        Self::new(
            params.lwe_dimension(),
            params.glwe_dimension().to_glwe_size(),
            params.polynomial_size(),
            params.pbs_base_log(),
            params.pbs_level(),
            params.glwe_noise_distribution(),
            NoiseSimulationModulus::from_ciphertext_modulus(params.ciphertext_modulus()),
        )
    }
}

impl NoiseSimulationLwePackingKeyswitchKey {
    pub fn new_from_params(
        noise_squashing_params: NoiseSquashingParameters,
        noise_squashing_compression_params: NoiseSquashingCompressionParameters,
    ) -> Self {
        let squashing_lwe_dim = noise_squashing_params
            .glwe_dimension()
            .to_equivalent_lwe_dimension(noise_squashing_params.polynomial_size());

        Self::new(
            squashing_lwe_dim,
            noise_squashing_compression_params.packing_ks_base_log,
            noise_squashing_compression_params.packing_ks_level,
            noise_squashing_compression_params
                .packing_ks_glwe_dimension
                .to_glwe_size(),
            noise_squashing_compression_params.packing_ks_polynomial_size,
            noise_squashing_compression_params.packing_ks_key_noise_distribution,
            NoiseSimulationModulus::from_ciphertext_modulus(
                noise_squashing_compression_params.ciphertext_modulus,
            ),
        )
    }
}

impl NoiseSimulationLweKeyswitchKey {
    pub fn matches_actual_shortint_server_key(&self, server_key: &ServerKey) -> bool {
        match &server_key.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                self.matches_actual_ksk(&standard_atomic_pattern_server_key.key_switching_key)
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                self.matches_actual_ksk(&ks32_atomic_pattern_server_key.key_switching_key)
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl NoiseSimulationDriftTechniqueKey {
    pub fn matches_actual_shortint_server_key(&self, server_key: &ServerKey) -> bool {
        match &server_key.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => match modulus_switch_noise_reduction_key {
                        ModulusSwitchConfiguration::Standard => false,
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ) => self.matches_actual_drift_key(modulus_switch_noise_reduction_key),
                        ModulusSwitchConfiguration::CenteredMeanNoiseReduction => false,
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => false,
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => match modulus_switch_noise_reduction_key {
                        ModulusSwitchConfiguration::Standard => false,
                        ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                            modulus_switch_noise_reduction_key,
                        ) => self.matches_actual_drift_key(modulus_switch_noise_reduction_key),
                        ModulusSwitchConfiguration::CenteredMeanNoiseReduction => false,
                    },
                    ShortintBootstrappingKey::MultiBit { .. } => false,
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }

    pub fn matches_actual_shortint_noise_squashing_key(
        &self,
        noise_squashing_key: &NoiseSquashingKey,
    ) -> bool {
        match noise_squashing_key.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => match standard_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => match modulus_switch_noise_reduction_key {
                    ModulusSwitchConfiguration::Standard => false,
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    ) => self.matches_actual_drift_key(modulus_switch_noise_reduction_key),
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction => false,
                },
                Shortint128BootstrappingKey::MultiBit { .. } => false,
            },
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => match ks32_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => match modulus_switch_noise_reduction_key {
                    ModulusSwitchConfiguration::Standard => false,
                    ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(
                        modulus_switch_noise_reduction_key,
                    ) => self.matches_actual_drift_key(modulus_switch_noise_reduction_key),
                    ModulusSwitchConfiguration::CenteredMeanNoiseReduction => false,
                },
                Shortint128BootstrappingKey::MultiBit { .. } => false,
            },
        }
    }
}

impl NoiseSimulationLweFourierBsk {
    pub fn matches_actual_shortint_server_key(&self, server_key: &ServerKey) -> bool {
        match &server_key.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: _,
                    } => self.matches_actual_bsk(bsk),
                    ShortintBootstrappingKey::MultiBit { .. } => false,
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: _,
                    } => self.matches_actual_bsk(bsk),
                    ShortintBootstrappingKey::MultiBit { .. } => false,
                }
            }
            AtomicPatternServerKey::Dynamic(_) => {
                panic!("Unsupported Dynamic Atomic Pattern for noise simulation")
            }
        }
    }
}

impl NoiseSimulationLweFourier128Bsk {
    pub fn matches_actual_shortint_noise_squashing_key(
        &self,
        noise_squashing_key: &NoiseSquashingKey,
    ) -> bool {
        match noise_squashing_key.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => match standard_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key: _,
                } => self.matches_actual_bsk(bsk),
                Shortint128BootstrappingKey::MultiBit { .. } => false,
            },
            AtomicPatternNoiseSquashingKey::KeySwitch32(
                ks32_atomic_pattern_noise_squashing_key,
            ) => match ks32_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk,
                    modulus_switch_noise_reduction_key: _,
                } => self.matches_actual_bsk(bsk),
                Shortint128BootstrappingKey::MultiBit { .. } => false,
            },
        }
    }
}
