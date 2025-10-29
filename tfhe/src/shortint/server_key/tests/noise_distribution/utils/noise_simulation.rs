pub use crate::core_crypto::commons::noise_formulas::noise_simulation::*;

use crate::core_crypto::algorithms::glwe_encryption::encrypt_glwe_ciphertext;
use crate::core_crypto::algorithms::test::noise_distribution::lwe_encryption_noise::lwe_compact_public_key_encryption_expected_variance;
use crate::core_crypto::commons::dispersion::{DispersionParameter, Variance};
use crate::core_crypto::commons::math::random::Gaussian;
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
    PlaintextCount, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut};
use crate::core_crypto::entities::{
    GlweCiphertext, GlweCiphertextOwned, LweCiphertext, LweCiphertextOwned, LweCiphertextView,
    PlaintextList,
};
use crate::shortint::client_key::atomic_pattern::AtomicPatternClientKey;
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::key_switching_key::{
    KeySwitchingKeyDestinationAtomicPattern, KeySwitchingKeyView,
};
use crate::shortint::list_compression::{
    CompressionPrivateKeys, DecompressionKey, NoiseSquashingCompressionKey,
};
use crate::shortint::noise_squashing::atomic_pattern::AtomicPatternNoiseSquashingKey;
use crate::shortint::noise_squashing::{
    NoiseSquashingKey, Shortint128BootstrappingKey, StandardNoiseSquashingKeyView,
};
use crate::shortint::parameters::{
    AtomicPatternParameters, CarryModulus, CompactPublicKeyEncryptionParameters,
    CompressionParameters, ModulusSwitchType, NoiseSquashingCompressionParameters,
    NoiseSquashingParameters, PBSParameters, ShortintKeySwitchingParameters,
};
use crate::shortint::public_key::CompactPublicKey;
use crate::shortint::server_key::tests::noise_distribution::utils::encrypt_new_noiseless_lwe;
use crate::shortint::server_key::{
    AtomicPatternServerKey, LookupTable, ModulusSwitchConfiguration,
    ModulusSwitchNoiseReductionKey, ServerKey, ShortintBootstrappingKey,
};
use crate::shortint::{EncryptionKeyChoice, PaddingBit, ShortintEncoding};

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
            (Self::U32(lhs), Self::U32(rhs)) => {
                Self::U32(lhs.lwe_uncorrelated_add(rhs, side_resources))
            }
            (Self::U64(lhs), Self::U64(rhs)) => {
                Self::U64(lhs.lwe_uncorrelated_add(rhs, side_resources))
            }
            (Self::U128(lhs), Self::U128(rhs)) => {
                Self::U128(lhs.lwe_uncorrelated_add(rhs, side_resources))
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
            (Self::U32(lhs), Self::U32(rhs)) => {
                Self::U32(lhs.lwe_uncorrelated_sub(rhs, side_resources))
            }
            (Self::U64(lhs), Self::U64(rhs)) => {
                Self::U64(lhs.lwe_uncorrelated_sub(rhs, side_resources))
            }
            (Self::U128(lhs), Self::U128(rhs)) => {
                Self::U128(lhs.lwe_uncorrelated_sub(rhs, side_resources))
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

impl CompressionPrivateKeys {
    // Decompression input == an LWE that would result from a compression, i.e. under the post
    // packing ks secret key
    pub fn encrypt_noiseless_decompression_input_dyn_lwe(
        &self,
        cks: &ClientKey,
        msg: u64,
        engine: &mut ShortintEngine,
    ) -> DynLwe {
        // cks used to have the proper encoding used for the computations
        let compute_params = cks.parameters();
        let encoding = ShortintEncoding {
            ciphertext_modulus: compute_params.ciphertext_modulus(),
            message_modulus: compute_params.message_modulus(),
            // Adapt to the compression which has no carry bits
            carry_modulus: CarryModulus(1),
            padding_bit: PaddingBit::Yes,
        };

        DynLwe::U64(encrypt_new_noiseless_lwe(
            &self.post_packing_ks_key.as_lwe_secret_key(),
            CiphertextModulus::try_new_power_of_2(self.params.storage_log_modulus().0).unwrap(),
            msg,
            &encoding,
            &mut engine.encryption_generator,
        ))
    }

    pub fn encrypt_noiseless_glwe(
        &self,
        cks: &ClientKey,
        msg: u64,
        engine: &mut ShortintEngine,
    ) -> GlweCiphertextOwned<u64> {
        assert_eq!(msg, 0, "todo: update this to manage other stuff");
        assert!(cks.parameters().ciphertext_modulus().is_native_modulus());

        let plaintext_list = PlaintextList::new(0, PlaintextCount(self.params.lwe_per_glwe().0));

        let ct_modulus =
            CiphertextModulus::try_new_power_of_2(self.params.storage_log_modulus().0).unwrap();

        let mut out = GlweCiphertext::new(
            0u64,
            self.post_packing_ks_key.glwe_dimension().to_glwe_size(),
            self.post_packing_ks_key.polynomial_size(),
            ct_modulus,
        );

        let noiseless_distribution = Gaussian::from_dispersion_parameter(Variance(0.0), 0.0);

        encrypt_glwe_ciphertext(
            &self.post_packing_ks_key,
            &mut out,
            &plaintext_list,
            noiseless_distribution,
            &mut engine.encryption_generator,
        );

        let cont = out.into_container();

        // Set the modulus as native to be compatible with operations afterwards
        // power of two encoding is compatible with native modulus
        GlweCiphertextOwned::from_container(
            cont,
            self.post_packing_ks_key.polynomial_size(),
            cks.parameters().ciphertext_modulus(),
        )
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
pub enum NoiseSimulationModulusSwitchConfig<DriftKey> {
    Standard,
    DriftTechniqueNoiseReduction(DriftKey),
    CenteredMeanNoiseReduction,
}

impl NoiseSimulationModulusSwitchConfig<NoiseSimulationDriftTechniqueKey> {
    pub fn new_from_atomic_pattern_parameters(params: AtomicPatternParameters) -> Self {
        let drift_key =
            NoiseSimulationDriftTechniqueKey::new_from_atomic_pattern_parameters(params);

        match params {
            AtomicPatternParameters::Standard(pbsparameters) => match pbsparameters {
                PBSParameters::PBS(classic_pbsparameters) => {
                    match classic_pbsparameters.modulus_switch_noise_reduction_params {
                        ModulusSwitchType::Standard => Self::Standard,
                        ModulusSwitchType::DriftTechniqueNoiseReduction(_) => {
                            Self::DriftTechniqueNoiseReduction(
                                drift_key.expect("Invalid drift key configuration"),
                            )
                        }
                        ModulusSwitchType::CenteredMeanNoiseReduction => {
                            Self::CenteredMeanNoiseReduction
                        }
                    }
                }
                PBSParameters::MultiBitPBS(_) => {
                    panic!(
                        "Unsupported ShortintBootstrappingKey::MultiBit \
                        for NoiseSimulationModulusSwitchConfig"
                    )
                }
            },
            AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                match &key_switch32_pbsparameters.modulus_switch_noise_reduction_params {
                    ModulusSwitchType::Standard => Self::Standard,
                    ModulusSwitchType::DriftTechniqueNoiseReduction(_) => {
                        Self::DriftTechniqueNoiseReduction(
                            drift_key.expect("Invalid drift key configuration"),
                        )
                    }
                    ModulusSwitchType::CenteredMeanNoiseReduction => {
                        Self::CenteredMeanNoiseReduction
                    }
                }
            }
        }
    }

    pub fn matches_shortint_server_key_modulus_switch_config(
        &self,
        shortint_config: NoiseSimulationModulusSwitchConfig<&ServerKey>,
    ) -> bool {
        match (self, shortint_config) {
            (Self::Standard, NoiseSimulationModulusSwitchConfig::Standard) => true,
            (
                Self::DriftTechniqueNoiseReduction(noise_sim),
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction(sks),
            ) => noise_sim.matches_actual_shortint_server_key(sks),
            (
                Self::CenteredMeanNoiseReduction,
                NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction,
            ) => true,
            _ => false,
        }
    }

    pub fn matches_shortint_noise_squashing_modulus_switch_config(
        &self,
        shortint_config: NoiseSimulationModulusSwitchConfig<&NoiseSquashingKey>,
    ) -> bool {
        match (self, shortint_config) {
            (Self::Standard, NoiseSimulationModulusSwitchConfig::Standard) => true,
            (
                Self::DriftTechniqueNoiseReduction(noise_sim),
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction(sns),
            ) => noise_sim.matches_actual_shortint_noise_squashing_key(sns),
            (
                Self::CenteredMeanNoiseReduction,
                NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction,
            ) => true,
            _ => false,
        }
    }
}

impl<DriftKey> NoiseSimulationModulusSwitchConfig<DriftKey> {
    fn new_from_config_and_key<Scalar: UnsignedInteger>(
        config: &ModulusSwitchConfiguration<Scalar>,
        key: DriftKey,
    ) -> Self {
        match config {
            ModulusSwitchConfiguration::Standard => Self::Standard,
            ModulusSwitchConfiguration::DriftTechniqueNoiseReduction(_) => {
                Self::DriftTechniqueNoiseReduction(key)
            }
            ModulusSwitchConfiguration::CenteredMeanNoiseReduction => {
                Self::CenteredMeanNoiseReduction
            }
        }
    }
}

impl<DriftKey> NoiseSimulationModulusSwitchConfig<DriftKey> {
    pub fn as_ref(&self) -> NoiseSimulationModulusSwitchConfig<&DriftKey> {
        match self {
            Self::Standard => NoiseSimulationModulusSwitchConfig::Standard,
            Self::DriftTechniqueNoiseReduction(key) => {
                NoiseSimulationModulusSwitchConfig::DriftTechniqueNoiseReduction(key)
            }
            Self::CenteredMeanNoiseReduction => {
                NoiseSimulationModulusSwitchConfig::CenteredMeanNoiseReduction
            }
        }
    }

    pub fn expected_average_after_ms(self, polynomial_size: PolynomialSize) -> f64 {
        match self {
            Self::Standard => 0.0f64,
            Self::DriftTechniqueNoiseReduction(_) => 0.0f64,
            Self::CenteredMeanNoiseReduction => {
                // Half case subtracted before entering the blind rotate
                -1.0f64 / (4.0 * polynomial_size.0 as f64)
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

    pub fn noise_simulation_modulus_switch_config(
        &self,
    ) -> NoiseSimulationModulusSwitchConfig<&Self> {
        match &self.atomic_pattern {
            AtomicPatternServerKey::Standard(standard_atomic_pattern_server_key) => {
                match &standard_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => NoiseSimulationModulusSwitchConfig::new_from_config_and_key(
                        modulus_switch_noise_reduction_key,
                        self,
                    ),
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does not support the drift technique")
                    }
                }
            }
            AtomicPatternServerKey::KeySwitch32(ks32_atomic_pattern_server_key) => {
                match &ks32_atomic_pattern_server_key.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: _,
                        modulus_switch_noise_reduction_key,
                    } => NoiseSimulationModulusSwitchConfig::new_from_config_and_key(
                        modulus_switch_noise_reduction_key,
                        self,
                    ),
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        panic!("MultiBit ServerKey does not support the drift technique")
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
    pub fn noise_simulation_modulus_switch_config(
        &self,
    ) -> NoiseSimulationModulusSwitchConfig<&Self> {
        match self.atomic_pattern() {
            AtomicPatternNoiseSquashingKey::Standard(
                standard_atomic_pattern_noise_squashing_key,
            ) => match &standard_atomic_pattern_noise_squashing_key.bootstrapping_key() {
                Shortint128BootstrappingKey::Classic {
                    bsk: _,
                    modulus_switch_noise_reduction_key,
                } => NoiseSimulationModulusSwitchConfig::new_from_config_and_key(
                    modulus_switch_noise_reduction_key,
                    self,
                ),
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
                } => NoiseSimulationModulusSwitchConfig::new_from_config_and_key(
                    modulus_switch_noise_reduction_key,
                    self,
                ),
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

impl AllocateLweKeyswitchResult for KeySwitchingKeyView<'_> {
    type Output = DynLwe;
    type SideResources = ();

    fn allocate_lwe_keyswitch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        match (
            self.key_switching_key_material.destination_atomic_pattern,
            self.key_switching_key_material.destination_key,
        ) {
            (
                KeySwitchingKeyDestinationAtomicPattern::Standard,
                EncryptionKeyChoice::Big | EncryptionKeyChoice::Small,
            ) => DynLwe::U64(
                self.key_switching_key_material
                    .key_switching_key
                    .allocate_lwe_keyswitch_result(side_resources),
            ),
            (KeySwitchingKeyDestinationAtomicPattern::KeySwitch32, EncryptionKeyChoice::Big) => {
                DynLwe::U64(
                    self.key_switching_key_material
                        .key_switching_key
                        .allocate_lwe_keyswitch_result(side_resources),
                )
            }
            (KeySwitchingKeyDestinationAtomicPattern::KeySwitch32, EncryptionKeyChoice::Small) => {
                DynLwe::U32(LweCiphertext::new(
                    0,
                    self.key_switching_key_material
                        .key_switching_key
                        .output_lwe_size(),
                    self.key_switching_key_material
                        .key_switching_key
                        .ciphertext_modulus()
                        .try_to()
                        .unwrap(),
                ))
            }
        }
    }
}

impl LweKeyswitch<DynLwe, DynLwe> for KeySwitchingKeyView<'_> {
    type SideResources = ();

    fn lwe_keyswitch(
        &self,
        input: &DynLwe,
        output: &mut DynLwe,
        side_resources: &mut Self::SideResources,
    ) {
        match (
            input,
            output,
            self.key_switching_key_material.destination_atomic_pattern,
        ) {
            (
                DynLwe::U64(input),
                DynLwe::U32(output),
                KeySwitchingKeyDestinationAtomicPattern::KeySwitch32,
            ) => {
                let mut tmp = LweCiphertext::new(
                    0u64,
                    output.lwe_size(),
                    self.key_switching_key_material
                        .key_switching_key
                        .ciphertext_modulus(),
                );
                self.key_switching_key_material
                    .key_switching_key
                    .lwe_keyswitch(input, &mut tmp, side_resources);

                // Manage encoding
                output
                    .as_mut()
                    .iter_mut()
                    .zip(tmp.as_ref().iter())
                    .for_each(|(dst, src)| *dst = (*src >> 32) as u32);
            }
            (
                DynLwe::U64(input),
                DynLwe::U64(output),
                KeySwitchingKeyDestinationAtomicPattern::Standard
                | KeySwitchingKeyDestinationAtomicPattern::KeySwitch32,
            ) => self
                .key_switching_key_material
                .key_switching_key
                .lwe_keyswitch(input, output, side_resources),
            _ => panic!("Unsupported configuration for KeySwitchingKeyView in noise simulation"),
        }
    }
}

impl LweClassicFftBootstrap<DynLwe, DynLwe, LookupTable<Vec<u64>>> for DecompressionKey {
    type SideResources = ();

    fn lwe_classic_fft_pbs(
        &self,
        input: &DynLwe,
        output: &mut DynLwe,
        accumulator: &LookupTable<Vec<u64>>,
        side_resources: &mut Self::SideResources,
    ) {
        match &self.bsk {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: _,
            } => match (input, output) {
                (DynLwe::U64(input), DynLwe::U64(output)) => {
                    bsk.lwe_classic_fft_pbs(input, output, &accumulator.acc, side_resources)
                }
                _ => panic!(
                    "DecompressionKey only supports DynLwe::U64 for noise
        simulation"
                ),
            },
            ShortintBootstrappingKey::MultiBit { .. } => {
                panic!("Tried to compute a classic PBS with a multi bit DecompressionKey")
            }
        }
    }
}

// ==== Below NoiseSimulation extensions

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

    pub fn encrypt_with_cpk(cpk: &CompactPublicKey) -> Self {
        let encryption_lwe_dimension = cpk.key.lwe_dimension();
        let noise_var = match cpk.parameters().encryption_noise_distribution {
            DynamicDistribution::Gaussian(gaussian) => gaussian.standard_dev().get_variance(),
            DynamicDistribution::TUniform(tuniform) => {
                tuniform.variance(cpk.parameters().ciphertext_modulus.raw_modulus_float())
            }
        };

        let cpk_encryption_noise_var = lwe_compact_public_key_encryption_expected_variance(
            noise_var,
            encryption_lwe_dimension,
        );

        Self::new(
            encryption_lwe_dimension,
            cpk_encryption_noise_var,
            NoiseSimulationModulus::from_ciphertext_modulus(cpk.parameters().ciphertext_modulus),
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

    pub fn new_from_cpk_params(
        cpk_params: CompactPublicKeyEncryptionParameters,
        ksk_params: ShortintKeySwitchingParameters,
        compute_params: AtomicPatternParameters,
    ) -> Self {
        let (output_lwe_dimension, noise_distribution, ciphertext_modulus) =
            match ksk_params.destination_key {
                EncryptionKeyChoice::Big => (
                    compute_params
                        .glwe_dimension()
                        .to_equivalent_lwe_dimension(compute_params.polynomial_size()),
                    compute_params.glwe_noise_distribution(),
                    compute_params.ciphertext_modulus(),
                ),
                EncryptionKeyChoice::Small => (
                    compute_params.lwe_dimension(),
                    compute_params.lwe_noise_distribution(),
                    match compute_params {
                        AtomicPatternParameters::Standard(pbsparameters) => {
                            pbsparameters.ciphertext_modulus()
                        }
                        AtomicPatternParameters::KeySwitch32(key_switch32_pbsparameters) => {
                            key_switch32_pbsparameters
                                .post_keyswitch_ciphertext_modulus
                                .try_to()
                                .unwrap()
                        }
                    },
                ),
            };

        Self::new(
            cpk_params.encryption_lwe_dimension,
            output_lwe_dimension,
            ksk_params.ks_base_log,
            ksk_params.ks_level,
            noise_distribution,
            NoiseSimulationModulus::from_ciphertext_modulus(ciphertext_modulus),
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

    pub fn new_from_comp_parameters(
        params: AtomicPatternParameters,
        comp_params: CompressionParameters,
    ) -> Self {
        Self::new(
            comp_params
                .packing_ks_glwe_dimension()
                .to_equivalent_lwe_dimension(comp_params.packing_ks_polynomial_size()),
            params.glwe_dimension().to_glwe_size(),
            params.polynomial_size(),
            comp_params.br_base_log(),
            comp_params.br_level(),
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

    pub fn matches_actual_shortint_keyswitching_key(&self, ksk: &KeySwitchingKeyView<'_>) -> bool {
        self.matches_actual_ksk(ksk.key_switching_key_material.key_switching_key)
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

    pub fn matches_actual_shortint_decomp_key(&self, decomp_key: &DecompressionKey) -> bool {
        match &decomp_key.bsk {
            ShortintBootstrappingKey::Classic {
                bsk,
                modulus_switch_noise_reduction_key: _,
            } => self.matches_actual_bsk(bsk),
            ShortintBootstrappingKey::MultiBit { .. } => false,
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
