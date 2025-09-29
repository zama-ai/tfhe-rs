use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

pub use crate::core_crypto::commons::parameters::{
    CiphertextModulusLog, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    EncryptionKeyChoice, GlweDimension, LweBskGroupingFactor, LweCiphertextCount, LweDimension,
    NoiseEstimationMeasureBound, PolynomialSize, RSigmaFactor,
};
use crate::core_crypto::prelude::{
    LweCiphertextConformanceParams, LweKeyswitchKeyConformanceParams, MsDecompressionType,
};
use crate::shortint::backward_compatibility::parameters::KeySwitch32PBSParametersVersions;
use crate::shortint::parameters::ModulusSwitchType;

use super::{
    AtomicPatternKind, CarryModulus, CiphertextConformanceParams, CiphertextModulus,
    CiphertextModulus32, Degree, MaxNoiseLevel, MessageModulus, NoiseLevel,
};

/// A set of cryptographic parameters used with the atomic pattern
/// [`KeySwitch32`](crate::shortint::atomic_pattern::AtomicPatternKind::KeySwitch32)
#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(KeySwitch32PBSParametersVersions)]
pub struct KeySwitch32PBSParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u32>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_noise_level: MaxNoiseLevel,
    pub log2_p_fail: f64,
    pub post_keyswitch_ciphertext_modulus: CiphertextModulus32,
    pub ciphertext_modulus: CiphertextModulus,
    pub modulus_switch_noise_reduction_params: ModulusSwitchType,
}

#[allow(clippy::fallible_impl_from)]
impl From<&KeySwitch32PBSParameters> for LweKeyswitchKeyConformanceParams<u32> {
    fn from(value: &KeySwitch32PBSParameters) -> Self {
        Self {
            decomp_base_log: value.ks_base_log(),
            decomp_level_count: value.ks_level(),
            output_lwe_size: value.lwe_dimension().to_lwe_size(),
            input_lwe_dimension: value
                .glwe_dimension()
                .to_equivalent_lwe_dimension(value.polynomial_size()),
            ciphertext_modulus: value.post_keyswitch_ciphertext_modulus(),
        }
    }
}

impl KeySwitch32PBSParameters {
    pub const fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    pub const fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub const fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub const fn lwe_noise_distribution(&self) -> DynamicDistribution<u32> {
        self.lwe_noise_distribution
    }

    pub const fn glwe_noise_distribution(&self) -> DynamicDistribution<u64> {
        self.glwe_noise_distribution
    }

    pub const fn pbs_base_log(&self) -> DecompositionBaseLog {
        self.pbs_base_log
    }

    pub const fn pbs_level(&self) -> DecompositionLevelCount {
        self.pbs_level
    }

    pub const fn ks_base_log(&self) -> DecompositionBaseLog {
        self.ks_base_log
    }

    pub const fn ks_level(&self) -> DecompositionLevelCount {
        self.ks_level
    }

    pub const fn message_modulus(&self) -> MessageModulus {
        self.message_modulus
    }

    pub const fn carry_modulus(&self) -> CarryModulus {
        self.carry_modulus
    }

    pub const fn max_noise_level(&self) -> MaxNoiseLevel {
        self.max_noise_level
    }

    pub const fn post_keyswitch_ciphertext_modulus(&self) -> CiphertextModulus32 {
        self.post_keyswitch_ciphertext_modulus
    }

    pub const fn ciphertext_modulus(&self) -> CiphertextModulus {
        self.ciphertext_modulus
    }

    pub const fn encryption_key_choice(&self) -> EncryptionKeyChoice {
        // The KS32 atomic pattern is only supported with the KsPbs order
        EncryptionKeyChoice::Big
    }

    pub const fn encryption_lwe_dimension(&self) -> LweDimension {
        self.glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    pub const fn log2_p_fail(&self) -> f64 {
        self.log2_p_fail
    }

    pub fn to_shortint_conformance_param(&self) -> CiphertextConformanceParams {
        let expected_dim = self
            .glwe_dimension
            .to_equivalent_lwe_dimension(self.polynomial_size);

        let message_modulus = self.message_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;
        let carry_modulus = self.carry_modulus;

        let degree = Degree::new(message_modulus.0 - 1);

        let noise_level = NoiseLevel::NOMINAL;

        CiphertextConformanceParams {
            ct_params: LweCiphertextConformanceParams {
                lwe_dim: expected_dim,
                ct_modulus: ciphertext_modulus,
                ms_decompression_method: MsDecompressionType::ClassicPbs,
            },
            message_modulus,
            carry_modulus,
            atomic_pattern: AtomicPatternKind::KeySwitch32,
            degree,
            noise_level,
        }
    }

    pub fn ciphertext_modulus_for_key(&self, key_choice: EncryptionKeyChoice) -> CiphertextModulus {
        match key_choice {
            EncryptionKeyChoice::Big => self.ciphertext_modulus,
            // Ok to unwrap because converting a 32b modulus into a 64b one should not fail
            EncryptionKeyChoice::Small => {
                self.post_keyswitch_ciphertext_modulus().try_to().unwrap()
            }
        }
    }
}
