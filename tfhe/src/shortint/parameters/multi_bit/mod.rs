use crate::core_crypto::commons::math::random::{Deserialize, Serialize};
use crate::core_crypto::entities::{
    LweCiphertextParameters, MsDecompressionType, MultiBitBootstrapKeyConformanceParams,
};
use crate::core_crypto::prelude::{DynamicDistribution, LweBskGroupingFactor};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::{CiphertextConformanceParams, MultiBitPBSParametersVersions};
use crate::shortint::prelude::*;
use crate::shortint::server_key::PBSConformanceParameters;
use crate::shortint::{
    CarryModulus, CiphertextModulus, EncryptionKeyChoice, MaxNoiseLevel, MessageModulus, PBSOrder,
};
use crate::Versionize;

pub mod gaussian;
pub mod tuniform;

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation. This structure contains information to run the so-called multi-bit PBS with improved
/// latency provided enough threads are available on the machine performing the FHE computations
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(MultiBitPBSParametersVersions)]
pub struct MultiBitPBSParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub max_noise_level: MaxNoiseLevel,
    pub log2_p_fail: f64,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
    pub grouping_factor: LweBskGroupingFactor,
    pub deterministic_execution: bool,
}

impl MultiBitPBSParameters {
    pub const fn with_deterministic_execution(self) -> Self {
        Self {
            deterministic_execution: true,
            ..self
        }
    }

    pub const fn with_non_deterministic_execution(self) -> Self {
        Self {
            deterministic_execution: false,
            ..self
        }
    }

    pub fn to_shortint_conformance_param(&self) -> CiphertextConformanceParams {
        let (pbs_order, expected_dim) = match self.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                PBSOrder::KeyswitchBootstrap,
                self.glwe_dimension
                    .to_equivalent_lwe_dimension(self.polynomial_size),
            ),
            EncryptionKeyChoice::Small => (PBSOrder::BootstrapKeyswitch, self.lwe_dimension),
        };

        let message_modulus = self.message_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;
        let carry_modulus = self.carry_modulus;

        let degree = Degree::new(message_modulus.0 - 1);

        let noise_level = NoiseLevel::NOMINAL;

        CiphertextConformanceParams {
            ct_params: LweCiphertextParameters {
                lwe_dim: expected_dim,
                ct_modulus: ciphertext_modulus,
                ms_decompression_method: MsDecompressionType::MultiBitPbs(self.grouping_factor),
            },
            message_modulus,
            carry_modulus,
            pbs_order,
            degree,
            noise_level,
        }
    }
}

impl TryFrom<&PBSConformanceParameters> for MultiBitBootstrapKeyConformanceParams {
    type Error = ();

    fn try_from(value: &PBSConformanceParameters) -> Result<Self, ()> {
        Ok(Self {
            decomp_base_log: value.base_log,
            decomp_level_count: value.level,
            input_lwe_dimension: value.in_lwe_dimension,
            output_glwe_size: value.out_glwe_dimension.to_glwe_size(),
            polynomial_size: value.out_polynomial_size,
            grouping_factor: value.multi_bit.ok_or(())?,
            ciphertext_modulus: value.ciphertext_modulus,
        })
    }
}
