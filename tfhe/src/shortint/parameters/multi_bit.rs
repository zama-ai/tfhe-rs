use crate::core_crypto::entities::{
    LweCiphertextConformanceParams, MsDecompressionType, MultiBitBootstrapKeyConformanceParams,
};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::{
    AtomicPatternKind, CarryModulus, CiphertextConformanceParams, CiphertextModulus,
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice,
    GlweDimension, LweBskGroupingFactor, LweDimension, MaxNoiseLevel, MessageModulus,
    MultiBitPBSParametersVersions, PBSOrder, PolynomialSize,
};
use crate::shortint::server_key::PBSConformanceParams;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

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
        let (atomic_pattern, expected_dim) = match self.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
                self.glwe_dimension
                    .to_equivalent_lwe_dimension(self.polynomial_size),
            ),
            EncryptionKeyChoice::Small => (
                AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch),
                self.lwe_dimension,
            ),
        };

        let message_modulus = self.message_modulus;
        let ciphertext_modulus = self.ciphertext_modulus;
        let carry_modulus = self.carry_modulus;

        let degree = Degree::new(message_modulus.0 - 1);

        let noise_level = NoiseLevel::NOMINAL;

        CiphertextConformanceParams {
            ct_params: LweCiphertextConformanceParams {
                lwe_dim: expected_dim,
                ct_modulus: ciphertext_modulus,
                ms_decompression_method: MsDecompressionType::MultiBitPbs(self.grouping_factor),
            },
            message_modulus,
            carry_modulus,
            atomic_pattern,
            degree,
            noise_level,
        }
    }
}

impl TryFrom<&PBSConformanceParams> for MultiBitBootstrapKeyConformanceParams<u64> {
    type Error = ();

    fn try_from(value: &PBSConformanceParams) -> Result<Self, ()> {
        Ok(Self {
            decomp_base_log: value.base_log,
            decomp_level_count: value.level,
            input_lwe_dimension: value.in_lwe_dimension,
            output_glwe_size: value.out_glwe_dimension.to_glwe_size(),
            polynomial_size: value.out_polynomial_size,
            grouping_factor: match value.pbs_type {
                crate::shortint::server_key::PbsTypeConformanceParams::Classic { .. } => {
                    return Err(());
                }
                crate::shortint::server_key::PbsTypeConformanceParams::MultiBit {
                    lwe_bsk_grouping_factor,
                } => lwe_bsk_grouping_factor,
            },
            ciphertext_modulus: value.ciphertext_modulus,
        })
    }
}
