//! #Warning experimental

pub mod p_fail_2_minus_128;
pub mod p_fail_2_minus_40;
pub mod p_fail_2_minus_64;
pub mod p_fail_2_minus_80;

use super::CiphertextConformanceParams;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::core_crypto::prelude::LweCiphertextParameters;
use crate::shortint::ciphertext::{Degree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::parameters::p_fail_2_minus_40::ks_pbs::*;
use crate::shortint::parameters::p_fail_2_minus_40::ks_pbs_gpu::*;
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, EncryptionKeyChoice, LweBskGroupingFactor, MessageModulus,
};
use crate::shortint::PBSOrder;
use serde::{Deserialize, Serialize};

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation. This structure contains information to run the so-called multi-bit PBS with improved
/// latency provided enough threads are available on the machine performing the FHE computations
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq)]
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
            },
            message_modulus,
            carry_modulus,
            pbs_order,
            degree,
            noise_level,
        }
    }
}

pub const ALL_MULTI_BIT_PARAMETER_VEC: [MultiBitPBSParameters; 6] = [
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
];

// Convenience aliases
pub const PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS: MultiBitPBSParameters =
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS: MultiBitPBSParameters =
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS: MultiBitPBSParameters =
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS: MultiBitPBSParameters =
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS: MultiBitPBSParameters =
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS: MultiBitPBSParameters =
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const DEFAULT_MULTI_BIT_GROUP_2: MultiBitPBSParameters =
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS;
pub const DEFAULT_MULTI_BIT_GROUP_3: MultiBitPBSParameters =
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;

// GPU
pub const PARAM_GPU_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_GPU_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_GPU_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40;
pub const PARAM_GPU_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS: MultiBitPBSParameters =
    PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40;
