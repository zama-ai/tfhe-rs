//! #Warning experimental

pub use super::parameters_wopbs_message_carry::*;
pub use super::parameters_wopbs_only::*;
use super::WopbsParametersVersions;
pub use crate::core_crypto::commons::dispersion::StandardDev;
pub use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
    LweDimension, PolynomialSize,
};
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, EncryptionKeyChoice, MessageModulus,
};
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// A structure defining the set of cryptographic parameters for homomorphic integer circuit
/// evaluation, this structure contains parameters to exclusively perform a so-called Wopbs.
#[derive(Serialize, Copy, Clone, Deserialize, Debug, PartialEq, Versionize)]
#[versionize(WopbsParametersVersions)]
pub struct WopbsParameters {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub glwe_noise_distribution: DynamicDistribution<u64>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_noise_distribution: DynamicDistribution<u64>,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub ciphertext_modulus: CiphertextModulus,
    pub encryption_key_choice: EncryptionKeyChoice,
}

pub const ALL_PARAMETER_VEC_WOPBS: [WopbsParameters; 72] = [
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    LEGACY_WOPBS_PARAM_MESSAGE_8_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_1_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_1_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_5_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_6_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_1_CARRY_7_KS_PBS,
    LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_2_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_5_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_2_CARRY_6_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_3_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_3_CARRY_5_KS_PBS,
    LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_4_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_5_CARRY_3_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_6_CARRY_2_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_7_CARRY_0_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_7_CARRY_1_KS_PBS,
    LEGACY_WOPBS_ONLY_2_BLOCKS_PARAM_MESSAGE_8_CARRY_0_KS_PBS,
];
