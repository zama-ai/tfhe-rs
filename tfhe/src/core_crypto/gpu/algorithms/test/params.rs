use crate::core_crypto::prelude::{
    CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, LweBskGroupingFactor, LweDimension, MessageModulusLog, PolynomialSize,
    UnsignedInteger,
};
use crate::shortint::EncryptionKeyChoice;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MultiBitTestKS32Params<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_noise_distribution: DynamicDistribution<Scalar>,
    pub glwe_noise_distribution: DynamicDistribution<Scalar>,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub message_modulus_log: MessageModulusLog,
    pub log2_p_fail: f64,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    pub encryption_key_choice: EncryptionKeyChoice,
    pub grouping_factor: LweBskGroupingFactor,
    pub deterministic_execution: bool,
}
