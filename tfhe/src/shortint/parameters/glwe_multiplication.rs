use crate::core_crypto::prelude::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};

#[derive(Copy, Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GlweMultParameters {
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub packing_ks_level: DecompositionLevelCount,
    pub packing_ks_base_log: DecompositionBaseLog,
    pub packing_ks_polynomial_size: PolynomialSize,
    pub packing_ks_glwe_dimension: GlweDimension,
    pub lwe_dimension: LweDimension,
    pub lwe_per_glwe: LweCiphertextCount,
    pub packing_ks_key_noise_distribution: DynamicDistribution<u64>,
    pub lwe_noise_distribution: DynamicDistribution<u64>,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

pub const MULT_PARAM_MESSAGE_2_CARRY_2_TPKS_TUNIFORM_100: GlweMultParameters =
    GlweMultParameters {
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        packing_ks_level: DecompositionLevelCount(1),
        packing_ks_base_log: DecompositionBaseLog(28),
        packing_ks_polynomial_size: PolynomialSize(512),
        packing_ks_glwe_dimension: GlweDimension(5),
        lwe_dimension: LweDimension(2048),
        lwe_per_glwe: LweCiphertextCount(100),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(17),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        ciphertext_modulus: CiphertextModulus::new_native(),
    };
