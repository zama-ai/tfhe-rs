use crate::core_crypto::prelude::{CiphertextModulusLog, LweCiphertextCount};
use crate::shortint::parameters::{
    CompressionParameters, DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution,
    GlweDimension, PolynomialSize,
};

pub const V0_10_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(23),
        packing_ks_level: DecompositionLevelCount(4),
        packing_ks_base_log: DecompositionBaseLog(4),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(4),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(42),
    };
