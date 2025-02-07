use crate::shortint::parameters::{
    CiphertextModulusLog, CompressionParameters, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, PolynomialSize,
};

// p-fail = 2^-129.048, algorithmic cost ~ 97955
pub const V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(23),
        packing_ks_level: DecompositionLevelCount(3),
        packing_ks_base_log: DecompositionBaseLog(4),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(4),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(43),
    };
