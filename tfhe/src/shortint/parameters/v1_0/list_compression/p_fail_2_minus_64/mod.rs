use crate::shortint::parameters::{
    CiphertextModulusLog, CompressionParameters, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, PolynomialSize, StandardDev,
};

// p-fail = 2^-71.052, algorithmic cost ~ 97079
pub const V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(23),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(6),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(4),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(43),
        decompression_grouping_factor: None,
    };

// p-fail = 2^-63.983, algorithmic cost ~ 110013
pub const V1_0_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters =
    CompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(23),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(6),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(4),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
            StandardDev(1.339775301998614e-07),
        ),
        decompression_grouping_factor: None,
    };
