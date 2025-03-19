use crate::shortint::parameters::{
    CiphertextModulusLog, CompressionParameters, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, PolynomialSize, StandardDev,
};

// p-fail = 2^-129.053, algorithmic cost ~ 41458
pub const V1_1_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: CompressionParameters =
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

// p-fail = 2^-129.053, algorithmic cost ~ 41458
pub const V1_1_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    CompressionParameters = CompressionParameters {
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

// p-fail = 2^-128.0, algorithmic cost ~ 42199
pub const V1_1_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128: CompressionParameters =
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
    };

// p-fail = 2^-128.0, algorithmic cost ~ 42199
pub const V1_1_COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128:
    CompressionParameters = CompressionParameters {
    br_level: DecompositionLevelCount(1),
    br_base_log: DecompositionBaseLog(23),
    packing_ks_level: DecompositionLevelCount(2),
    packing_ks_base_log: DecompositionBaseLog(6),
    packing_ks_polynomial_size: PolynomialSize(256),
    packing_ks_glwe_dimension: GlweDimension(4),
    lwe_per_glwe: LweCiphertextCount(256),
    storage_log_modulus: CiphertextModulusLog(12),
    packing_ks_key_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.339775301998614e-07,
    )),
};
