use crate::shortint::parameters::list_compression::ClassicCompressionParameters;
use crate::shortint::parameters::{
    CiphertextModulusLog, CompressionParameters, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, PolynomialSize, StandardDev,
};

/// p-fail = 2^-72.052, algorithmic cost ~ 42700
pub const V1_5_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64: CompressionParameters =
    CompressionParameters::Classic(ClassicCompressionParameters {
        br_level: DecompositionLevelCount(1),
        br_base_log: DecompositionBaseLog(23),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(6),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(4),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(43),
    });

/// p-fail = 2^-64.174, algorithmic cost ~ 58234
pub const V1_5_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: CompressionParameters =
    CompressionParameters::Classic(ClassicCompressionParameters {
        br_level: DecompositionLevelCount(2),
        br_base_log: DecompositionBaseLog(15),
        packing_ks_level: DecompositionLevelCount(2),
        packing_ks_base_log: DecompositionBaseLog(6),
        packing_ks_polynomial_size: PolynomialSize(256),
        packing_ks_glwe_dimension: GlweDimension(4),
        lwe_per_glwe: LweCiphertextCount(256),
        storage_log_modulus: CiphertextModulusLog(12),
        packing_ks_key_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(
            StandardDev(1.339775301998614e-07),
        ),
    });
