use crate::shortint::parameters::noise_squashing::{
    NoiseSquashingClassicParameters, NoiseSquashingMultiBitParameters,
};
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweBskGroupingFactor, LweCiphertextCount, MessageModulus,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    NoiseSquashingCompressionParameters, NoiseSquashingParameters, PolynomialSize, RSigmaFactor,
    Variance,
};

pub const V1_3_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
        ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1449),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
            ms_input_variance: Variance(2.63039184094559E-7f64),
        },
    ),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
});

pub const V1_3_NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingCompressionParameters = NoiseSquashingCompressionParameters {
    packing_ks_level: DecompositionLevelCount(1),
    packing_ks_base_log: DecompositionBaseLog(61),
    packing_ks_polynomial_size: PolynomialSize(1024),
    packing_ks_glwe_dimension: GlweDimension(6),
    lwe_per_glwe: LweCiphertextCount(128),
    packing_ks_key_noise_distribution: DynamicDistribution::new_t_uniform(3),
    ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
};

pub const V1_3_NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
    decomp_base_log: DecompositionBaseLog(24),
    decomp_level_count: DecompositionLevelCount(3),
    modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
        ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(2827),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(20.83904137608219f64),
            ms_input_variance: Variance(2.7596542105799535e-07f64),
        },
    ),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
});

pub const V1_3_NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
    NoiseSquashingParameters = NoiseSquashingParameters::MultiBit(NoiseSquashingMultiBitParameters {
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(30),
    decomp_base_log: DecompositionBaseLog(23),
    decomp_level_count: DecompositionLevelCount(3),
    grouping_factor: LweBskGroupingFactor(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    deterministic_execution: false,
});
