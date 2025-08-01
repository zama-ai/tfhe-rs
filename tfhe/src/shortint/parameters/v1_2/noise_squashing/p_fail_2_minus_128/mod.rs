use crate::shortint::parameters::noise_squashing::NoiseSquashingClassicParameters;
use crate::shortint::parameters::{
    CarryModulus, CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweCiphertextCount, MessageModulus,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    NoiseSquashingParameters, PolynomialSize, RSigmaFactor, Variance,
};

pub const V1_2_NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128:
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
