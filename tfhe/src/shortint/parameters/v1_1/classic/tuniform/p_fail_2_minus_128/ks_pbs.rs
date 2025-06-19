use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension,
    LweCiphertextCount, LweDimension, MaxNoiseLevel, MessageModulus,
    ModulusSwitchNoiseReductionParams, ModulusSwitchType, NoiseEstimationMeasureBound,
    PolynomialSize, RSigmaFactor, Variance,
};

/// p-fail = 2^-144.044, algorithmic cost ~ 67, 2-norm = 3
/// Average number of encryptions of 0s ~ 15, peak noise ~ Variance(0.0000201396668936698)
pub const V1_1_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(879),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -144.044,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1437),
                ms_bound: NoiseEstimationMeasureBound(1152921504606846976f64),
                ms_r_sigma_factor: RSigmaFactor(13.926881354504543f64),
                ms_input_variance: Variance(0.00000263576954463012f64),
            },
        ),
    };

/// p-fail = 2^-129.358, algorithmic cost ~ 113, 2-norm = 5
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(0.00000140546154228955)
pub const V1_1_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(918),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -129.358,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1449),
                ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
                ms_r_sigma_factor: RSigmaFactor(13.179852282053789f64),
                ms_input_variance: Variance(2.63039184094559E-7f64),
            },
        ),
    };

/// p-fail = 2^-128.771, algorithmic cost ~ 900, 2-norm = 9
/// Average number of encryptions of 0s ~ 17, peak noise ~ Variance(8.82526029096167E-8)
pub const V1_1_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1077),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -128.771,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(1459),
                ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
                ms_r_sigma_factor: RSigmaFactor(13.149107412468162f64),
                ms_input_variance: Variance(4.51118140877493E-9f64),
            },
        ),
    };

/// p-fail = 2^-141.493, algorithmic cost ~ 11860, 2-norm = 17
/// Average number of encryptions of 0s ~ 31, peak noise ~ Variance(5.00776611824111E-9)
pub const V1_1_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1117),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -141.493,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::DriftTechniqueNoiseReduction(
            ModulusSwitchNoiseReductionParams {
                modulus_switch_zeros_count: LweCiphertextCount(2948),
                ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
                ms_r_sigma_factor: RSigmaFactor(13.799966261408738f64),
                ms_input_variance: Variance(3.65080002319590E-9f64),
            },
        ),
    };
