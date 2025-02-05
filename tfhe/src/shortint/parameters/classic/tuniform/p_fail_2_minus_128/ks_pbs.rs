use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
use crate::shortint::server_key::ModulusSwitchNoiseReductionParams;

// p-fail = 2^-144.044, algorithmic cost ~ 67, 2-norm = 3
pub const V1_0_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
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
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1109),
            ms_bound: NoiseEstimationMeasureBound(1152921504606846976f64),
            ms_r_sigma_factor: RSigmaFactor(14.9386942434093f64),
        }),
    };
// p-fail = 2^-129.358, algorithmic cost ~ 113, 2-norm = 5
pub const V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
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
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1161),
            ms_bound: NoiseEstimationMeasureBound(288230376151711744f64),
            ms_r_sigma_factor: RSigmaFactor(14.6186301624361f64),
        }),
    };
// p-fail = 2^-128.771, algorithmic cost ~ 900, 2-norm = 9
pub const V1_0_PARAM_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
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
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(1375),
            ms_bound: NoiseEstimationMeasureBound(72057594037927936f64),
            ms_r_sigma_factor: RSigmaFactor(13.4986354989548f64),
        }),
    };
// p-fail = 2^-141.493, algorithmic cost ~ 11860, 2-norm = 17
pub const V1_0_PARAM_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
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
        modulus_switch_noise_reduction_params: Some(ModulusSwitchNoiseReductionParams {
            modulus_switch_zeros_count: LweCiphertextCount(714),
            ms_bound: NoiseEstimationMeasureBound(18014398509481984f64),
            ms_r_sigma_factor: RSigmaFactor(26.5103551016191f64),
        }),
    };
