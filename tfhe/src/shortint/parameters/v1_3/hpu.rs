use crate::core_crypto::prelude::DynamicDistribution;
use crate::shortint::parameters::{
    CiphertextModulus32, KeySwitch32PBSParameters, ModulusSwitchType, StandardDev,
};
use crate::shortint::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use crate::shortint::{CarryModulus, CiphertextModulus, MaxNoiseLevel, MessageModulus};

// Gaussian parameters set with pfail 2^-64
pub const V1_3_HPU_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_GAUSSIAN_2M64: KeySwitch32PBSParameters =
    KeySwitch32PBSParameters {
        lwe_dimension: LweDimension(804),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.963599673924788e-6,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.8452674713391114e-15,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(8),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -64.0,
        post_keyswitch_ciphertext_modulus: CiphertextModulus32::new(1 << 21),
        ciphertext_modulus: CiphertextModulus::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
    };

// TUniform parameters set with pfail 2^-64
pub const V1_3_HPU_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M64: KeySwitch32PBSParameters =
    KeySwitch32PBSParameters {
        lwe_dimension: LweDimension(839),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -64.0,
        post_keyswitch_ciphertext_modulus: CiphertextModulus32::new(1 << 21),
        ciphertext_modulus: CiphertextModulus::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
    };

// TUniform parameters set with pfail 2^-128
pub const V1_3_HPU_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128: KeySwitch32PBSParameters =
    KeySwitch32PBSParameters {
        lwe_dimension: LweDimension(879),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(8),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -128.0,
        post_keyswitch_ciphertext_modulus: CiphertextModulus32::new(1 << 21),
        ciphertext_modulus: CiphertextModulus::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };
