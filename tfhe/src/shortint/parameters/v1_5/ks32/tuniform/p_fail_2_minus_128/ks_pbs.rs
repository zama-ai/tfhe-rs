use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, CiphertextModulus32, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, GlweDimension, KeySwitch32PBSParameters,
    LweDimension, MaxNoiseLevel, MessageModulus, ModulusSwitchType, PolynomialSize,
};

/// p-fail = 2^-129.581, algorithmic cost ~ 113, 2-norm = 5
pub const V1_5_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128: KeySwitch32PBSParameters =
    KeySwitch32PBSParameters {
        lwe_dimension: LweDimension(918),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(13),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -129.581,
        post_keyswitch_ciphertext_modulus: CiphertextModulus32::new_native(),
        ciphertext_modulus: CiphertextModulus::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };
