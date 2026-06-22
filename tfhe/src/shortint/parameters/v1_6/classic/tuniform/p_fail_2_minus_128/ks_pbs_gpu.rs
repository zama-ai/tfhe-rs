use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, DecompositionBaseLog,
    DecompositionLevelCount, DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweDimension,
    MaxNoiseLevel, MessageModulus, ModulusSwitchType, PolynomialSize,
};

/// p-fail = 2^-144.851, algorithmic cost ~ 93.2, 2-norm = 3
pub const V1_6_PARAM_GPU_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(759),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(50),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -144.851,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

/// GPU FastKreyvium transciphering, classical (non-multibit) PBS variant.
///
/// Classical twin of `V1_6_PARAM_GPU_MULT_BIT_GROUP_4_KREYVIUM_1_0_TUNIFORM_2M128`
/// (same crypto core, no grouping factor). Z4 single-bit-extraction encoding:
/// message_modulus 2, carry_modulus 1, Delta = q/4, as the FastKreyvium kernels require.
/// `Standard` modulus switch matches the multibit baseline so the classical-vs-multibit
/// benchmark stays apples-to-apples. `log2_p_fail` is the optimizer's gpu_kreyvium value.
pub const V1_6_PARAM_GPU_KREYVIUM_1_0_TUNIFORM_2M128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(50),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(14),
    log2_p_fail: -185.13875243118102,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
};
