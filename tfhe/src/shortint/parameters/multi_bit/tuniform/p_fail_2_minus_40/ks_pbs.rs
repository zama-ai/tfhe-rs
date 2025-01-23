use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::multi_bit::MultiBitPBSParameters;
use crate::shortint::parameters::{CarryModulus, MessageModulus};

// p-fail = 2^-44.562, algorithmic cost ~ 59, 2-norm = 3
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(50),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -44.562,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-42.062, algorithmic cost ~ 82, 2-norm = 5
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(958),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(7),
    ks_level: DecompositionLevelCount(2),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -42.062,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-41.38, algorithmic cost ~ 638, 2-norm = 9
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(998),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -41.38,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-43.86, algorithmic cost ~ 4240, 2-norm = 17
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1078),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -43.86,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

// p-fail = 2^-44.565, algorithmic cost ~ 61, 2-norm = 3
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(720),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(50),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -44.565,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-42.159, algorithmic cost ~ 79, 2-norm = 5
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(960),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(7),
    ks_level: DecompositionLevelCount(2),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -42.159,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-41.367, algorithmic cost ~ 622, 2-norm = 9
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(999),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -41.367,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-43.912, algorithmic cost ~ 4118, 2-norm = 17
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1077),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -43.912,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-48.15, algorithmic cost ~ 75, 2-norm = 3
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
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
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -48.15,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-55.544, algorithmic cost ~ 91, 2-norm = 5
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(840),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -55.544,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-41.346, algorithmic cost ~ 746, 2-norm = 9
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1000),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -41.346,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-43.888, algorithmic cost ~ 4920, 2-norm = 17
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_TUNIFORM_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1080),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -43.888,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
