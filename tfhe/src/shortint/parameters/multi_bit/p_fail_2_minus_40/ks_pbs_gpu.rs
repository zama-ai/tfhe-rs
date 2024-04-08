use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::multi_bit::MultiBitPBSParameters;
use crate::shortint::parameters::{CarryModulus, MessageModulus};

// Group 2
pub const PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(764),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000006025673585415336,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000039666089171633006,
    )),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(6),
    ks_level: DecompositionLevelCount(2),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

pub const PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(818),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000002226459789930014,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000003152931493498455,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

pub const PARAM_GPU_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(922),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000003272369292345697,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

// Group 3
pub const PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(765),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000005915594083804978,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000039666089171633006,
    )),
    pbs_base_log: DecompositionBaseLog(18),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(6),
    ks_level: DecompositionLevelCount(2),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

pub const PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(888),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000006125031601933181,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000003152931493498455,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(7),
    ks_level: DecompositionLevelCount(2),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

pub const PARAM_GPU_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(972),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.00000013016688349592805,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(6),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
