use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use crate::shortint::MultiBitPBSParameters;

// p-fail = 2^-65.348, algorithmic cost ~ 41, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(700),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.58747009344789e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -65.348,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.263, algorithmic cost ~ 59, 2-norm = 3
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(750),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5140301927925663e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -64.263,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.119, algorithmic cost ~ 68, 2-norm = 7
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(862),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.192351209970737e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -64.119,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.871, algorithmic cost ~ 127, 2-norm = 15
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(840),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.2044815829012556e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -64.871,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.172, algorithmic cost ~ 292, 2-norm = 31
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.803076706754256e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(31),
    log2_p_fail: -64.172,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.06, algorithmic cost ~ 887, 2-norm = 63
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(63),
    log2_p_fail: -64.06,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.03, algorithmic cost ~ 2853, 2-norm = 127
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1018),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4859028577569142e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.03,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.171, algorithmic cost ~ 49, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(766),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.1488024017979662e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.171,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.615, algorithmic cost ~ 67, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(860),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.269322810630956e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.615,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.442, algorithmic cost ~ 84, 2-norm = 5
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(888),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.3998779623487315e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.442,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.099, algorithmic cost ~ 291, 2-norm = 10
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(948),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.971708676181112e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -64.099,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.298, algorithmic cost ~ 665, 2-norm = 21
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(990),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.408776579232607e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(21),
    log2_p_fail: -64.298,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.168, algorithmic cost ~ 2408, 2-norm = 42
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1020),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4355035400171204e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -64.168,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.709, algorithmic cost ~ 67, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(860),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.269322810630956e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.709,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.253, algorithmic cost ~ 82, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(910),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.577287511785255e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.253,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.115, algorithmic cost ~ 291, 2-norm = 4
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(948),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.971708676181112e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.115,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.02, algorithmic cost ~ 661, 2-norm = 9
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -64.02,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.111, algorithmic cost ~ 2365, 2-norm = 18
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1016),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5380716530060473e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.111,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.305, algorithmic cost ~ 82, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(908),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.913537993191986e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.305,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.085, algorithmic cost ~ 220, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(926),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.266969277511613e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.085,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.178, algorithmic cost ~ 661, 2-norm = 4
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.178,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.259, algorithmic cost ~ 2365, 2-norm = 8
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1016),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5380716530060473e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.259,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.126, algorithmic cost ~ 189, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(962),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.9048344098472363e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.126,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.207, algorithmic cost ~ 661, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.207,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.114, algorithmic cost ~ 1886, 2-norm = 4
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1018),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4859028577569142e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.114,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.214, algorithmic cost ~ 661, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.214,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.16, algorithmic cost ~ 1882, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1016),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5380716530060473e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.16,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.261, algorithmic cost ~ 1882, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1016),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5380716530060473e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(20),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.261,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
pub const ALL_V0_10_MULTI_BIT_PARAMETER_2_VEC: [MultiBitPBSParameters; 28] = [
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
]; // p-fail = 2^-67.438, algorithmic cost ~ 45, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(702),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.4657891610923056e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -67.438,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.086, algorithmic cost ~ 61, 2-norm = 3
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(750),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5140301927925663e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(20),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -64.086,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.377, algorithmic cost ~ 70, 2-norm = 7
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.117990356129097e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -64.377,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.87, algorithmic cost ~ 127, 2-norm = 15
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(840),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.2044815829012556e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -64.87,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.453, algorithmic cost ~ 288, 2-norm = 31
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(951),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.7209178960699193e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(31),
    log2_p_fail: -64.453,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.606, algorithmic cost ~ 884, 2-norm = 63
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(987),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.5367387617400005e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(63),
    log2_p_fail: -64.606,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.101, algorithmic cost ~ 3855, 2-norm = 127
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.101,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.031, algorithmic cost ~ 58, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(765),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.1687951746275051e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.031,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-65.038, algorithmic cost ~ 70, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(861),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.230505012256408e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -65.038,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.442, algorithmic cost ~ 80, 2-norm = 5
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(891),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.3292631075564801e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.442,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.086, algorithmic cost ~ 287, 2-norm = 10
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(948),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.971708676181112e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -64.086,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.068, algorithmic cost ~ 653, 2-norm = 21
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(996),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.1718912188918548e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(21),
    log2_p_fail: -64.068,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.064, algorithmic cost ~ 2859, 2-norm = 42
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -64.064,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.73, algorithmic cost ~ 70, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(861),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.230505012256408e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(19),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.73,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.769, algorithmic cost ~ 78, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(912),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.252442079345288e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.769,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.113, algorithmic cost ~ 287, 2-norm = 4
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(948),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.971708676181112e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.113,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.437, algorithmic cost ~ 647, 2-norm = 9
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(987),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.5367387617400005e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -64.437,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.139, algorithmic cost ~ 2859, 2-norm = 18
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.139,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.351, algorithmic cost ~ 78, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(909),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.743962418842052e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(20),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.351,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.117, algorithmic cost ~ 287, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(948),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.971708676181112e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.117,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.138, algorithmic cost ~ 645, 2-norm = 4
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.138,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.111, algorithmic cost ~ 2360, 2-norm = 8
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.111,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.194, algorithmic cost ~ 181, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(972),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.286032625627172e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.194,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.146, algorithmic cost ~ 645, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.146,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.145, algorithmic cost ~ 2360, 2-norm = 4
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.145,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.212, algorithmic cost ~ 645, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(984),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.671498718807819e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.212,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.153, algorithmic cost ~ 2360, 2-norm = 2
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.153,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.079, algorithmic cost ~ 1862, 2-norm = 1
pub const V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1014),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.592072050626447e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.079,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
pub const ALL_V0_10_MULTI_BIT_PARAMETER_3_VEC: [MultiBitPBSParameters; 28] = [
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    V0_10_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
];
