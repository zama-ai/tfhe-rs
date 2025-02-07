use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweBskGroupingFactor, LweDimension,
    MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PolynomialSize, StandardDev,
};

// p-fail = 2^-65.905, algorithmic cost ~ 41, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(696),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.8437982930180355e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -65.905,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-66.162, algorithmic cost ~ 59, 2-norm = 3
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(748),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5671865150356198e-05,
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
    log2_p_fail: -66.162,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.528, algorithmic cost ~ 67, 2-norm = 7
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
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
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -64.528,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.972, algorithmic cost ~ 126, 2-norm = 15
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(834),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.5539902359442825e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -64.972,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.434, algorithmic cost ~ 291, 2-norm = 31
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(946),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.146261171730886e-07,
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
    log2_p_fail: -64.434,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.052, algorithmic cost ~ 695, 2-norm = 63
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1010),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.705827134764532e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(63),
    log2_p_fail: -64.052,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.09, algorithmic cost ~ 2126, 2-norm = 127
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1046),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.166094197883469e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.09,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.018, algorithmic cost ~ 8061, 2-norm = 255
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1118),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.6465671112690942e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(12),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    max_noise_level: MaxNoiseLevel::new(255),
    log2_p_fail: -64.018,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.597, algorithmic cost ~ 46, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(780),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.022819800659706e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.597,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.598, algorithmic cost ~ 67, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(858),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.348996819227123e-06,
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
    log2_p_fail: -64.598,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.148, algorithmic cost ~ 82, 2-norm = 5
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(872),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.844927811696596e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.148,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.082, algorithmic cost ~ 290, 2-norm = 10
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(944),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.326942058078918e-07,
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
    log2_p_fail: -64.082,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.278, algorithmic cost ~ 658, 2-norm = 21
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(980),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.862379879879129e-07,
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
    log2_p_fail: -64.278,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.114, algorithmic cost ~ 2004, 2-norm = 42
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1054),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.984352743330102e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -64.114,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.024, algorithmic cost ~ 6864, 2-norm = 85
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1114),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.8356668849263424e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(85),
    log2_p_fail: -64.024,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.665, algorithmic cost ~ 67, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(858),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.348996819227123e-06,
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
    log2_p_fail: -64.665,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.098, algorithmic cost ~ 82, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(906),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0261593945208966e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.098,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.093, algorithmic cost ~ 290, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(944),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.326942058078918e-07,
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
    log2_p_fail: -64.093,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.212, algorithmic cost ~ 657, 2-norm = 9
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.212,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.13, algorithmic cost ~ 2000, 2-norm = 18
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.264676629436917e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.13,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.004, algorithmic cost ~ 5831, 2-norm = 36
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1126),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.3053576495153107e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(36),
    log2_p_fail: -64.004,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.422, algorithmic cost ~ 82, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(906),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0261593945208966e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.422,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.174, algorithmic cost ~ 196, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(920),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.059568198173411e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.174,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.395, algorithmic cost ~ 657, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.395,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.195, algorithmic cost ~ 1511, 2-norm = 8
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1060),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.199150706330062e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.195,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.021, algorithmic cost ~ 5810, 2-norm = 17
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1122),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.470077677912143e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.021,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.327, algorithmic cost ~ 187, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(952),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.64016444919407e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.327,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.41, algorithmic cost ~ 657, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.41,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.235, algorithmic cost ~ 1503, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1054),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.984352743330102e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.235,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.039, algorithmic cost ~ 4682, 2-norm = 8
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.039,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.414, algorithmic cost ~ 657, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.414,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.136, algorithmic cost ~ 1500, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.264676629436917e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.136,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.016, algorithmic cost ~ 4657, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1110),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.038278019865525e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.016,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.182, algorithmic cost ~ 1500, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.264676629436917e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.182,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.017, algorithmic cost ~ 4335, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1102),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.487964951537331e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(22),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.017,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-64.007, algorithmic cost ~ 3578, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_2_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1114),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.8356668849263424e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.007,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};
// p-fail = 2^-65.875, algorithmic cost ~ 44, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(696),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.8437982930180355e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -65.875,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.618, algorithmic cost ~ 60, 2-norm = 3
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(747),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5944604865450687e-05,
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
    log2_p_fail: -64.618,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.667, algorithmic cost ~ 69, 2-norm = 7
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(807),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.6627743617620195e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -64.667,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.972, algorithmic cost ~ 126, 2-norm = 15
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(834),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.5539902359442825e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -64.972,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.239, algorithmic cost ~ 286, 2-norm = 31
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(945),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.235822292396081e-07,
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
    log2_p_fail: -64.239,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.047, algorithmic cost ~ 667, 2-norm = 63
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1017),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5117622381302512e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(63),
    log2_p_fail: -64.047,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.11, algorithmic cost ~ 2093, 2-norm = 127
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1047),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.009303989461499e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.11,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.051, algorithmic cost ~ 8019, 2-norm = 255
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1119),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.60129637762614e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(12),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    max_noise_level: MaxNoiseLevel::new(255),
    log2_p_fail: -64.051,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.629, algorithmic cost ~ 50, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(744),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.679163503644773e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.629,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.612, algorithmic cost ~ 69, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(858),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.348996819227123e-06,
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
    log2_p_fail: -64.612,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.095, algorithmic cost ~ 78, 2-norm = 5
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.095,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.32, algorithmic cost ~ 286, 2-norm = 10
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(945),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.235822292396081e-07,
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
    log2_p_fail: -64.32,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.593, algorithmic cost ~ 643, 2-norm = 21
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(981),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.8134175707144757e-07,
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
    log2_p_fail: -64.593,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.368, algorithmic cost ~ 1973, 2-norm = 42
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1056),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.713536970443607e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -64.368,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.08, algorithmic cost ~ 6803, 2-norm = 85
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(85),
    log2_p_fail: -64.08,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.668, algorithmic cost ~ 69, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(858),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.348996819227123e-06,
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
    log2_p_fail: -64.668,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.153, algorithmic cost ~ 78, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(906),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0261593945208966e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.153,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.328, algorithmic cost ~ 286, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(945),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.235822292396081e-07,
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
    log2_p_fail: -64.328,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.232, algorithmic cost ~ 641, 2-norm = 9
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.232,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.03, algorithmic cost ~ 1911, 2-norm = 18
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1041),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.991937098983378e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.03,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.032, algorithmic cost ~ 5697, 2-norm = 36
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1119),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.60129637762614e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(36),
    log2_p_fail: -64.032,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.435, algorithmic cost ~ 78, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(906),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0261593945208966e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.435,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.187, algorithmic cost ~ 186, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(918),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.342532835418705e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.187,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.399, algorithmic cost ~ 641, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.399,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.227, algorithmic cost ~ 1458, 2-norm = 8
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1059),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.324438557758654e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.227,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.022, algorithmic cost ~ 5697, 2-norm = 17
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1119),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.60129637762614e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.022,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.267, algorithmic cost ~ 177, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.267,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.412, algorithmic cost ~ 641, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.412,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.131, algorithmic cost ~ 1450, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1053),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.123305578333294e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.131,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.053, algorithmic cost ~ 4560, 2-norm = 8
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.053,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.415, algorithmic cost ~ 641, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(978),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
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
    log2_p_fail: -64.415,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.29, algorithmic cost ~ 1450, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1053),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.123305578333294e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.29,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.019, algorithmic cost ~ 4536, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1110),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.038278019865525e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.019,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.33, algorithmic cost ~ 1450, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1053),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.123305578333294e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.33,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.051, algorithmic cost ~ 4187, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1101),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.5486665054375844e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(22),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.051,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.074, algorithmic cost ~ 3439, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_3_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.074,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};
// p-fail = 2^-64.761, algorithmic cost ~ 57, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(664),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.676348397087967e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.761,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-65.871, algorithmic cost ~ 74, 2-norm = 3
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(712),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.9165631782424004e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -65.871,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-65.172, algorithmic cost ~ 81, 2-norm = 7
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(776),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.667508981141782e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(7),
    log2_p_fail: -65.172,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-65.906, algorithmic cost ~ 154, 2-norm = 15
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(836),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.433444883863949e-06,
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
    log2_p_fail: -65.906,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.013, algorithmic cost ~ 346, 2-norm = 31
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(944),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.326942058078918e-07,
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
    log2_p_fail: -64.013,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.064, algorithmic cost ~ 791, 2-norm = 63
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1016),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5380716530060473e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(63),
    log2_p_fail: -64.064,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.007, algorithmic cost ~ 2802, 2-norm = 127
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1036),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0892186446555833e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(21),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.007,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.032, algorithmic cost ~ 9798, 2-norm = 255
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1124),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.3862968108916744e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(12),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    max_noise_level: MaxNoiseLevel::new(255),
    log2_p_fail: -64.032,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.014, algorithmic cost ~ 64, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(744),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.679163503644773e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.014,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-66.202, algorithmic cost ~ 81, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(776),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.667508981141782e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -66.202,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.122, algorithmic cost ~ 91, 2-norm = 5
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(872),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.844927811696596e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.122,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.086, algorithmic cost ~ 346, 2-norm = 10
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(944),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.326942058078918e-07,
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
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.394, algorithmic cost ~ 763, 2-norm = 21
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(980),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.862379879879129e-07,
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
    log2_p_fail: -64.394,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.282, algorithmic cost ~ 2371, 2-norm = 42
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1056),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.713536970443607e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -64.282,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.045, algorithmic cost ~ 8229, 2-norm = 85
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(85),
    log2_p_fail: -64.045,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-66.272, algorithmic cost ~ 81, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(776),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.667508981141782e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -66.272,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.539, algorithmic cost ~ 91, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(868),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.976749683932629e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.539,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.093, algorithmic cost ~ 346, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(944),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.326942058078918e-07,
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
    log2_p_fail: -64.093,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.633, algorithmic cost ~ 763, 2-norm = 9
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(980),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.862379879879129e-07,
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
    log2_p_fail: -64.633,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.114, algorithmic cost ~ 2362, 2-norm = 18
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.264676629436917e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.114,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.072, algorithmic cost ~ 6827, 2-norm = 36
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1120),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.5568000204635114e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(36),
    log2_p_fail: -64.072,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.837, algorithmic cost ~ 91, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(868),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.976749683932629e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.837,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.426, algorithmic cost ~ 210, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(916),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.635432122258441e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.426,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.835, algorithmic cost ~ 763, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(980),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.862379879879129e-07,
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
    log2_p_fail: -64.835,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.265, algorithmic cost ~ 1711, 2-norm = 8
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1060),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.199150706330062e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.265,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.007, algorithmic cost ~ 6852, 2-norm = 17
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1124),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.3862968108916744e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.007,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.62, algorithmic cost ~ 203, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(952),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.64016444919407e-07,
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
    log2_p_fail: -64.62,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.848, algorithmic cost ~ 763, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(980),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.862379879879129e-07,
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
    log2_p_fail: -64.848,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.512, algorithmic cost ~ 1705, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1056),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        7.713536970443607e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.512,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.077, algorithmic cost ~ 5377, 2-norm = 8
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.077,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.851, algorithmic cost ~ 763, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(980),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.862379879879129e-07,
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
    log2_p_fail: -64.851,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.141, algorithmic cost ~ 1698, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.264676629436917e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.141,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.1, algorithmic cost ~ 5357, 2-norm = 4
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1112),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.935224755982453e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.1,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.183, algorithmic cost ~ 1698, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.264676629436917e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.183,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.029, algorithmic cost ~ 4705, 2-norm = 2
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1104),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.369659065698222e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(22),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.029,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
// p-fail = 2^-64.048, algorithmic cost ~ 3951, 2-norm = 1
pub const V1_0_PARAM_MULTI_BIT_GROUP_4_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1116),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7394858488703536e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(11),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.048,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
