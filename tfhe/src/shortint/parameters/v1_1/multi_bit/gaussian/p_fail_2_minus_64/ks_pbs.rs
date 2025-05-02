use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweBskGroupingFactor, LweDimension,
    MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PolynomialSize, StandardDev,
};

/// p-fail = 2^-64.715, algorithmic cost ~ 41, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(694),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.9787508069597174e-05,
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
    log2_p_fail: -64.715,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.542, algorithmic cost ~ 58, 2-norm = 3
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(746),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.622209110889238e-05,
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
    log2_p_fail: -65.542,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.278, algorithmic cost ~ 66, 2-norm = 7
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(842),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0957909745987987e-06,
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
    log2_p_fail: -64.278,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.033, algorithmic cost ~ 87, 2-norm = 15
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(886),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4490264961242091e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -64.033,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.105, algorithmic cost ~ 282, 2-norm = 31
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(31),
    log2_p_fail: -65.105,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.52, algorithmic cost ~ 650, 2-norm = 63
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(968),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.520822827277673e-07,
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
    log2_p_fail: -64.52,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.298, algorithmic cost ~ 1985, 2-norm = 127
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1044),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.487908029082033e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.298,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.032, algorithmic cost ~ 7529, 2-norm = 255
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1094),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.004208773393045e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(6),
    pbs_level: DecompositionLevelCount(6),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    max_noise_level: MaxNoiseLevel::new(255),
    log2_p_fail: -64.032,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.15, algorithmic cost ~ 44, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(760),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.274100790843934e-05,
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
    log2_p_fail: -65.15,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.22, algorithmic cost ~ 66, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(842),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0957909745987987e-06,
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
    log2_p_fail: -65.22,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.571, algorithmic cost ~ 80, 2-norm = 5
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.571,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.233, algorithmic cost ~ 282, 2-norm = 10
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -65.233,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.216, algorithmic cost ~ 638, 2-norm = 21
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.803076706754256e-07,
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
    log2_p_fail: -64.216,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.507, algorithmic cost ~ 1927, 2-norm = 42
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1050),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.554842450594469e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -64.507,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.291, algorithmic cost ~ 5427, 2-norm = 85
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(85),
    log2_p_fail: -64.291,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.284, algorithmic cost ~ 66, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(842),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.0957909745987987e-06,
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
    log2_p_fail: -65.284,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.202, algorithmic cost ~ 80, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(886),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4490264961242091e-06,
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
    log2_p_fail: -65.202,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.245, algorithmic cost ~ 282, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -65.245,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.103, algorithmic cost ~ 638, 2-norm = 9
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.803076706754256e-07,
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
    log2_p_fail: -65.103,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.432, algorithmic cost ~ 1923, 2-norm = 18
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.855195748835875e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.432,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.19, algorithmic cost ~ 5329, 2-norm = 36
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1084),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.7582522707221004e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(36),
    log2_p_fail: -64.19,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.512, algorithmic cost ~ 80, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(886),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4490264961242091e-06,
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
    log2_p_fail: -65.512,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.819, algorithmic cost ~ 183, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(932),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.552316598334162e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.819,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.266, algorithmic cost ~ 638, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.803076706754256e-07,
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
    log2_p_fail: -65.266,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.788, algorithmic cost ~ 1436, 2-norm = 8
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
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
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.788,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.165, algorithmic cost ~ 4287, 2-norm = 17
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1090),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.2903133537382335e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -64.165,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.609, algorithmic cost ~ 181, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.609,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.296, algorithmic cost ~ 638, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.803076706754256e-07,
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
    log2_p_fail: -65.296,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.834, algorithmic cost ~ 1428, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1050),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.554842450594469e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.834,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.741, algorithmic cost ~ 4263, 2-norm = 8
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1084),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.7582522707221004e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.741,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-65.304, algorithmic cost ~ 638, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.803076706754256e-07,
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
    log2_p_fail: -65.304,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.424, algorithmic cost ~ 1425, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.855195748835875e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.424,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.394, algorithmic cost ~ 4255, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1082),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.925310492031218e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.394,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.616, algorithmic cost ~ 1425, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.855195748835875e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.616,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.352, algorithmic cost ~ 3227, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1094),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.004208773393045e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.352,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.031, algorithmic cost ~ 3185, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1130),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.151622169498345e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.031,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-64.392, algorithmic cost ~ 44, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(693),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.0479935774347736e-05,
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
    log2_p_fail: -64.392,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-69.055, algorithmic cost ~ 60, 2-norm = 3
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
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
    log2_p_fail: -69.055,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-67.055, algorithmic cost ~ 68, 2-norm = 7
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(837),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.3747142481837397e-06,
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
    log2_p_fail: -67.055,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.731, algorithmic cost ~ 78, 2-norm = 15
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -64.731,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.116, algorithmic cost ~ 276, 2-norm = 31
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(885),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4742441118914234e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(31),
    log2_p_fail: -64.116,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.593, algorithmic cost ~ 623, 2-norm = 63
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(951),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.7209178960699193e-07,
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
    log2_p_fail: -65.593,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.211, algorithmic cost ~ 1893, 2-norm = 127
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1050),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.554842450594469e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -65.211,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.376, algorithmic cost ~ 6440, 2-norm = 255
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    max_noise_level: MaxNoiseLevel::new(255),
    log2_p_fail: -64.376,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-66.171, algorithmic cost ~ 48, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(753),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4376570909289213e-05,
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
    log2_p_fail: -66.171,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.37, algorithmic cost ~ 67, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(834),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.5539902359442825e-06,
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
    log2_p_fail: -64.37,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.968, algorithmic cost ~ 76, 2-norm = 5
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6350380064649354e-06,
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
    log2_p_fail: -64.968,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.212, algorithmic cost ~ 276, 2-norm = 10
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(885),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4742441118914234e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -64.212,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-66.244, algorithmic cost ~ 617, 2-norm = 21
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(942),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.51396649785382e-07,
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
    log2_p_fail: -66.244,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.413, algorithmic cost ~ 1871, 2-norm = 42
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1038),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0522741860905233e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -65.413,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.825, algorithmic cost ~ 5215, 2-norm = 85
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1080),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.098233986495092e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(85),
    log2_p_fail: -65.825,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.423, algorithmic cost ~ 67, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(834),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.5539902359442825e-06,
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
    log2_p_fail: -64.423,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-66.941, algorithmic cost ~ 76, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6350380064649354e-06,
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
    log2_p_fail: -66.941,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.215, algorithmic cost ~ 179, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(966),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.644435945205178e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.215,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.023, algorithmic cost ~ 616, 2-norm = 9
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(939),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.806886643881978e-07,
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
    log2_p_fail: -64.023,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.082, algorithmic cost ~ 1408, 2-norm = 18
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1074),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.654291759779223e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.082,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.189, algorithmic cost ~ 4198, 2-norm = 36
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1098),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.73718341270979e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(36),
    log2_p_fail: -64.189,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-67.234, algorithmic cost ~ 76, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6350380064649354e-06,
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
    log2_p_fail: -67.234,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.348, algorithmic cost ~ 170, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(915),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        8.785715784997144e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -65.348,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.163, algorithmic cost ~ 616, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(939),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.806886643881978e-07,
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
    log2_p_fail: -64.163,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.134, algorithmic cost ~ 1365, 2-norm = 8
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
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
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -65.134,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.51, algorithmic cost ~ 4107, 2-norm = 17
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1074),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.654291759779223e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -65.51,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.558, algorithmic cost ~ 169, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(909),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.743962418842052e-07,
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
    log2_p_fail: -64.558,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.189, algorithmic cost ~ 616, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(939),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.806886643881978e-07,
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
    log2_p_fail: -64.189,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-65.524, algorithmic cost ~ 1361, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1038),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0522741860905233e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -65.524,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.512, algorithmic cost ~ 4087, 2-norm = 8
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1107),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.199681401913558e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -64.512,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.33, algorithmic cost ~ 407, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1020),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4355035400171204e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.33,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-66.282, algorithmic cost ~ 1361, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1038),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0522741860905233e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -66.282,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.798, algorithmic cost ~ 3103, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.798,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-66.474, algorithmic cost ~ 1361, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1038),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0522741860905233e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -66.474,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.582, algorithmic cost ~ 2991, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1113),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.8850164020946995e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.582,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-64.28, algorithmic cost ~ 2975, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1107),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.199681401913558e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.28,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-69.861, algorithmic cost ~ 57, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64:
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
    log2_p_fail: -69.861,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-67.207, algorithmic cost ~ 74, 2-norm = 3
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64:
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
    log2_p_fail: -67.207,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.13, algorithmic cost ~ 80, 2-norm = 7
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(800),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.3897046246437025e-06,
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
    log2_p_fail: -64.13,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.051, algorithmic cost ~ 90, 2-norm = 15
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.117990356129097e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(15),
    log2_p_fail: -65.051,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.7, algorithmic cost ~ 330, 2-norm = 31
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(880),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6070699380295623e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(31),
    log2_p_fail: -65.7,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.453, algorithmic cost ~ 735, 2-norm = 63
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(944),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.326942058078918e-07,
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
    log2_p_fail: -64.453,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.212, algorithmic cost ~ 2266, 2-norm = 127
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1040),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0165828212228237e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(127),
    log2_p_fail: -64.212,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.846, algorithmic cost ~ 7822, 2-norm = 255
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1100),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.610424457179293e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(7),
    pbs_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(128),
    max_noise_level: MaxNoiseLevel::new(255),
    log2_p_fail: -64.846,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.154, algorithmic cost ~ 62, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(716),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.7220687403398157e-05,
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
    log2_p_fail: -65.154,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.526, algorithmic cost ~ 80, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(768),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.1098369627275701e-05,
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
    log2_p_fail: -64.526,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.733, algorithmic cost ~ 88, 2-norm = 5
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(808),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.565910031845765e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -64.733,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.801, algorithmic cost ~ 330, 2-norm = 10
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(880),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.6070699380295623e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(10),
    log2_p_fail: -65.801,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.464, algorithmic cost ~ 729, 2-norm = 21
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(936),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.115367677337101e-07,
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
    log2_p_fail: -65.464,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-66.236, algorithmic cost ~ 2239, 2-norm = 42
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1012),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.647968356631524e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(42),
    log2_p_fail: -66.236,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.354, algorithmic cost ~ 6253, 2-norm = 85
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1072),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.8528091713010457e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(8),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(64),
    max_noise_level: MaxNoiseLevel::new(85),
    log2_p_fail: -65.354,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.592, algorithmic cost ~ 80, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(768),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.1098369627275701e-05,
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
    log2_p_fail: -64.592,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.134, algorithmic cost ~ 88, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64:
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
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.134,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.793, algorithmic cost ~ 199, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(932),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.552316598334162e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.793,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-66.43, algorithmic cost ~ 729, 2-norm = 9
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(936),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.115367677337101e-07,
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
    log2_p_fail: -66.43,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.032, algorithmic cost ~ 1648, 2-norm = 18
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1064),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.719066893831459e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(18),
    log2_p_fail: -64.032,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.043, algorithmic cost ~ 4956, 2-norm = 36
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1088),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.440942634607687e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(32),
    max_noise_level: MaxNoiseLevel::new(36),
    log2_p_fail: -64.043,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.431, algorithmic cost ~ 88, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64:
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
    ks_base_log: DecompositionBaseLog(5),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.431,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.246, algorithmic cost ~ 193, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(908),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.913537993191986e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -65.246,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-66.607, algorithmic cost ~ 729, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(936),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.115367677337101e-07,
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
    log2_p_fail: -66.607,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-66.387, algorithmic cost ~ 1604, 2-norm = 8
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -66.387,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-66.466, algorithmic cost ~ 4865, 2-norm = 17
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1068),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.27099803371059e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -66.466,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.954, algorithmic cost ~ 193, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(904),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0621869847945622e-06,
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
    log2_p_fail: -64.954,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-66.64, algorithmic cost ~ 729, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(936),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.115367677337101e-07,
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
    log2_p_fail: -66.64,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.677, algorithmic cost ~ 1598, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1032),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.1670443677557458e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -65.677,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.883, algorithmic cost ~ 4847, 2-norm = 8
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1064),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        6.719066893831459e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(32),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(8),
    log2_p_fail: -65.883,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.047, algorithmic cost ~ 452, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(968),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.520822827277673e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.047,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.138, algorithmic cost ~ 1594, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1008),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.765717285765577e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -64.138,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.742, algorithmic cost ~ 3549, 2-norm = 4
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1128),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.2271638079224748e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(64),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(4),
    log2_p_fail: -64.742,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-64.346, algorithmic cost ~ 1594, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1008),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.765717285765577e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.346,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.867, algorithmic cost ~ 3473, 2-norm = 2
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M64:
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
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(128),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(2),
    log2_p_fail: -65.867,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-65.847, algorithmic cost ~ 3461, 2-norm = 1
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M64:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1100),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.610424457179293e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(256),
    carry_modulus: CarryModulus(1),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -65.847,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
