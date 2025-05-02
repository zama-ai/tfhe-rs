use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, EncryptionKeyChoice, GlweDimension, LweBskGroupingFactor, LweDimension,
    MaxNoiseLevel, MessageModulus, MultiBitPBSParameters, PolynomialSize, StandardDev,
};

/// p-fail = 2^-40.645, algorithmic cost ~ 44, 2-norm = 3
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(752),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.4626768433082104e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -40.645,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-40.713, algorithmic cost ~ 77, 2-norm = 5
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(858),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
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
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.713,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-40.788, algorithmic cost ~ 616, 2-norm = 9
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(964),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.77238901537491e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.788,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-40.51, algorithmic cost ~ 4113, 2-norm = 17
pub const V1_1_PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40:
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
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -40.51,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(2),
    deterministic_execution: false,
};

/// p-fail = 2^-40.879, algorithmic cost ~ 48, 2-norm = 3
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(747),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.5944604865450687e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -40.879,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-41.165, algorithmic cost ~ 74, 2-norm = 5
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(855),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.4737833030723735e-06,
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
    log2_p_fail: -41.165,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-40.56, algorithmic cost ~ 596, 2-norm = 9
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(957),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        4.2566505386938744e-07,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.56,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-41.06, algorithmic cost ~ 3977, 2-norm = 17
pub const V1_1_PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1077),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.3690690458649886e-08,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -41.06,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(3),
    deterministic_execution: false,
};

/// p-fail = 2^-41.55, algorithmic cost ~ 62, 2-norm = 3
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40:
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
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(3),
    log2_p_fail: -41.55,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-40.224, algorithmic cost ~ 86, 2-norm = 5
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(852),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.6051988578567595e-06,
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
    log2_p_fail: -40.224,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-40.024, algorithmic cost ~ 380, 2-norm = 9
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40:
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
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(9),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(9),
    log2_p_fail: -40.024,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};

/// p-fail = 2^-43.231, algorithmic cost ~ 4756, 2-norm = 17
pub const V1_1_PARAM_MULTI_BIT_GROUP_4_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40:
    MultiBitPBSParameters = MultiBitPBSParameters {
    lwe_dimension: LweDimension(1044),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
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
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(17),
    log2_p_fail: -43.231,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    grouping_factor: LweBskGroupingFactor(4),
    deterministic_execution: false,
};
