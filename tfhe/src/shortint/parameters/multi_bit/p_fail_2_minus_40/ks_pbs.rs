// p-fail = 2^-40.132, algorithmic cost ~ 35, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(660),
        glwe_dimension: GlweDimension(5),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.0997573154568715e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.449096324925789e-10,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.132,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.724, algorithmic cost ~ 41, 2-norm = 3
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(702),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.889967064728197e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.966608917163306e-12,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -40.724,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.179, algorithmic cost ~ 60, 2-norm = 7
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(760),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.48686031444288e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(7),
        log2_p_fail: -40.179,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-41.051, algorithmic cost ~ 74, 2-norm = 15
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(826),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.921130946437615e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -41.051,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.545, algorithmic cost ~ 261, 2-norm = 31
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(826),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.921130946437615e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(31),
        log2_p_fail: -40.545,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.131, algorithmic cost ~ 593, 2-norm = 63
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(928),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.929671271816316e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(63),
        log2_p_fail: -40.131,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.063, algorithmic cost ~ 1771, 2-norm = 127
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0261620265864796e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -40.063,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.892, algorithmic cost ~ 4955, 2-norm = 255
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1008),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.702549186334495e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(128),
        max_noise_level: MaxNoiseLevel::new(255),
        log2_p_fail: -40.892,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.616, algorithmic cost ~ 41, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(700),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.96095987892077e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.966608917163306e-12,
        )),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.616,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.078, algorithmic cost ~ 60, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(760),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.48686031444288e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.078,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.374, algorithmic cost ~ 74, 2-norm = 5
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(820),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.145855057588057e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -40.374,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.607, algorithmic cost ~ 261, 2-norm = 10
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(826),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.921130946437615e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(10),
        log2_p_fail: -40.607,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.265, algorithmic cost ~ 592, 2-norm = 21
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(926),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.0397184848746404e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(21),
        log2_p_fail: -40.265,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.526, algorithmic cost ~ 1330, 2-norm = 42
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(978),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.1653519057640512e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -40.526,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.919, algorithmic cost ~ 3972, 2-norm = 85
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1010),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.459896170269795e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(85),
        log2_p_fail: -40.919,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.546, algorithmic cost ~ 60, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(760),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.48686031444288e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.546,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.72, algorithmic cost ~ 74, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(820),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.145855057588057e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.72,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.17, algorithmic cost ~ 168, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(854),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.1464479944984405e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.17,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.341, algorithmic cost ~ 592, 2-norm = 9
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(926),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.0397184848746404e-07,
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
        log2_p_fail: -40.341,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.766, algorithmic cost ~ 1322, 2-norm = 18
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(972),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3016688349592805e-07,
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
        log2_p_fail: -40.766,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.712, algorithmic cost ~ 3949, 2-norm = 36
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1004),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.21554191512647e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(36),
        log2_p_fail: -40.712,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.769, algorithmic cost ~ 74, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(820),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.145855057588057e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.769,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.29, algorithmic cost ~ 167, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(886),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.3551061035236e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.29,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.355, algorithmic cost ~ 592, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(926),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.0397184848746404e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.355,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.126, algorithmic cost ~ 1319, 2-norm = 8
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(970),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3505634085553605e-07,
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
        log2_p_fail: -40.126,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.039, algorithmic cost ~ 3159, 2-norm = 17
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1004),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.21554191512647e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(10),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -40.039,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.937, algorithmic cost ~ 167, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(886),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.3551061035236e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.937,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.242, algorithmic cost ~ 397, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1010),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.459896170269795e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.242,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.2, algorithmic cost ~ 1319, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(970),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3505634085553605e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.2,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.528, algorithmic cost ~ 2968, 2-norm = 8
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1006),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.954316975245897e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -40.528,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.096, algorithmic cost ~ 383, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(936),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.527906485727494e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.096,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.259, algorithmic cost ~ 1319, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(970),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3505634085553605e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.259,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.865, algorithmic cost ~ 2962, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1004),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.21554191512647e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.865,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.277, algorithmic cost ~ 1319, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(970),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3505634085553605e-07,
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
        log2_p_fail: -40.277,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.017, algorithmic cost ~ 2956, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1002),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.48657924484466e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.017,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-40.105, algorithmic cost ~ 2956, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1002),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.48657924484466e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.105,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
pub const ALL_MULTI_BIT_PARAMETER_2_VEC: [MultiBitPBSParameters; 36] = [
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M40,
]; // p-fail = 2^-40.217, algorithmic cost ~ 41, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(681),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.78359592965502e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.966608917163306e-12,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(2),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.217,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.579, algorithmic cost ~ 45, 2-norm = 3
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(702),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.889967064728197e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.966608917163306e-12,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -40.579,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.202, algorithmic cost ~ 62, 2-norm = 7
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(762),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.252015902812266e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(7),
        log2_p_fail: -41.202,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.417, algorithmic cost ~ 71, 2-norm = 15
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(825),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9568800418143656e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -40.417,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.01, algorithmic cost ~ 257, 2-norm = 31
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(825),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9568800418143656e-06,
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
        log2_p_fail: -40.01,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.795, algorithmic cost ~ 579, 2-norm = 63
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(930),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.8236081083211815e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(63),
        log2_p_fail: -40.795,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.317, algorithmic cost ~ 1745, 2-norm = 127
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(951),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.917133974645489e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -41.317,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.984, algorithmic cost ~ 4867, 2-norm = 255
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1008),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.702549186334495e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(8),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(128),
        max_noise_level: MaxNoiseLevel::new(255),
        log2_p_fail: -40.984,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.148, algorithmic cost ~ 45, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(699),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9974501253932986e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.966608917163306e-12,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.148,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.095, algorithmic cost ~ 61, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(759),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.607570143466592e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.095,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.843, algorithmic cost ~ 71, 2-norm = 5
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(822),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0681684659218507e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -41.843,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.024, algorithmic cost ~ 257, 2-norm = 10
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(825),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9568800418143656e-06,
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
        log2_p_fail: -40.024,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.592, algorithmic cost ~ 577, 2-norm = 21
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(927),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.984187648179355e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(21),
        log2_p_fail: -40.592,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.493, algorithmic cost ~ 1282, 2-norm = 42
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(978),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.1653519057640512e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -40.493,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.803, algorithmic cost ~ 3866, 2-norm = 85
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1011),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.341884110572598e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(10),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(85),
        log2_p_fail: -40.803,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.102, algorithmic cost ~ 61, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(759),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.607570143466592e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.102,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.843, algorithmic cost ~ 71, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(822),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0681684659218507e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(19),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.843,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.823, algorithmic cost ~ 159, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(894),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.483589265161398e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.823,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.662, algorithmic cost ~ 577, 2-norm = 9
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(927),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.984187648179355e-07,
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
        log2_p_fail: -40.662,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.76, algorithmic cost ~ 1274, 2-norm = 18
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(972),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3016688349592805e-07,
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
        log2_p_fail: -40.76,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.195, algorithmic cost ~ 3843, 2-norm = 36
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1005),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.083725405883707e-08,
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
        log2_p_fail: -41.195,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.018, algorithmic cost ~ 70, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(819),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.1857859000226386e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.018,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.188, algorithmic cost ~ 158, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(888),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.125031601933181e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -41.188,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.674, algorithmic cost ~ 577, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(927),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.984187648179355e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.674,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.382, algorithmic cost ~ 1274, 2-norm = 8
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0261620265864796e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -40.382,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.39, algorithmic cost ~ 3049, 2-norm = 17
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1011),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.341884110572598e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(10),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -40.39,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.39, algorithmic cost ~ 157, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(885),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.47336420281948e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.39,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.012, algorithmic cost ~ 365, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(996),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.362321145455233e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.012,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.496, algorithmic cost ~ 1274, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0261620265864796e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.496,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.356, algorithmic cost ~ 2841, 2-norm = 8
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1008),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.702549186334495e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -41.356,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.668, algorithmic cost ~ 358, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(936),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.527906485727494e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.668,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.124, algorithmic cost ~ 1274, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0261620265864796e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(17),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.124,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-41.398, algorithmic cost ~ 2833, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1005),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.083725405883707e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -41.398,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.124, algorithmic cost ~ 1274, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0261620265864796e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.124,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.003, algorithmic cost ~ 2824, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1002),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.48657924484466e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.003,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-40.102, algorithmic cost ~ 2824, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M40: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1002),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.48657924484466e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.102,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
pub const ALL_MULTI_BIT_PARAMETER_3_VEC: [MultiBitPBSParameters; 36] = [
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_7_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_6_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_5_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_3_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_2_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_1_KS_PBS_GAUSSIAN_2M40,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_8_CARRY_0_KS_PBS_GAUSSIAN_2M40,
];
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::multi_bit::MultiBitPBSParameters;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
