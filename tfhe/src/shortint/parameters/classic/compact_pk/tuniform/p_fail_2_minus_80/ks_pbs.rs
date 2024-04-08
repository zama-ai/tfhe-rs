// p-fail = 2^-80.129, algorithmic cost ~ 45, 2-norm = 1
pub const PARAM_MESSAGE_1_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(709),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(49),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
        pbs_base_log: DecompositionBaseLog(7),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.129,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.064, algorithmic cost ~ 65, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(856),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -80.064,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.14, algorithmic cost ~ 81, 2-norm = 7
pub const PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(832),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(7),
        log2_p_fail: -80.14,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.065, algorithmic cost ~ 347, 2-norm = 15
pub const PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(872),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(17),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -80.065,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.231, algorithmic cost ~ 1241, 2-norm = 31
pub const PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(947),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(31),
        log2_p_fail: -80.231,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.821, algorithmic cost ~ 2840, 2-norm = 63
pub const PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(979),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(63),
        log2_p_fail: -80.821,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.659, algorithmic cost ~ 8302, 2-norm = 127
pub const PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1060),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -81.659,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.659, algorithmic cost ~ 23125, 2-norm = 255
pub const PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1106),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(128),
        max_noise_level: MaxNoiseLevel::new(255),
        log2_p_fail: -80.659,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.06, algorithmic cost ~ 65, 2-norm = 1
pub const PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(856),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.06,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.124, algorithmic cost ~ 81, 2-norm = 2
pub const PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(830),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.124,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.066, algorithmic cost ~ 347, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(872),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(17),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -80.066,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.361, algorithmic cost ~ 1241, 2-norm = 10
pub const PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(947),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(10),
        log2_p_fail: -80.361,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.2, algorithmic cost ~ 2825, 2-norm = 21
pub const PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(974),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(21),
        log2_p_fail: -81.2,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.629, algorithmic cost ~ 8287, 2-norm = 42
pub const PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1058),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -81.629,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.136, algorithmic cost ~ 18946, 2-norm = 85
pub const PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1116),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(85),
        log2_p_fail: -80.136,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.147, algorithmic cost ~ 81, 2-norm = 1
pub const PARAM_MESSAGE_3_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(830),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(14),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.147,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.001, algorithmic cost ~ 268, 2-norm = 2
pub const PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(877),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(17),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.001,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.374, algorithmic cost ~ 1241, 2-norm = 4
pub const PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(947),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -80.374,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.329, algorithmic cost ~ 2822, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(973),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -80.329,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.344, algorithmic cost ~ 6352, 2-norm = 18
pub const PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1065),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(18),
        log2_p_fail: -81.344,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.232, algorithmic cost ~ 18589, 2-norm = 36
pub const PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1095),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(36),
        log2_p_fail: -81.232,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.046, algorithmic cost ~ 267, 2-norm = 1
pub const PARAM_MESSAGE_4_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(873),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(17),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.046,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.032, algorithmic cost ~ 857, 2-norm = 2
pub const PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(960),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.032,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.419, algorithmic cost ~ 2822, 2-norm = 4
pub const PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(973),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -80.419,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.454, algorithmic cost ~ 6317, 2-norm = 8
pub const PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1059),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -80.454,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.341, algorithmic cost ~ 18538, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1092),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -80.341,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.676, algorithmic cost ~ 848, 2-norm = 1
pub const PARAM_MESSAGE_5_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(950),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.676,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.497, algorithmic cost ~ 2822, 2-norm = 2
pub const PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(973),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.497,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.207, algorithmic cost ~ 6311, 2-norm = 4
pub const PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1058),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -81.207,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.574, algorithmic cost ~ 14609, 2-norm = 8
pub const PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1143),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -80.574,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.154, algorithmic cost ~ 2001, 2-norm = 1
pub const PARAM_MESSAGE_6_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1062),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.154,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.091, algorithmic cost ~ 6305, 2-norm = 2
pub const PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1057),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.091,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.558, algorithmic cost ~ 14309, 2-norm = 4
pub const PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1097),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -80.558,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.196, algorithmic cost ~ 6305, 2-norm = 1
pub const PARAM_MESSAGE_7_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1057),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.196,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.918, algorithmic cost ~ 14257, 2-norm = 2
pub const PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1093),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.918,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.865, algorithmic cost ~ 14244, 2-norm = 1
pub const PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS_TUNIFORM_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1092),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.865,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
