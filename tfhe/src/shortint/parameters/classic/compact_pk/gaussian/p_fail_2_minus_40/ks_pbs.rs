// p-fail = 2^-40.755, algorithmic cost ~ 35, 2-norm = 1
pub const PARAM_MESSAGE_1_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(624),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.96193534738532e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.990272175010415e-08,
        )),
        pbs_base_log: DecompositionBaseLog(8),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.755,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.51, algorithmic cost ~ 54, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(708),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.6920407568805268e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -40.51,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.026, algorithmic cost ~ 68, 2-norm = 7
pub const PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(759),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.607570143466592e-06,
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
        log2_p_fail: -40.026,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.328, algorithmic cost ~ 161, 2-norm = 15
pub const PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(847),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3043826430106891e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -40.328,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.059, algorithmic cost ~ 538, 2-norm = 31
pub const PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(870),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.535688986373291e-07,
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
        log2_p_fail: -40.059,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.372, algorithmic cost ~ 1243, 2-norm = 63
pub const PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(903),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.6451505410272586e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(63),
        log2_p_fail: -40.372,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.115, algorithmic cost ~ 3682, 2-norm = 127
pub const PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(990),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.340502872240508e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -40.115,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.007, algorithmic cost ~ 8925, 2-norm = 255
pub const PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1085),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.620626123216454e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(8),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(128),
        max_noise_level: MaxNoiseLevel::new(255),
        log2_p_fail: -40.007,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.082, algorithmic cost ~ 44, 2-norm = 1
pub const PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(693),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.231101665299365e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.990272175010415e-08,
        )),
        pbs_base_log: DecompositionBaseLog(8),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.082,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.097, algorithmic cost ~ 68, 2-norm = 2
pub const PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(759),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.607570143466592e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.097,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.129, algorithmic cost ~ 160, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(840),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4840743649535557e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -40.129,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.068, algorithmic cost ~ 538, 2-norm = 10
pub const PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(870),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.535688986373291e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(10),
        log2_p_fail: -40.068,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.197, algorithmic cost ~ 1242, 2-norm = 21
pub const PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(902),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.73158917241699e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(21),
        log2_p_fail: -40.197,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.468, algorithmic cost ~ 2826, 2-norm = 42
pub const PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(997),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.209554798100223e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -40.468,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.014, algorithmic cost ~ 8297, 2-norm = 85
pub const PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1025),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.899107815351972e-08,
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
        log2_p_fail: -40.014,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.102, algorithmic cost ~ 68, 2-norm = 1
pub const PARAM_MESSAGE_3_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(759),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            6.607570143466592e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.102,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.496, algorithmic cost ~ 160, 2-norm = 2
pub const PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(840),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4840743649535557e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.496,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.213, algorithmic cost ~ 371, 2-norm = 4
pub const PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(878),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.365134701760727e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.213,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.246, algorithmic cost ~ 1242, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(902),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.73158917241699e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -40.246,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.292, algorithmic cost ~ 2809, 2-norm = 18
pub const PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(991),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.169866695821157e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(18),
        log2_p_fail: -40.292,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.173, algorithmic cost ~ 8281, 2-norm = 36
pub const PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1023),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.083132953850712e-08,
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
        log2_p_fail: -40.173,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.62, algorithmic cost ~ 160, 2-norm = 1
pub const PARAM_MESSAGE_4_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(840),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4840743649535557e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.62,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.243, algorithmic cost ~ 368, 2-norm = 2
pub const PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(872),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.226670638405535e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.243,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.255, algorithmic cost ~ 1242, 2-norm = 4
pub const PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(902),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.73158917241699e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.255,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.226, algorithmic cost ~ 2807, 2-norm = 8
pub const PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(990),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.340502872240508e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -40.226,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.105, algorithmic cost ~ 6526, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1048),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.205904405936845e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -40.105,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.389, algorithmic cost ~ 368, 2-norm = 1
pub const PARAM_MESSAGE_5_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(871),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.379755483470793e-07,
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
        log2_p_fail: -40.389,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.085, algorithmic cost ~ 893, 2-norm = 2
pub const PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(964),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5085454358100435e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.085,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.326, algorithmic cost ~ 2807, 2-norm = 4
pub const PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(990),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.340502872240508e-08,
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
        log2_p_fail: -40.326,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.015, algorithmic cost ~ 6335, 2-norm = 8
pub const PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1062),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.47656233645343e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -40.015,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.308, algorithmic cost ~ 860, 2-norm = 1
pub const PARAM_MESSAGE_6_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1000),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.76779754710308e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(6),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.308,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.352, algorithmic cost ~ 2807, 2-norm = 2
pub const PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(990),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.340502872240508e-08,
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
        log2_p_fail: -40.352,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.14, algorithmic cost ~ 6311, 2-norm = 4
pub const PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1058),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.6661108851744016e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -40.14,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.358, algorithmic cost ~ 2807, 2-norm = 1
pub const PARAM_MESSAGE_7_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(990),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.340502872240508e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.358,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.132, algorithmic cost ~ 6305, 2-norm = 2
pub const PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1057),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.715722835102037e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -40.132,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-40.232, algorithmic cost ~ 6305, 2-norm = 1
pub const PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M40: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1057),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.715722835102037e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(256),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -40.232,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
