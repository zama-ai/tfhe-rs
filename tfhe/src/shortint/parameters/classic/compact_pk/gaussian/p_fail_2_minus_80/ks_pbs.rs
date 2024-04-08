// p-fail = 2^-80.049, algorithmic cost ~ 41, 2-norm = 1
pub const PARAM_MESSAGE_1_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(683),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.682821145455988e-05,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.990272175010415e-08,
        )),
        pbs_base_log: DecompositionBaseLog(8),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.049,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.118, algorithmic cost ~ 61, 2-norm = 3
pub const PARAM_MESSAGE_1_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(803),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.9357792504909956e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(3),
        log2_p_fail: -80.118,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.082, algorithmic cost ~ 76, 2-norm = 7
pub const PARAM_MESSAGE_1_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(781),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.4043577651404615e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(7),
        log2_p_fail: -80.082,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.097, algorithmic cost ~ 265, 2-norm = 15
pub const PARAM_MESSAGE_1_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(863),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.711565298549587e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -80.097,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.488, algorithmic cost ~ 1192, 2-norm = 31
pub const PARAM_MESSAGE_1_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(909),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.1586883623255596e-07,
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
        log2_p_fail: -80.488,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.016, algorithmic cost ~ 2727, 2-norm = 63
pub const PARAM_MESSAGE_1_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(940),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.348183651116047e-07,
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
        log2_p_fail: -80.016,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.211, algorithmic cost ~ 7997, 2-norm = 127
pub const PARAM_MESSAGE_1_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1021),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.27407062680997e-08,
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
        log2_p_fail: -80.211,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.739, algorithmic cost ~ 22309, 2-norm = 255
pub const PARAM_MESSAGE_1_CARRY_7_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1067),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.2584635394536597e-08,
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
        log2_p_fail: -80.739,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.129, algorithmic cost ~ 61, 2-norm = 1
pub const PARAM_MESSAGE_2_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(803),
        glwe_dimension: GlweDimension(4),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.9357792504909956e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.129,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.038, algorithmic cost ~ 76, 2-norm = 2
pub const PARAM_MESSAGE_2_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(780),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.486315637981604e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(24),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.038,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.011, algorithmic cost ~ 202, 2-norm = 5
pub const PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(844),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.3785633212699611e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(9),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -80.011,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.614, algorithmic cost ~ 1192, 2-norm = 10
pub const PARAM_MESSAGE_2_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(909),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.1586883623255596e-07,
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
        log2_p_fail: -80.614,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.367, algorithmic cost ~ 2715, 2-norm = 21
pub const PARAM_MESSAGE_2_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(936),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.527906485727494e-07,
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
        log2_p_fail: -81.367,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.716, algorithmic cost ~ 7989, 2-norm = 42
pub const PARAM_MESSAGE_2_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1020),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.372212429278534e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -81.716,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.26, algorithmic cost ~ 18267, 2-norm = 85
pub const PARAM_MESSAGE_2_CARRY_6_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1076),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9131453186756372e-08,
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
        log2_p_fail: -80.26,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.083, algorithmic cost ~ 76, 2-norm = 1
pub const PARAM_MESSAGE_3_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(780),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.486315637981604e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1529322391500584e-16,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.083,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.037, algorithmic cost ~ 186, 2-norm = 2
pub const PARAM_MESSAGE_3_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(866),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.188984659930854e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.037,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.045, algorithmic cost ~ 980, 2-norm = 4
pub const PARAM_MESSAGE_3_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(927),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.984187648179355e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(9),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -80.045,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.022, algorithmic cost ~ 2712, 2-norm = 9
pub const PARAM_MESSAGE_3_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(935),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.574946678500066e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(9),
        log2_p_fail: -80.022,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.589, algorithmic cost ~ 6120, 2-norm = 18
pub const PARAM_MESSAGE_3_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1026),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.809608883986922e-08,
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
        log2_p_fail: -80.589,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.163, algorithmic cost ~ 17927, 2-norm = 36
pub const PARAM_MESSAGE_3_CARRY_5_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1056),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.7662579820314513e-08,
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
        log2_p_fail: -80.163,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.01, algorithmic cost ~ 186, 2-norm = 1
pub const PARAM_MESSAGE_4_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(863),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.711565298549587e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(23),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.01,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.219, algorithmic cost ~ 823, 2-norm = 2
pub const PARAM_MESSAGE_4_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(921),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.3332627166887524e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.219,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.573, algorithmic cost ~ 2712, 2-norm = 4
pub const PARAM_MESSAGE_4_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(935),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.574946678500066e-07,
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
        log2_p_fail: -80.573,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.669, algorithmic cost ~ 6090, 2-norm = 8
pub const PARAM_MESSAGE_4_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1021),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.27407062680997e-08,
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
        log2_p_fail: -80.669,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.527, algorithmic cost ~ 17893, 2-norm = 17
pub const PARAM_MESSAGE_4_CARRY_4_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1054),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.8701669032989807e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(17),
        log2_p_fail: -80.527,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.127, algorithmic cost ~ 815, 2-norm = 1
pub const PARAM_MESSAGE_5_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(912),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.9349087806215726e-07,
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
        log2_p_fail: -81.127,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.598, algorithmic cost ~ 2712, 2-norm = 2
pub const PARAM_MESSAGE_5_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(935),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.574946678500066e-07,
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
        log2_p_fail: -80.598,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.308, algorithmic cost ~ 6084, 2-norm = 4
pub const PARAM_MESSAGE_5_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1020),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.372212429278534e-08,
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
        log2_p_fail: -81.308,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.695, algorithmic cost ~ 14098, 2-norm = 8
pub const PARAM_MESSAGE_5_CARRY_3_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1103),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.162927355420996e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(14),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -80.695,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.412, algorithmic cost ~ 1924, 2-norm = 1
pub const PARAM_MESSAGE_6_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1021),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.27407062680997e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(5),
        ks_level: DecompositionLevelCount(4),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.412,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.137, algorithmic cost ~ 6078, 2-norm = 2
pub const PARAM_MESSAGE_6_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1019),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.472180489693452e-08,
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
        log2_p_fail: -80.137,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.097, algorithmic cost ~ 13814, 2-norm = 4
pub const PARAM_MESSAGE_6_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1059),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.617405266903232e-08,
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
        log2_p_fail: -81.097,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.147, algorithmic cost ~ 6078, 2-norm = 1
pub const PARAM_MESSAGE_7_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1019),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(32768),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            5.472180489693452e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(5),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -80.147,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-80.893, algorithmic cost ~ 13762, 2-norm = 2
pub const PARAM_MESSAGE_7_CARRY_1_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1055),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.817733505144395e-08,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(15),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(7),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -80.893,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
// p-fail = 2^-81.035, algorithmic cost ~ 13749, 2-norm = 1
pub const PARAM_MESSAGE_8_CARRY_0_COMPACT_PK_KS_PBS_GAUSSIAN_2M80: ClassicPBSParameters =
    ClassicPBSParameters {
        lwe_dimension: LweDimension(1054),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(65536),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.8701669032989807e-08,
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
        log2_p_fail: -81.035,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
    };
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::{CarryModulus, ClassicPBSParameters, MessageModulus};
