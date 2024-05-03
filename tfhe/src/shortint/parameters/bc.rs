use super::*;

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(767),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_128_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(855),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_128_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(994),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_128_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(22),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_128_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1115),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(22),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_128_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(773),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_129_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(864),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_129_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1006),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_129_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(24),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_129_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1139),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(9),
    pbs_level: DecompositionLevelCount(4),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(24),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_129_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(779),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_130_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(871),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_130_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1016),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_130_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_130_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1104),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_130_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(785),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_131_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_131_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1025),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_131_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_131_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1112),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_131_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(791),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_132_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(887),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_132_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1036),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_132_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_132_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1121),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_132_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(798),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_133_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(896),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_133_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1048),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_133_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_133_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1130),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_133_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(805),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_134_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(906),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_134_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1063),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_134_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_134_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1140),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_134_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(811),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_135_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(914),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_135_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1076),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_135_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_135_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1149),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_135_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(816),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_136_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(922),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_136_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1090),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_136_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_136_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1155),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_136_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(822),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_137_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(932),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_137_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1086),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_137_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_137_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1164),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_137_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(829),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_138_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(948),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_138_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1102),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_138_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_138_64: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1174),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -64.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_138_64: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(776),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_128_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(871),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_128_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(8),
        ks_base_log: DecompositionBaseLog(2),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(973),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_128_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_128_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1096),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_128_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(783),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_129_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(17),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(888),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(17),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_129_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(8),
        ks_base_log: DecompositionBaseLog(2),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(982),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_129_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_129_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1106),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_129_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(789),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_130_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(866),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_130_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(989),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_130_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_130_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1115),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_130_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(795),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_131_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(873),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_131_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(997),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_131_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_131_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1123),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_131_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(801),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(24),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_132_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(879),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_132_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1004),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_132_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_132_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1131),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_132_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(808),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_133_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(887),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_133_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1013),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_133_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_133_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1140),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_133_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(815),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_134_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(895),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_134_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1022),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_134_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_134_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1151),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_134_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(821),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_135_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(902),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_135_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1029),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_135_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_135_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1159),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_135_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(827),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_136_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(907),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_136_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1036),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_136_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_136_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1166),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_136_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(832),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_137_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(914),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_137_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1043),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_137_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_137_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1174),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_137_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(840),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_138_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(922),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_138_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1052),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_138_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_138_80: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1185),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -80.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_138_80: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(802),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_128_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(904),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_128_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(998),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_128_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_128_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1123),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_128_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(809),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_129_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(912),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_129_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1007),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_129_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_129_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1135),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_129_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(815),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_130_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(919),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_130_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1015),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_130_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_130_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1143),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_130_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(822),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_131_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(926),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_131_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1023),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_131_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_131_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1151),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_131_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(828),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_132_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(933),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_132_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1030),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_132_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_132_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1160),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_132_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(835),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_133_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(941),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_133_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1039),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_133_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_133_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1170),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_133_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(843),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_134_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(950),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_134_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1049),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_134_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_134_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1181),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_134_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(849),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_135_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(957),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_135_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1057),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_135_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_135_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1190),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(37),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_135_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(855),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_136_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(963),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_136_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1063),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(41),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_136_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_136_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1197),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(37),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_136_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(861),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_137_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(970),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_137_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1071),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(16),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_137_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_137_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1206),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(37),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_137_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(869),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_138_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(979),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_138_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(5),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1081),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(16384),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(40),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_138_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_138_128: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1217),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(65536),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(37),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(11),
    pbs_level: DecompositionLevelCount(3),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -128.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_138_128: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(20),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(749),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(49),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(20),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_128_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(817),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_128_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(942),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_128_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_128_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1118),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_128_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(755),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(49),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_129_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(824),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_129_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(951),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(44),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_129_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_129_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1130),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_129_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(7),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(27),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(761),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(27),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_130_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(830),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_130_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(958),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_130_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_130_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1139),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_130_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(7),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(767),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_131_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(837),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_131_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(965),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_131_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_131_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1148),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_131_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(772),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_132_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(843),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_132_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(972),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_132_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_132_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1158),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_132_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(7),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(779),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_133_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(851),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_133_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(981),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_133_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_133_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1129),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_133_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(786),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_134_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(859),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_134_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(990),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_134_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_134_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1140),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(39),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_134_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(792),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_135_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(865),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_135_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(997),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_135_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_135_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1149),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_135_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(797),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_136_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(871),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_136_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1004),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_136_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_136_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1157),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_136_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(803),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_137_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(878),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_137_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1011),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_137_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_137_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1166),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_137_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_1_CARRY_1_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_1_CARRY_1_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(809),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    message_modulus: MessageModulus(2),
    carry_modulus: CarryModulus(2),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_1_CARRY_1_138_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_2_CARRY_2_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_2_CARRY_2_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(886),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(15),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_138_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_3_CARRY_3_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_3_CARRY_3_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1020),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(6),
    message_modulus: MessageModulus(8),
    carry_modulus: CarryModulus(8),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_3_CARRY_3_138_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(4),
    };

// only lwe_dimension and lwe_noise_distribution should be use; other parameters are the ones for
// the classical AP
pub const PARAM_PKE_MESSAGE_4_CARRY_4_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1024),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(42),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Small,
};

pub const PARAM_FHE_MESSAGE_4_CARRY_4_138_40: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1178),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(32768),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(38),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(15),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(7),
    message_modulus: MessageModulus(16),
    carry_modulus: CarryModulus(16),
    max_noise_level: MaxNoiseLevel::new(1),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
};

pub const PARAM_KEYSWITCH_MESSAGE_4_CARRY_4_138_40: ShortintKeySwitchingParameters =
    ShortintKeySwitchingParameters {
        ks_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(6),
    };
