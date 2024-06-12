// p-fail = 2^-64.023, algorithmic cost ~ 41, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(698),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.713423140641025e-05,
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
        log2_p_fail: -64.023,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.308, algorithmic cost ~ 59, 2-norm = 3
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.308,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.344, algorithmic cost ~ 67, 2-norm = 7
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.344,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.129, algorithmic cost ~ 90, 2-norm = 15
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(882),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5525608373746976e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -64.129,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.068, algorithmic cost ~ 291, 2-norm = 31
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.971708676181112e-07,
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
        log2_p_fail: -64.068,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.094, algorithmic cost ~ 671, 2-norm = 63
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(998),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.0982243334250348e-07,
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
        log2_p_fail: -64.094,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.187, algorithmic cost ~ 2847, 2-norm = 127
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1016),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5380716530060473e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(20),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -64.187,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.317, algorithmic cost ~ 46, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.317,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.708, algorithmic cost ~ 67, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.708,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.584, algorithmic cost ~ 82, 2-norm = 5
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.584,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.113, algorithmic cost ~ 291, 2-norm = 10
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(948),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.971708676181112e-07,
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
        log2_p_fail: -64.113,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.374, algorithmic cost ~ 662, 2-norm = 21
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(986),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.5808859899421514e-07,
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
        log2_p_fail: -64.374,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.148, algorithmic cost ~ 2365, 2-norm = 42
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1016),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5380716530060473e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(20),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -64.148,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.732, algorithmic cost ~ 67, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.732,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.346, algorithmic cost ~ 82, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(908),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.913537993191986e-07,
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
        log2_p_fail: -64.346,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.035, algorithmic cost ~ 221, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(928),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            7.020485941329387e-07,
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
        log2_p_fail: -64.035,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.168, algorithmic cost ~ 661, 2-norm = 9
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.168,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.268, algorithmic cost ~ 2365, 2-norm = 18
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1016),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5380716530060473e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(20),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(18),
        log2_p_fail: -64.268,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.496, algorithmic cost ~ 82, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(908),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.913537993191986e-07,
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
        log2_p_fail: -64.496,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.088, algorithmic cost ~ 189, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(962),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.9048344098472363e-07,
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
        log2_p_fail: -64.088,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.207, algorithmic cost ~ 661, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.207,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.229, algorithmic cost ~ 1886, 2-norm = 8
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -64.229,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.364, algorithmic cost ~ 187, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.364,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.006, algorithmic cost ~ 661, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(984),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.671498718807819e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(18),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -64.006,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.188, algorithmic cost ~ 1882, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -64.188,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.216, algorithmic cost ~ 661, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.216,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.268, algorithmic cost ~ 1882, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.268,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
// p-fail = 2^-64.242, algorithmic cost ~ 1882, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1016),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.5380716530060473e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(13),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(20),
        message_modulus: MessageModulus(128),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -64.242,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(2),
        deterministic_execution: false,
    };
pub const ALL_MULTI_BIT_PARAMETER_2_VEC: [MultiBitPBSParameters; 28] = [
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_2_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
]; // p-fail = 2^-65.739, algorithmic cost ~ 45, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(699),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.649903349592563e-05,
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
        log2_p_fail: -65.739,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.31, algorithmic cost ~ 61, 2-norm = 3
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.31,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.861, algorithmic cost ~ 70, 2-norm = 7
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(861),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.230505012256408e-06,
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
        log2_p_fail: -64.861,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.129, algorithmic cost ~ 87, 2-norm = 15
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(885),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.4742441118914234e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(3),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(15),
        log2_p_fail: -64.129,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.072, algorithmic cost ~ 287, 2-norm = 31
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(31),
        log2_p_fail: -64.072,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.107, algorithmic cost ~ 653, 2-norm = 63
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(63),
        log2_p_fail: -64.107,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.013, algorithmic cost ~ 2859, 2-norm = 127
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1014),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.592072050626447e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(21),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(64),
        max_noise_level: MaxNoiseLevel::new(127),
        log2_p_fail: -64.013,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.251, algorithmic cost ~ 50, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(780),
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(512),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            9.022819800659706e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.9524392655548086e-11,
        )),
        pbs_base_log: DecompositionBaseLog(16),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(4),
        ks_level: DecompositionLevelCount(3),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -64.251,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-65.185, algorithmic cost ~ 70, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(861),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.230505012256408e-06,
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
        log2_p_fail: -65.185,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.046, algorithmic cost ~ 78, 2-norm = 5
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(5),
        log2_p_fail: -64.046,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.114, algorithmic cost ~ 287, 2-norm = 10
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.114,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.343, algorithmic cost ~ 647, 2-norm = 21
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(987),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.5367387617400005e-07,
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
        log2_p_fail: -64.343,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.094, algorithmic cost ~ 2859, 2-norm = 42
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        pbs_level: DecompositionLevelCount(4),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(21),
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(32),
        max_noise_level: MaxNoiseLevel::new(42),
        log2_p_fail: -64.094,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-65.207, algorithmic cost ~ 70, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(861),
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(1024),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.230505012256408e-06,
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
        log2_p_fail: -65.207,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.685, algorithmic cost ~ 78, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -64.685,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.029, algorithmic cost ~ 276, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(918),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            8.342532835418705e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(18),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -64.029,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.173, algorithmic cost ~ 645, 2-norm = 9
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.173,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.121, algorithmic cost ~ 2360, 2-norm = 18
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1014),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.592072050626447e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(11),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(21),
        message_modulus: MessageModulus(8),
        carry_modulus: CarryModulus(16),
        max_noise_level: MaxNoiseLevel::new(18),
        log2_p_fail: -64.121,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.84, algorithmic cost ~ 78, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -64.84,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.308, algorithmic cost ~ 179, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -64.308,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.208, algorithmic cost ~ 645, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.208,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.047, algorithmic cost ~ 2360, 2-norm = 8
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(1014),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(16384),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            1.592072050626447e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(13),
        pbs_level: DecompositionLevelCount(3),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(21),
        message_modulus: MessageModulus(16),
        carry_modulus: CarryModulus(8),
        max_noise_level: MaxNoiseLevel::new(8),
        log2_p_fail: -64.047,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.112, algorithmic cost ~ 177, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(951),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            4.7209178960699193e-07,
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
        log2_p_fail: -64.112,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.212, algorithmic cost ~ 645, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.212,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.049, algorithmic cost ~ 1862, 2-norm = 4
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(32),
        carry_modulus: CarryModulus(4),
        max_noise_level: MaxNoiseLevel::new(4),
        log2_p_fail: -64.049,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.099, algorithmic cost ~ 615, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
        lwe_dimension: LweDimension(978),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(8192),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.962875621642539e-07,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.168404344971009e-19,
        )),
        pbs_base_log: DecompositionBaseLog(21),
        pbs_level: DecompositionLevelCount(1),
        ks_base_log: DecompositionBaseLog(1),
        ks_level: DecompositionLevelCount(19),
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(1),
        max_noise_level: MaxNoiseLevel::new(1),
        log2_p_fail: -64.099,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.129, algorithmic cost ~ 1862, 2-norm = 2
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        message_modulus: MessageModulus(64),
        carry_modulus: CarryModulus(2),
        max_noise_level: MaxNoiseLevel::new(2),
        log2_p_fail: -64.129,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };
// p-fail = 2^-64.149, algorithmic cost ~ 1862, 2-norm = 1
pub const PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64: MultiBitPBSParameters =
    MultiBitPBSParameters {
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
        log2_p_fail: -64.149,
        ciphertext_modulus: CiphertextModulus::new_native(),
        encryption_key_choice: EncryptionKeyChoice::Big,
        grouping_factor: LweBskGroupingFactor(3),
        deterministic_execution: false,
    };

pub const ALL_MULTI_BIT_PARAMETER_3_VEC: [MultiBitPBSParameters; 28] = [
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_1_CARRY_6_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_5_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_3_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_4_CARRY_3_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_5_CARRY_2_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_0_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_6_CARRY_1_KS_PBS_GAUSSIAN_2M64,
    PARAM_MULTI_BIT_GROUP_3_MESSAGE_7_CARRY_0_KS_PBS_GAUSSIAN_2M64,
];
use crate::core_crypto::prelude::*;
use crate::shortint::ciphertext::MaxNoiseLevel;
use crate::shortint::parameters::multi_bit::MultiBitPBSParameters;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
