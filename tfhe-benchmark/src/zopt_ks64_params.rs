// Generated from zopt experiments/blockchain_ks64 (exp/blockchain-ks64):
// the CPU blockchain circuit on KS_PBS (keyswitch at 2^64).
use tfhe::core_crypto::prelude::{
    CiphertextModulus as CoreCiphertextModulus, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, LweDimension, PolynomialSize,
};
use tfhe::shortint::parameters::noise_squashing::NoiseSquashingClassicParameters;
use tfhe::shortint::parameters::{
    CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
    MessageModulus, ModulusSwitchType, NoiseSquashingParameters,
};

/// zopt experiments/blockchain_ks64/circuit.ref.json
/// p-fail = 2^-130.479, 2-norm = 5, 132 bits of security
pub const ZOPT_KS64_132_S80_2M128_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(901),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(4),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -130.479,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-130.479 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_132_S80_2M128_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(28),
        decomp_base_log: DecompositionBaseLog(25),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.bootstrap_cost.ref.json
/// p-fail = 2^-130.260, 2-norm = 5, 132 bits of security
pub const ZOPT_KS64_132_S80_2M128_BOOTSTRAP_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(821),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -130.260,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-130.260 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_132_S80_2M128_BOOTSTRAP_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(28),
        decomp_base_log: DecompositionBaseLog(25),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.132_80_160.ref.json
/// p-fail = 2^-175.336, 2-norm = 5, 132 bits of security
pub const ZOPT_KS64_132_S80_2M160_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(860),
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
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -175.336,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-175.336 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_132_S80_2M160_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(28),
        decomp_base_log: DecompositionBaseLog(25),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.132_80_160.bootstrap_cost.ref.json
/// p-fail = 2^-169.666, 2-norm = 5, 132 bits of security
pub const ZOPT_KS64_132_S80_2M160_BOOTSTRAP_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(821),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -169.666,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-169.666 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_132_S80_2M160_BOOTSTRAP_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(4096),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(28),
        decomp_base_log: DecompositionBaseLog(25),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.160_80_128.ref.json
/// p-fail = 2^-128.142, 2-norm = 5, 160 bits of security
pub const ZOPT_KS64_160_S80_2M128_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1092),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(25),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -128.142,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-128.142 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_160_S80_2M128_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        decomp_base_log: DecompositionBaseLog(25),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.160_80_128.bootstrap_cost.ref.json
/// p-fail = 2^-129.142, 2-norm = 5, 160 bits of security
pub const ZOPT_KS64_160_S80_2M128_BOOTSTRAP_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1043),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(25),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -129.142,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-129.142 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_160_S80_2M128_BOOTSTRAP_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        decomp_base_log: DecompositionBaseLog(25),
        decomp_level_count: DecompositionLevelCount(3),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.160_128_128.ref.json
/// p-fail = 2^-128.142, 2-norm = 5, 160 bits of security
pub const ZOPT_KS64_160_S126_2M128_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1092),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(45),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(25),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(2),
    ks_level: DecompositionLevelCount(8),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -128.142,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-128.139 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_160_S126_2M128_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        decomp_base_log: DecompositionBaseLog(3),
        decomp_level_count: DecompositionLevelCount(32),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.160_128_128.bootstrap_cost.ref.json
/// p-fail = 2^-129.142, 2-norm = 5, 160 bits of security
pub const ZOPT_KS64_160_S126_2M128_BOOTSTRAP_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1043),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(25),
    pbs_base_log: DecompositionBaseLog(13),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(16),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -129.142,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-129.142 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_160_S126_2M128_BOOTSTRAP_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(3),
        polynomial_size: PolynomialSize(2048),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        decomp_base_log: DecompositionBaseLog(3),
        decomp_level_count: DecompositionLevelCount(32),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.160_160_160.ref.json
/// p-fail = 2^-164.643, 2-norm = 5, 160 bits of security
pub const ZOPT_KS64_160_S125_2M160_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1043),
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
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -164.643,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-164.643 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_160_S125_2M160_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        decomp_base_log: DecompositionBaseLog(2),
        decomp_level_count: DecompositionLevelCount(47),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// zopt experiments/blockchain_ks64/circuit.160_160_160.bootstrap_cost.ref.json
/// p-fail = 2^-160.007, 2-norm = 5, 160 bits of security
pub const ZOPT_KS64_160_S125_2M160_BOOTSTRAP_COST: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(997),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(47),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(1),
    ks_level: DecompositionLevelCount(15),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -160.007,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
};

/// p-fail = 2^-160.007 (squashing and packing), keys at 2^128
pub const ZOPT_KS64_NS_160_S125_2M160_BOOTSTRAP_COST: NoiseSquashingParameters =
    NoiseSquashingParameters::Classic(NoiseSquashingClassicParameters {
        glwe_dimension: GlweDimension(2),
        polynomial_size: PolynomialSize(4096),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(3),
        decomp_base_log: DecompositionBaseLog(2),
        decomp_level_count: DecompositionLevelCount(47),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
        message_modulus: MessageModulus(4),
        carry_modulus: CarryModulus(4),
        ciphertext_modulus: CoreCiphertextModulus::<u128>::new_native(),
    });

/// The compute and noise squashing parameters of each solution, with the name of the
/// compute parameters.
pub const ZOPT_KS64_PARAMS: [(ClassicPBSParameters, NoiseSquashingParameters, &str); 10] = [
    (
        ZOPT_KS64_132_S80_2M128_COST,
        ZOPT_KS64_NS_132_S80_2M128_COST,
        "ZOPT_KS64_132_S80_2M128_COST",
    ),
    (
        ZOPT_KS64_132_S80_2M128_BOOTSTRAP_COST,
        ZOPT_KS64_NS_132_S80_2M128_BOOTSTRAP_COST,
        "ZOPT_KS64_132_S80_2M128_BOOTSTRAP_COST",
    ),
    (
        ZOPT_KS64_132_S80_2M160_COST,
        ZOPT_KS64_NS_132_S80_2M160_COST,
        "ZOPT_KS64_132_S80_2M160_COST",
    ),
    (
        ZOPT_KS64_132_S80_2M160_BOOTSTRAP_COST,
        ZOPT_KS64_NS_132_S80_2M160_BOOTSTRAP_COST,
        "ZOPT_KS64_132_S80_2M160_BOOTSTRAP_COST",
    ),
    (
        ZOPT_KS64_160_S80_2M128_COST,
        ZOPT_KS64_NS_160_S80_2M128_COST,
        "ZOPT_KS64_160_S80_2M128_COST",
    ),
    (
        ZOPT_KS64_160_S80_2M128_BOOTSTRAP_COST,
        ZOPT_KS64_NS_160_S80_2M128_BOOTSTRAP_COST,
        "ZOPT_KS64_160_S80_2M128_BOOTSTRAP_COST",
    ),
    (
        ZOPT_KS64_160_S126_2M128_COST,
        ZOPT_KS64_NS_160_S126_2M128_COST,
        "ZOPT_KS64_160_S126_2M128_COST",
    ),
    (
        ZOPT_KS64_160_S126_2M128_BOOTSTRAP_COST,
        ZOPT_KS64_NS_160_S126_2M128_BOOTSTRAP_COST,
        "ZOPT_KS64_160_S126_2M128_BOOTSTRAP_COST",
    ),
    (
        ZOPT_KS64_160_S125_2M160_COST,
        ZOPT_KS64_NS_160_S125_2M160_COST,
        "ZOPT_KS64_160_S125_2M160_COST",
    ),
    (
        ZOPT_KS64_160_S125_2M160_BOOTSTRAP_COST,
        ZOPT_KS64_NS_160_S125_2M160_BOOTSTRAP_COST,
        "ZOPT_KS64_160_S125_2M160_BOOTSTRAP_COST",
    ),
];
