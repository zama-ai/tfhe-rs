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

/// Waits until `ZOPT_KS64_BARRIER_N` processes reach the barrier of `id` in the directory
/// `ZOPT_KS64_BARRIER_DIR` (no-op without it), so that the processes of a per-NUMA-node
/// run measure the same set at the same time.
pub fn zopt_ks64_barrier(id: &str) {
    let Ok(dir) = std::env::var("ZOPT_KS64_BARRIER_DIR") else {
        return;
    };
    let n: usize = std::env::var("ZOPT_KS64_BARRIER_N")
        .expect("ZOPT_KS64_BARRIER_N")
        .parse()
        .expect("ZOPT_KS64_BARRIER_N");
    let prefix: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    // The tag differs between the processes: drop it from the barrier name.
    let prefix = match std::env::var("ZOPT_KS64_TAG") {
        Ok(tag) if !tag.is_empty() => prefix.replace(&tag, ""),
        _ => prefix,
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{prefix}.{}", std::process::id())), b"").unwrap();
    loop {
        let arrived = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{prefix}."))
            })
            .count();
        if arrived >= n {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The batch size recorded for `id` in the file `ZOPT_HL_BATCH_FILE`, or `compute()`'s,
/// recorded there, so that the runs of several NUMA placements measure the same batch.
/// Without the variable, `compute()`.
pub fn zopt_recorded_batch(id: &str, compute: impl FnOnce() -> u64) -> u64 {
    let Ok(path) = std::env::var("ZOPT_HL_BATCH_FILE") else {
        return compute();
    };
    let recorded = std::fs::read_to_string(&path).unwrap_or_default();
    if let Some(batch) = recorded
        .lines()
        .filter_map(|line| line.rsplit_once(' '))
        .find(|(name, _)| *name == id)
        .and_then(|(_, batch)| batch.parse().ok())
    {
        println!("zopt batch {id}: {batch} (recorded)");
        return batch;
    }
    let batch = compute();
    println!("zopt batch {id}: {batch}");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut file, format!("{id} {batch}\n").as_bytes()).unwrap();
    batch
}
