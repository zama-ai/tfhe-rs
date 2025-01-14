use super::*;

mod lwe_encryption_noise;
mod lwe_keyswitch_noise;
mod lwe_multi_bit_programmable_bootstrapping_noise;
mod lwe_programmable_bootstrapping_noise;

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN: ClassicTestParams<u64> =
    ClassicTestParams {
        lwe_dimension: LweDimension(841),
        glwe_dimension: GlweDimension(1),
        polynomial_size: PolynomialSize(2048),
        lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            3.1496674685772435e-06,
        )),
        glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
            2.845267479601915e-15,
        )),
        pbs_base_log: DecompositionBaseLog(22),
        pbs_level: DecompositionLevelCount(1),
        ks_level: DecompositionLevelCount(5),
        ks_base_log: DecompositionBaseLog(3),
        pfks_level: DecompositionLevelCount(0),
        pfks_base_log: DecompositionBaseLog(0),
        pfks_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0)),
        cbs_level: DecompositionLevelCount(0),
        cbs_base_log: DecompositionBaseLog(0),
        message_modulus_log: MessageModulusLog(4),
        ciphertext_modulus: CiphertextModulus::new_native(),
    };

//TODO FIXME after 3af71b4 in the optimizer, param's changed, not updated here yet:

// ----    GAUSSIAN    ---------------------------------------------------------

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_2_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(256 * 3),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.1098369627275701e-05,
    )),
    pbs_base_log: DecompositionBaseLog(17),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.9524392655548086e-11,
    )),
    message_modulus_log: MessageModulusLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(279 * 3),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.3747142481837397e-06,
    )),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_6_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(326 * 3),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
    )),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.168404344971009e-19,
    )),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

// ----    TUNIFORM    ---------------------------------------------------------

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_2_2_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(400 * 2),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_2_4_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(440 * 2),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_2_6_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(499 * 2),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(2),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_2_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(267 * 3),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(293 * 3),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_6_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(333 * 3),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_4_2_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(200 * 4),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(48),
    pbs_base_log: DecompositionBaseLog(22),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(4),
    polynomial_size: PolynomialSize(512),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(4),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_4_4_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(220 * 4),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    pbs_base_log: DecompositionBaseLog(21),
    pbs_level: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(4),
    thread_count: ThreadCount(12),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_4_6_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    lwe_dimension: LweDimension(250 * 4),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(43),
    pbs_base_log: DecompositionBaseLog(14),
    pbs_level: DecompositionLevelCount(2),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(8192),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(4),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(4),
    thread_count: ThreadCount(12),
};
