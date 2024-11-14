use super::*;

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
#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_GPU_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(909),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.743962418842028e-07,
    )),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(1),
};

#[allow(clippy::excessive_precision)]
pub const NOISE_TEST_PARAMS_GPU_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_TUNIFORM:
    MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(879),
    lwe_noise_distribution: DynamicDistribution::new_t_uniform(46),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    glwe_noise_distribution: DynamicDistribution::new_t_uniform(17),
    message_modulus_log: MessageModulusLog(4),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(1),
};
