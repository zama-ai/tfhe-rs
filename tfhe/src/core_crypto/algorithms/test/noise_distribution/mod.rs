use super::*;

mod lwe_encryption_noise;
mod lwe_keyswitch_noise;
mod lwe_multi_bit_programmable_bootstrapping_noise;
mod lwe_programmable_bootstrapping_noise;
mod pfail_multi_bit;

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
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(837),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.3747142481837397e-06,
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
    thread_count: ThreadCount(8),
};
#[allow(clippy::excessive_precision)]
pub const PFAIL_TEST_PARAMS_MULTI_BIT_GROUP_3_6_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(522),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0007736698118352694,
    )),
    decomp_base_log: DecompositionBaseLog(21),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(4096),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.0000000000000000002168404344971009,
    )),
    message_modulus_log: MessageModulusLog(6),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(8),
};
