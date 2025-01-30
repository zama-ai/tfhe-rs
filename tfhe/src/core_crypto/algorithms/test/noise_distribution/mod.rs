use super::*;

pub(crate) mod lwe_encryption_noise;
mod lwe_hpu_noise;
mod lwe_keyswitch_noise;
// We are having crashes on aarch64 at the moment, problem is the code paths are not the same
// between archs, so we disable those on the Apple M1
#[cfg(not(target_arch = "aarch64"))]
mod lwe_multi_bit_programmable_bootstrapping_noise;
mod lwe_programmable_bootstrapping_noise;
mod variance_formula;

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

// ----    GAUSSIAN    ---------------------------------------------------------

#[allow(clippy::excessive_precision)]
#[allow(dead_code)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_2_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(759),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.296274149494132e-05,
    )),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.845267479601915e-15,
    )),
    message_modulus_log: MessageModulusLog(2),
    ciphertext_modulus: CiphertextModulus::new_native(),
    grouping_factor: LweBskGroupingFactor(3),
    thread_count: ThreadCount(12),
};

// Tests currently disabled on M1
#[allow(clippy::excessive_precision)]
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_4_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(912),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.252442079345288e-07,
    )),
    decomp_base_log: DecompositionBaseLog(22),
    decomp_level_count: DecompositionLevelCount(1),
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
#[allow(dead_code)]
pub const NOISE_TEST_PARAMS_MULTI_BIT_GROUP_3_6_BITS_NATIVE_U64_132_BITS_GAUSSIAN:
    MultiBitTestParams<u64> = MultiBitTestParams {
    input_lwe_dimension: LweDimension(978),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        2.962875621642539e-07,
    )),
    decomp_base_log: DecompositionBaseLog(14),
    decomp_level_count: DecompositionLevelCount(2),
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
