use crate::boolean::parameters::BooleanParameters;
use crate::core_crypto::prelude::*;
/// Default parameter set.
///
/// This parameter set ensures 132-bits of security, and a probability of error is upper-bounded by
/// $2^{-64}$. The secret keys generated with this parameter set are uniform binary.
/// This parameter set allows to evaluate faster Boolean circuits than the `TFHE_LIB_PARAMETERS`
/// one.
// p-fail = 2^-64.344, algorithmic cost ~ 75, 2-norm = 2.8284271247461903
pub const DEFAULT_PARAMETERS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(805),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    #[allow(clippy::excessive_precision)]
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        5.8615896642671336e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.315272083503367e-10,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
// p-fail = 2^-64.017, algorithmic cost ~ 67, 2-norm = 2.8284271247461903
pub const DEFAULT_PARAMETERS_KS_PBS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(739),
    glwe_dimension: GlweDimension(3),
    polynomial_size: PolynomialSize(512),
    #[allow(clippy::excessive_precision)]
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.8304520733507305e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.315272083503367e-10,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(4),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
// p-fail = 2^-165.434, algorithmic cost ~ 117, 2-norm = 2.8284271247461903
pub const PARAMETERS_ERROR_PROB_2_POW_MINUS_165: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(837),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    #[allow(clippy::excessive_precision)]
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        3.374714376692653e-06,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.313225746198247e-10,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    encryption_key_choice: EncryptionKeyChoice::Small,
};
// p-fail = 2^-166.826, algorithmic cost ~ 108, 2-norm = 2.8284271247461903
pub const PARAMETERS_ERROR_PROB_2_POW_MINUS_165_KS_PBS: BooleanParameters = BooleanParameters {
    lwe_dimension: LweDimension(770),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    #[allow(clippy::excessive_precision)]
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        1.0721931696480342e-05,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        9.313225746198247e-10,
    )),
    pbs_base_log: DecompositionBaseLog(10),
    pbs_level: DecompositionLevelCount(2),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    encryption_key_choice: EncryptionKeyChoice::Big,
};
