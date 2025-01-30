// This file was autogenerated, do not modify by hand.
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::*;

/// This formula is only valid if the proper noise distributions are used and
/// if the keys used are encrypted using secure noise given by the
/// [`minimal_glwe_variance`](`super::secure_noise`)
/// and [`minimal_lwe_variance`](`super::secure_noise`) family of functions.
pub fn pbs_variance_132_bits_security_gaussian(
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    modulus: f64,
) -> Variance {
    Variance(pbs_variance_132_bits_security_gaussian_impl(
        input_lwe_dimension.0 as f64,
        output_glwe_dimension.0 as f64,
        output_polynomial_size.0 as f64,
        2.0f64.powi(decomposition_base_log.0 as i32),
        decomposition_level_count.0 as f64,
        modulus,
    ))
}

/// This formula is only valid if the proper noise distributions are used and
/// if the keys used are encrypted using secure noise given by the
/// [`minimal_glwe_variance`](`super::secure_noise`)
/// and [`minimal_lwe_variance`](`super::secure_noise`) family of functions.
#[allow(clippy::suspicious_operation_groupings)]
pub fn pbs_variance_132_bits_security_gaussian_impl(
    input_lwe_dimension: f64,
    output_glwe_dimension: f64,
    output_polynomial_size: f64,
    decomposition_base: f64,
    decomposition_level_count: f64,
    modulus: f64,
) -> f64 {
    input_lwe_dimension
        * (0.00705585707451537
            * (2.88539008177793 * decomposition_base.ln() - 2.88539008177793 * modulus.ln()
                + 2.0 * 0.0f64.max(core::f64::consts::LOG2_E * modulus.ln() - 53.0))
            .exp2()
            * decomposition_level_count.powf(1.01827580069378)
            * output_glwe_dimension.powf(1.22003417682341)
            * output_polynomial_size.powf(2.22003417682341)
            * (output_glwe_dimension + 1.0).powf(1.01827580069378)
            + decomposition_level_count
                * output_polynomial_size
                * ((4.0 - 2.88539008177793 * modulus.ln()).exp2()
                    + (-0.0497829131652661 * output_glwe_dimension * output_polynomial_size
                        + 5.31469187675068)
                        .exp2())
                * ((1_f64 / 12.0) * decomposition_base.powf(2.0) + 0.166666666666667)
                * (output_glwe_dimension + 1.0)
            + (1_f64 / 12.0) * modulus.powf(-2.0)
            + (1_f64 / 2.0)
                * output_glwe_dimension
                * output_polynomial_size
                * (0.0208333333333333 * modulus.powf(-2.0)
                    + 0.0416666666666667
                        * decomposition_base.powf(-2.0 * decomposition_level_count))
            + (1_f64 / 24.0) * decomposition_base.powf(-2.0 * decomposition_level_count))
}

/// This formula is only valid if the proper noise distributions are used and
/// if the keys used are encrypted using secure noise given by the
/// [`minimal_glwe_variance`](`super::secure_noise`)
/// and [`minimal_lwe_variance`](`super::secure_noise`) family of functions.
pub fn pbs_variance_132_bits_security_tuniform(
    input_lwe_dimension: LweDimension,
    output_glwe_dimension: GlweDimension,
    output_polynomial_size: PolynomialSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    modulus: f64,
) -> Variance {
    Variance(pbs_variance_132_bits_security_tuniform_impl(
        input_lwe_dimension.0 as f64,
        output_glwe_dimension.0 as f64,
        output_polynomial_size.0 as f64,
        2.0f64.powi(decomposition_base_log.0 as i32),
        decomposition_level_count.0 as f64,
        modulus,
    ))
}

/// This formula is only valid if the proper noise distributions are used and
/// if the keys used are encrypted using secure noise given by the
/// [`minimal_glwe_variance`](`super::secure_noise`)
/// and [`minimal_lwe_variance`](`super::secure_noise`) family of functions.
#[allow(clippy::suspicious_operation_groupings)]
pub fn pbs_variance_132_bits_security_tuniform_impl(
    input_lwe_dimension: f64,
    output_glwe_dimension: f64,
    output_polynomial_size: f64,
    decomposition_base: f64,
    decomposition_level_count: f64,
    modulus: f64,
) -> f64 {
    input_lwe_dimension
        * (0.00705585707451537
            * (2.88539008177793 * decomposition_base.ln() - 2.88539008177793 * modulus.ln()
                + 2.0 * 0.0f64.max(core::f64::consts::LOG2_E * modulus.ln() - 53.0))
            .exp2()
            * decomposition_level_count.powf(1.01827580069378)
            * output_glwe_dimension.powf(1.22003417682341)
            * output_polynomial_size.powf(2.22003417682341)
            * (output_glwe_dimension + 1.0).powf(1.01827580069378)
            + decomposition_level_count
                * output_polynomial_size
                * ((4.0 - 2.88539008177793 * modulus.ln()).exp2()
                    + (1_f64 / 3.0)
                        * modulus.powf(-2.0)
                        * ((2.0
                            * (-0.025167785 * output_glwe_dimension * output_polynomial_size
                                + core::f64::consts::LOG2_E * modulus.ln()
                                + 4.10067100000001)
                                .ceil())
                        .exp2()
                            + 0.5))
                * ((1_f64 / 12.0) * decomposition_base.powf(2.0) + 0.166666666666667)
                * (output_glwe_dimension + 1.0)
            + (1_f64 / 12.0) * modulus.powf(-2.0)
            + (1_f64 / 2.0)
                * output_glwe_dimension
                * output_polynomial_size
                * (0.0208333333333333 * modulus.powf(-2.0)
                    + 0.0416666666666667
                        * decomposition_base.powf(-2.0 * decomposition_level_count))
            + (1_f64 / 24.0) * decomposition_base.powf(-2.0 * decomposition_level_count))
}
