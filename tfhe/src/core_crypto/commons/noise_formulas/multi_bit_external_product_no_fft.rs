// This file was autogenerated, do not modify by hand.
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::*;

/// This formula is only valid if the proper noise distributions are used and
/// if the keys used are encrypted using secure noise given by the
/// [`minimal_glwe_variance`](`super::secure_noise`)
/// and [`minimal_lwe_variance`](`super::secure_noise`) family of functions.
pub fn multi_bit_external_product_no_fft_additive_variance_132_bits_security_gaussian(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    grouping_factor: f64,
    modulus: f64,
) -> Variance {
    Variance(
        multi_bit_external_product_no_fft_additive_variance_132_bits_security_gaussian_impl(
            glwe_dimension.0 as f64,
            polynomial_size.0 as f64,
            2.0f64.powi(decomposition_base_log.0 as i32),
            decomposition_level_count.0 as f64,
            grouping_factor,
            modulus,
        ),
    )
}

/// This formula is only valid if the proper noise distributions are used and
/// if the keys used are encrypted using secure noise given by the
/// [`minimal_glwe_variance`](`super::secure_noise`)
/// and [`minimal_lwe_variance`](`super::secure_noise`) family of functions.
pub fn multi_bit_external_product_no_fft_additive_variance_132_bits_security_gaussian_impl(
    glwe_dimension: f64,
    polynomial_size: f64,
    decomposition_base: f64,
    decomposition_level_count: f64,
    grouping_factor: f64,
    modulus: f64,
) -> f64 {
    grouping_factor.exp2()
        * decomposition_level_count
        * polynomial_size
        * ((-0.0497829131652661 * glwe_dimension * polynomial_size + 5.31469187675068).exp2()
            + 16.0 * modulus.powf(-2.0))
        * ((1_f64 / 12.0) * decomposition_base.powf(2.0) + 0.166666666666667)
        * (glwe_dimension + 1.0)
        + (1_f64 / 2.0)
            * glwe_dimension
            * polynomial_size
            * (0.0208333333333333 * modulus.powf(-2.0)
                //JKL 2.0f64*
                + 2.0f64*0.0416666666666667 * decomposition_base.powf(-2.0 * decomposition_level_count)) //JKL remove this term if the GGSW-encrypted value == 0
        + (1_f64 / 12.0) * modulus.powf(-2.0)
        + (1_f64 / 24.0) * decomposition_base.powf(-2.0 * decomposition_level_count)
}
