// This file was autogenerated, do not modify by hand.
use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::*;

pub fn minimal_glwe_variance_for_132_bits_security_gaussian(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    modulus: f64,
) -> Variance {
    let lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    minimal_lwe_variance_for_132_bits_security_gaussian(lwe_dimension, modulus)
}

pub fn minimal_lwe_variance_for_132_bits_security_gaussian(
    lwe_dimension: LweDimension,
    modulus: f64,
) -> Variance {
    Variance(minimal_variance_for_132_bits_security_gaussian_impl(
        lwe_dimension.0 as f64,
        modulus,
    ))
}

pub fn minimal_variance_for_132_bits_security_gaussian_impl(
    lwe_dimension: f64,
    modulus: f64,
) -> f64 {
    (4.0 - 2.88539008177793 * modulus.ln()).exp2()
        + (5.31469187675068 - 0.0497829131652661 * lwe_dimension).exp2()
}

pub fn minimal_glwe_variance_for_132_bits_security_tuniform(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    modulus: f64,
) -> Variance {
    let lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    minimal_lwe_variance_for_132_bits_security_tuniform(lwe_dimension, modulus)
}

pub fn minimal_lwe_variance_for_132_bits_security_tuniform(
    lwe_dimension: LweDimension,
    modulus: f64,
) -> Variance {
    Variance(minimal_variance_for_132_bits_security_tuniform_impl(
        lwe_dimension.0 as f64,
        modulus,
    ))
}

pub fn minimal_variance_for_132_bits_security_tuniform_impl(
    lwe_dimension: f64,
    modulus: f64,
) -> f64 {
    (4.0 - 2.88539008177793 * modulus.ln()).exp2()
        + (1_f64 / 3.0)
            * modulus.powf(-2.0)
            * ((2.0
                * (-0.025167785 * lwe_dimension
                    + core::f64::consts::LOG2_E * modulus.ln()
                    + 4.10067100000001)
                    .ceil())
            .exp2()
                + 0.5)
}

pub fn minimal_glwe_bound_for_132_bits_security_tuniform(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    modulus: f64,
) -> u32 {
    let lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    minimal_lwe_bound_for_132_bits_security_tuniform(lwe_dimension, modulus)
}

pub fn minimal_lwe_bound_for_132_bits_security_tuniform(
    lwe_dimension: LweDimension,
    modulus: f64,
) -> u32 {
    minimal_bound_for_132_bits_security_tuniform_impl(lwe_dimension.0 as f64, modulus)
}

pub fn minimal_bound_for_132_bits_security_tuniform_impl(lwe_dimension: f64, modulus: f64) -> u32 {
    (-0.025167785 * lwe_dimension + core::f64::consts::LOG2_E * modulus.ln() + 4.10067100000001)
        .ceil() as u32
}
