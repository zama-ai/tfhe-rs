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

#[allow(clippy::manual_midpoint)]
pub fn minimal_variance_for_132_bits_security_gaussian_impl(
    lwe_dimension: f64,
    modulus: f64,
) -> f64 {
    // 128b curve
    //let slope2=-0.05139355742296919;
    //let biais2=5.351862745098032;
    // 132b curve
    let slope2 = -0.04978291316526609;
    let biais2 = 5.31469187675068;
    let f = slope2 * lwe_dimension + biais2;
    let g = 2.0 * (2.0 - modulus.log2().ceil());
    ((f + g) / 2.0 + (f - g).abs() / 2.0).exp2()
}

pub fn minimal_variance_for_132_bits_security_tuniform_impl(
    lwe_dimension: f64,
    modulus: f64,
) -> f64 {
    let log2_modulus = modulus.log2();
    let epsilon_var_log2 = 2.0 * (2.2 - log2_modulus);
    let slope = -0.025167785;
    let biais = 68.100671;
    let min_bound = (slope * lwe_dimension + biais + (log2_modulus - 64.0)).ceil();
    let theoretical_secure_var_log2 =
        (((2.0 * min_bound + 1.0).exp2() + 1.0) / 6.0).log2() - 2.0 * log2_modulus;
    println!("log2_modulus: {log2_modulus:?} min_bound: {min_bound:?} theoretical_secure_var_log2: {theoretical_secure_var_log2:?}");
    f64::max(theoretical_secure_var_log2.exp2(), epsilon_var_log2.exp2())
}
