use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::*;

pub fn minimal_glwe_variance_for_128_bits_security_gaussian(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    modulus: f64,
) -> Variance {
    let lwe_dimension = glwe_dimension.to_equivalent_lwe_dimension(polynomial_size);
    minimal_lwe_variance_for_128_bits_security_gaussian(lwe_dimension, modulus)
}

pub fn minimal_lwe_variance_for_128_bits_security_gaussian(
    lwe_dimension: LweDimension,
    modulus: f64,
) -> Variance {
    Variance(minimal_variance_for_128_bits_security_gaussian_impl(
        lwe_dimension.0 as f64,
        modulus,
    ))
}

pub fn minimal_variance_for_128_bits_security_gaussian_impl(
    lwe_dimension: f64,
    modulus: f64,
) -> f64 {
    // 128b curve
    //let slope2=-0.05139355742296919;
    //let biais2=5.351862745098032;
    // 132b curve
    let slope2=-0.04978291316526609;
    let biais2=5.31469187675068;
    let f=slope2*lwe_dimension+biais2;
    let g=2.0*(2.0-modulus.log2().ceil());
    ((f+g)/2.0+(f-g).abs()/2.0).exp2()
}
