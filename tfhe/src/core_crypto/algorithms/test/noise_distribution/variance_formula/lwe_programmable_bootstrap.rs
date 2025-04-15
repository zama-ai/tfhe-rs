use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::*;

pub fn pbs_variance_132_bits_security_gaussian(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    ciphertext_modulus: f64,
    ntt_modulus: f64,
) -> Variance {
    let var_min = super::secure_noise::minimal_glwe_variance_for_132_bits_security_gaussian(
        glwe_dimension,
        polynomial_size,
        ciphertext_modulus,
    );
    Variance(pbs_variance_impl(
        lwe_dimension.0 as f64,
        glwe_dimension.0 as f64,
        polynomial_size.0 as f64,
        var_min.0 as f64,
        decomposition_level_count.0 as f64,
        decomposition_base_log.0 as f64,
        ciphertext_modulus,
        ntt_modulus,
    ))
}

pub fn pbs_variance_132_bits_security_tuniform(
    lwe_dimension: LweDimension,
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    ciphertext_modulus: f64,
    ntt_modulus: f64,
) -> Variance {
    let var_min = super::secure_noise::minimal_glwe_variance_for_132_bits_security_tuniform(
        glwe_dimension,
        polynomial_size,
        ciphertext_modulus,
    );
    Variance(pbs_variance_impl(
        lwe_dimension.0 as f64,
        glwe_dimension.0 as f64,
        polynomial_size.0 as f64,
        var_min.0 as f64,
        decomposition_level_count.0 as f64,
        decomposition_base_log.0 as f64,
        ciphertext_modulus,
        ntt_modulus,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn pbs_variance_impl(
    lwe_dimension: f64,
    glwe_dimension: f64,
    polynomial_size: f64,
    var_min: f64,
    decomposition_level_count: f64,
    decomposition_base_log: f64,
    ciphertext_modulus: f64,
    ntt_modulus: f64,
) -> f64 {
    let pow2_2b = (2.0 * decomposition_base_log).exp2();
    let pow2_bl = (decomposition_level_count * decomposition_base_log).exp2();
    let ntt2q_factor =
        ciphertext_modulus.powf(-2.0) + (ciphertext_modulus * ntt_modulus).powf(-2.0);
    let q2ntt_factor = ntt_modulus.powf(-2.0) + 2.0 * (ciphertext_modulus * ntt_modulus).powf(-2.0);
    let var_ntt_to_q = glwe_dimension * polynomial_size / 24.0 * ntt2q_factor + ntt2q_factor / 12.0;
    let var_q_to_ntt = glwe_dimension * polynomial_size / 24.0 * q2ntt_factor + q2ntt_factor / 12.0;
    let var_modswitch = (1.0 + (glwe_dimension * polynomial_size) / 2.0)
        * (pow2_bl.powf(-2.0) + 2.0 * ciphertext_modulus.powf(-2.0))
        / 12.0;
    let var_ext_product = decomposition_level_count
        * (glwe_dimension + 1.0)
        * polynomial_size
        * ((pow2_2b / 12.0 + 1.0 / 6.0)
            * (var_min + var_q_to_ntt * ciphertext_modulus.powf(2.0) * ntt_modulus.powf(-2.0)))
        + var_modswitch / 2.0
        + var_ntt_to_q;
    println!(
        "PBS components var_modswitch {var_modswitch:?} var_ext_product {var_ext_product:?} lwe_dimension {lwe_dimension}");
    lwe_dimension * var_ext_product
}
