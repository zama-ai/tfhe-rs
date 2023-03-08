use crate::gaussian_noise::conversion::modular_variance_to_variance;
use crate::utils::square;

pub fn estimate_modulus_switching_noise_with_binary_key(
    internal_ks_output_lwe_dimension: u64,
    glwe_log2_polynomial_size: u64,
    ciphertext_modulus_log: u32,
) -> f64 {
    let nb_msb = glwe_log2_polynomial_size + 1;

    let w = 2_f64.powi(nb_msb as i32);
    let n = internal_ks_output_lwe_dimension as f64;

    (1. / 12. + n / 24.) / square(w)
        + modular_variance_to_variance(-1. / 12. + n / 48., ciphertext_modulus_log)
}
