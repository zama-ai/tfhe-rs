use crate::gaussian_noise::conversion::modular_variance_to_variance;
use crate::utils::square;

// packing private keyswitch for WoP-PBS, described in algorithm 3 of https://eprint.iacr.org/2018/421.pdf (TFHE paper)
pub fn estimate_packing_private_keyswitch(
    var_glwe: f64,
    var_ggsw: f64,
    log2_base: u64,
    level: u64,
    output_glwe_dimension: u64,
    output_polynomial_size: u64,
    ciphertext_modulus_log: u32,
) -> f64 {
    let variance_key_coefficient_binary: f64 = 1. / 4.;
    let expectation_key_coefficient_binary: f64 = 1. / 2.;

    let l = level as f64;
    let b = 2f64.powi(log2_base as i32);
    let n = (output_glwe_dimension * output_polynomial_size) as f64; // param.internal_lwe_dimension.0 as f64;
    let b2l = f64::powi(b, 2 * level as i32);
    let var_s_w = 1. / 4.;
    let mean_s_w = 1. / 2.;
    let res_1 = l * (n + 1.) * var_ggsw * (square(b) + 2.) / 12.;

    #[allow(clippy::cast_possible_wrap)]
    let res_3 = (f64::powi(2., 2 * ciphertext_modulus_log as i32) - b2l) / (12. * b2l)
        * modular_variance_to_variance(
            1. + n * variance_key_coefficient_binary + square(expectation_key_coefficient_binary),
            ciphertext_modulus_log,
        )
        + n / 4.
            * modular_variance_to_variance(variance_key_coefficient_binary, ciphertext_modulus_log)
        + var_glwe * (var_s_w + square(mean_s_w));

    let res_5 = modular_variance_to_variance(var_s_w, ciphertext_modulus_log) * 1. / 4.
        * square(1. - n * expectation_key_coefficient_binary);

    res_1 + res_3 + res_5
}
