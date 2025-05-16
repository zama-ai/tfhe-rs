use crate::core_crypto::commons::dispersion::Variance;
use crate::core_crypto::commons::parameters::*;

pub fn keyswitch_additive_variance_132_bits_security_gaussian(
    input_glwe_dimension: GlweDimension,
    input_polynomial_size: PolynomialSize,
    output_lwe_dimension: LweDimension,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    ksk_modulus: f64,
    ct_modulus: f64,
) -> (Variance, Variance) {
    let var_min = super::secure_noise::minimal_lwe_variance_for_132_bits_security_gaussian(
        output_lwe_dimension,
        ksk_modulus,
    );
    let (var_ks, var_modswitch) = keyswitch_additive_variance_impl(
        input_glwe_dimension.0 as f64,
        input_polynomial_size.0 as f64,
        output_lwe_dimension.0 as f64,
        var_min.0,
        decomposition_level_count.0 as f64,
        decomposition_base_log.0 as i32,
        ksk_modulus,
        ct_modulus,
    );
    (Variance(var_ks), Variance(var_modswitch))
}

pub fn keyswitch_additive_variance_132_bits_security_tuniform(
    input_glwe_dimension: GlweDimension,
    input_polynomial_size: PolynomialSize,
    output_lwe_dimension: LweDimension,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    ksk_modulus: f64,
    ct_modulus: f64,
) -> (Variance, Variance) {
    let var_min = super::secure_noise::minimal_lwe_variance_for_132_bits_security_tuniform(
        output_lwe_dimension,
        ksk_modulus,
    );
    let (var_ks, var_modswitch) = keyswitch_additive_variance_impl(
        input_glwe_dimension.0 as f64,
        input_polynomial_size.0 as f64,
        output_lwe_dimension.0 as f64,
        var_min.0,
        decomposition_level_count.0 as f64,
        decomposition_base_log.0 as i32,
        ksk_modulus,
        ct_modulus,
    );
    (Variance(var_ks), Variance(var_modswitch))
}

#[allow(clippy::too_many_arguments)]
pub fn keyswitch_additive_variance_impl(
    input_glwe_dimension: f64,
    input_polynomial_size: f64,
    output_lwe_dimension: f64,
    var_min: f64,
    decomposition_level_count: f64,
    decomposition_base_log: i32,
    ksk_modulus: f64,
    ct_modulus: f64,
) -> (f64, f64) {
    //let decomposition_base = 2.0f64.powi(decomposition_base_log.0 as i32);
    let pow2_2bl = 2.0f64.powi(2 * (decomposition_level_count as i32) * decomposition_base_log);
    let ks_0 = ((input_glwe_dimension * input_polynomial_size) / 2.0)
        * (1.0 / pow2_2bl + 2.0 * ct_modulus.powf(-2.0))
        / 12.0;
    let ks_1 = (2.0 * ct_modulus.powf(-2.0) + ksk_modulus.powf(-2.0)) / 12.0;
    let ks_2 = var_min
        * (input_glwe_dimension * input_polynomial_size)
        * decomposition_level_count
        * (2.0f64.powi(2 * decomposition_base_log) + 2.0)
        / 12.0;

    let var_modswitch = (1.0 + output_lwe_dimension / 2.0)
        * ((2.0 * input_polynomial_size).powf(-2.0) + 2.0 * ksk_modulus.powf(-2.0))
        / 12.0;

    println!(
        "KS ad var {:?} + {:?} + {:?} = {:?} / mod switch KS-2N {:?}",
        ks_0,
        ks_1,
        ks_2,
        ks_0 + ks_1 + ks_2,
        var_modswitch
    );
    //ks_0 + ks_1 + ks_2 + var_modswitch
    (ks_0 + ks_1 + ks_2, var_modswitch)
}
