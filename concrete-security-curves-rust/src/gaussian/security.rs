use super::curves_gen::SECURITY_WEIGHTS_ARRAY;
use super::security_weights::SecurityWeights;

pub fn supported_security_levels() -> impl std::iter::Iterator<Item = u64> {
    SECURITY_WEIGHTS_ARRAY
        .iter()
        .map(|(security_level, _)| *security_level)
}

pub fn security_weight(security_level: u64) -> Option<SecurityWeights> {
    let index = SECURITY_WEIGHTS_ARRAY
        .binary_search_by_key(&security_level, |(security_level, _weights)| {
            *security_level
        })
        .ok()?;

    Some(SECURITY_WEIGHTS_ARRAY[index].1)
}

/// Noise ensuring security
pub fn minimal_variance_lwe(
    lwe_dimension: u64,
    ciphertext_modulus_log: u32,
    security_level: u64,
) -> f64 {
    minimal_variance_glwe(lwe_dimension, 1, ciphertext_modulus_log, security_level)
}

/// Noise ensuring security
pub fn minimal_variance_glwe(
    glwe_dimension: u64,
    polynomial_size: u64,
    ciphertext_modulus_log: u32,
    security_level: u64,
) -> f64 {
    let equiv_lwe_dimension = glwe_dimension * polynomial_size;
    let security_weights = security_weight(security_level)
        .unwrap_or_else(|| panic!("{security_level} bits of security is not supported"));

    let secure_log2_std =
        security_weights.secure_log2_std(equiv_lwe_dimension, ciphertext_modulus_log as f64);
    let log2_var = 2.0 * secure_log2_std;
    f64::exp2(log2_var)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let weight = security_weight(128).unwrap();

        let secure_log_2_std = weight.secure_log2_std(512, 64.);

        assert!((-12.0..-10.0).contains(&secure_log_2_std));
    }

    #[test]
    fn security_security_glwe_variance_low() {
        let integer_size = 64;
        let golden_std_dev = 2.168_404_344_971_009e-19;
        let security_level = 128;

        let actual_var = minimal_variance_glwe(10, 1 << 14, integer_size, security_level);
        let actual_std_dev = actual_var.sqrt();
        let expected_std_dev = (0.99 * golden_std_dev)..(1.01 * golden_std_dev);
        assert!(expected_std_dev.contains(&actual_std_dev));
    }

}
