fn modular_variance_variance_ratio(ciphertext_modulus_log: u32) -> f64 {
    2_f64.powi(2 * ciphertext_modulus_log as i32)
}

pub fn modular_variance_to_variance(modular_variance: f64, ciphertext_modulus_log: u32) -> f64 {
    modular_variance / modular_variance_variance_ratio(ciphertext_modulus_log)
}

pub fn variance_to_modular_variance(variance: f64, ciphertext_modulus_log: u32) -> f64 {
    variance * modular_variance_variance_ratio(ciphertext_modulus_log)
}

pub fn variance_to_std_dev(variance: f64) -> f64 {
    variance.sqrt()
}
