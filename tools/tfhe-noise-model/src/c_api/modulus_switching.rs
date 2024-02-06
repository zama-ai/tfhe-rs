use crate::gaussian_noise::noise::modulus_switching::estimate_modulus_switching_noise_with_binary_key;

#[no_mangle]
pub extern "C" fn concrete_cpu_estimate_modulus_switching_noise_with_binary_key(
    internal_ks_output_lwe_dimension: u64,
    glwe_log2_polynomial_size: u64,
    ciphertext_modulus_log: u32,
) -> f64 {
    estimate_modulus_switching_noise_with_binary_key(
        internal_ks_output_lwe_dimension,
        glwe_log2_polynomial_size,
        ciphertext_modulus_log,
    )
}
