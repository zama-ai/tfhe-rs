use crate::gaussian_noise::noise::blind_rotate::variance_blind_rotate;

#[no_mangle]
pub extern "C" fn concrete_cpu_variance_blind_rotate(
    in_lwe_dimension: u64,
    out_glwe_dimension: u64,
    out_polynomial_size: u64,
    log2_base: u64,
    level: u64,
    ciphertext_modulus_log: u32,
    fft_precision: u32,
    variance_bsk: f64,
) -> f64 {
    variance_blind_rotate(
        in_lwe_dimension,
        out_glwe_dimension,
        out_polynomial_size,
        log2_base,
        level,
        ciphertext_modulus_log,
        fft_precision,
        variance_bsk,
    )
}
