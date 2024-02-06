use crate::gaussian_noise::noise::keyswitch::variance_keyswitch;

#[no_mangle]
pub extern "C" fn concrete_cpu_variance_keyswitch(
    input_lwe_dimension: u64,
    log2_base: u64,
    level: u64,
    ciphertext_modulus_log: u32,
    variance_ksk: f64,
) -> f64 {
    variance_keyswitch(
        input_lwe_dimension,
        log2_base,
        level,
        ciphertext_modulus_log,
        variance_ksk,
    )
}
