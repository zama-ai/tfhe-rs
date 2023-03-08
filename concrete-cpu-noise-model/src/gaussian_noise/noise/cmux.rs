use super::external_product_glwe::variance_external_product_glwe;

// only valid in the blind rotate case
pub fn variance_cmux(
    glwe_dimension: u64,
    polynomial_size: u64,
    log2_base: u64,
    level: u64,
    ciphertext_modulus_log: u32,
    variance_ggsw: f64,
) -> f64 {
    variance_external_product_glwe(
        glwe_dimension,
        polynomial_size,
        log2_base,
        level,
        ciphertext_modulus_log,
        variance_ggsw,
    )
}
