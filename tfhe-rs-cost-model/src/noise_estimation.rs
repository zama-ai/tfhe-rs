use concrete_cpu_noise_model::gaussian_noise;
use tfhe::core_crypto::commons::dispersion::DispersionParameter;
use tfhe::core_crypto::prelude::*;

pub fn classic_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe<D1>(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    ggsw_noise: D1,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
{
    Variance(
        gaussian_noise::noise::external_product_glwe::theoretical_variance_external_product_glwe(
            glwe_dimension.0 as u64,
            polynomial_size.0 as u64,
            base_log.0 as u64,
            level.0 as u64,
            log2_modulus,
            ggsw_noise.get_variance(),
        ),
    )
}

pub fn multi_bit_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe<D1>(
    polynomial_size: PolynomialSize,
    glwe_dimension: GlweDimension,
    ggsw_noise: D1,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    log2_modulus: u32,
    grouping_factor: LweBskGroupingFactor,
) -> Variance
where
    D1: DispersionParameter,
{
    Variance(
            gaussian_noise::noise::multi_bit_external_product_glwe::theoretical_variance_multi_bit_external_product_glwe(
                glwe_dimension.0 as u64,
                polynomial_size.0 as u64,
                base_log.0 as u64,
                level.0 as u64,
                log2_modulus,
                ggsw_noise.get_variance(),
                grouping_factor.0 as u32,
            ),
        )
}
