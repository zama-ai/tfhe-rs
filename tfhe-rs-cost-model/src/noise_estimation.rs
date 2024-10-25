use tfhe::core_crypto::prelude::*;

pub fn classic_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe<D1>(
    _polynomial_size: PolynomialSize,
    _glwe_dimension: GlweDimension,
    _ggsw_noise: D1,
    _base_log: DecompositionBaseLog,
    _level: DecompositionLevelCount,
    _log2_modulus: u32,
) -> Variance
where
    D1: DispersionParameter,
{
    todo!()
}

pub fn multi_bit_pbs_estimate_external_product_noise_with_binary_ggsw_and_glwe<D1>(
    _polynomial_size: PolynomialSize,
    _glwe_dimension: GlweDimension,
    _ggsw_noise: D1,
    _base_log: DecompositionBaseLog,
    _level: DecompositionLevelCount,
    _log2_modulus: u32,
    _grouping_factor: LweBskGroupingFactor,
) -> Variance
where
    D1: DispersionParameter,
{
    todo!()
}
