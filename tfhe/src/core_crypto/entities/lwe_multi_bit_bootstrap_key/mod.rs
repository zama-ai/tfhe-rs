//! Module containing the definition of the [`LweMultiBitBootstrapKey`].

pub mod fft128_lwe_multi_bit_bootstrap_key;
pub mod fft64_lwe_multi_bit_bootstrap_key;
pub mod standard_lwe_multi_bit_bootstrap_key;

pub use fft128_lwe_multi_bit_bootstrap_key::Fourier128LweMultiBitBootstrapKey;
pub use fft64_lwe_multi_bit_bootstrap_key::{
    FourierLweMultiBitBootstrapKey, FourierLweMultiBitBootstrapKeyMutView,
    FourierLweMultiBitBootstrapKeyOwned, FourierLweMultiBitBootstrapKeyView,
};
pub use standard_lwe_multi_bit_bootstrap_key::{
    lwe_multi_bit_bootstrap_key_fork_config, LweMultiBitBootstrapKey, LweMultiBitBootstrapKeyOwned,
    MultiBitBootstrapKeyConformanceParams,
};

use crate::core_crypto::commons::parameters::{
    DecompositionLevelCount, GgswCiphertextCount, GlweSize, LweBskGroupingFactor, LweDimension,
    PolynomialSize,
};
use crate::core_crypto::entities::ggsw_ciphertext_list::{
    fourier_ggsw_ciphertext_list_size, ggsw_ciphertext_list_size,
};

pub fn equivalent_multi_bit_lwe_dimension(
    input_lwe_dimension: LweDimension,
    grouping_factor: LweBskGroupingFactor,
) -> Result<LweDimension, &'static str> {
    if input_lwe_dimension.0 % grouping_factor.0 != 0 {
        return Err("equivalent_multi_bit_lwe_dimension error: \
        input_lwe_dimension is required to be a multiple of grouping_factor");
    }

    Ok(LweDimension(input_lwe_dimension.0 / grouping_factor.0))
}

pub fn lwe_multi_bit_bootstrap_key_size(
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
) -> Result<usize, &'static str> {
    let equivalent_multi_bit_lwe_dimension =
        equivalent_multi_bit_lwe_dimension(input_lwe_dimension, grouping_factor)?;
    let ggsw_count =
        equivalent_multi_bit_lwe_dimension.0 * grouping_factor.ggsw_per_multi_bit_element().0;

    Ok(ggsw_ciphertext_list_size(
        GgswCiphertextCount(ggsw_count),
        glwe_size,
        polynomial_size,
        decomp_level_count,
    ))
}

pub fn fourier_lwe_multi_bit_bootstrap_key_size(
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
) -> Result<usize, &'static str> {
    let equivalent_multi_bit_lwe_dimension =
        equivalent_multi_bit_lwe_dimension(input_lwe_dimension, grouping_factor)?;
    let ggsw_count =
        equivalent_multi_bit_lwe_dimension.0 * grouping_factor.ggsw_per_multi_bit_element().0;

    Ok(fourier_ggsw_ciphertext_list_size(
        GgswCiphertextCount(ggsw_count),
        glwe_size,
        polynomial_size,
        decomp_level_count,
    ))
}
