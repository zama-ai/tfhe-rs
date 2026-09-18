//! Module containing primitives pertaining to the conversion of combined
//! [`half-product + half-rotate LWE bootstrap
//! keys`](`LweHalfProductHalfRotateBootstrapKey`) to the Fourier domain.

use crate::core_crypto::algorithms::par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convert a standard-domain [`LweHalfProductHalfRotateBootstrapKey`] to a Fourier-domain
/// [`Fourier128HalfProductHalfRotateLweBootstrapKey`].
pub fn par_allocate_and_convert_standard_half_product_half_rotate_lwe_bootstrap_key_to_fourier_128<
    Scalar,
    Cont,
>(
    input_bsk: &LweHalfProductHalfRotateBootstrapKey<Cont>,
) -> Fourier128HalfProductHalfRotateLweBootstrapKeyOwned
where
    Scalar: UnsignedTorus + Sync,
    Cont: Container<Element = Scalar> + Sync,
{
    let start = input_bsk.start();
    let end = input_bsk.end();

    let mut output_bsk = Fourier128HalfProductHalfRotateLweBootstrapKey::new(
        start.input_lwe_dimension(),
        start.decomposition_base_log_mask(),
        start.decomposition_level_count_mask(),
        start.decomposition_base_log_body(),
        start.decomposition_level_count_body(),
        end.input_lwe_dimension(),
        end.decomposition_base_log_mask(),
        end.decomposition_level_count_mask(),
        end.decomposition_base_log_body(),
        end.decomposition_level_count_body(),
        start.glwe_size(),
        start.polynomial_size(),
    );

    let (output_start, output_end) = output_bsk.as_mut_sections();

    // Convert the two sections concurrently; each conversion is itself parallelized over its GGSWs.
    rayon::join(
        || {
            par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128::<Scalar, _, _>(
                start,
                output_start,
            )
        },
        || {
            par_convert_standard_half_product_lwe_bootstrap_key_to_fourier_128::<Scalar, _, _>(
                end, output_end,
            )
        },
    );

    output_bsk
}
