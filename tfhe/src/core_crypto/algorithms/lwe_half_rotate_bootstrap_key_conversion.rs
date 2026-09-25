//! Module containing primitives pertaining to the conversion of
//! [`half-rotate LWE bootstrap keys`](`LweHalfRotateBootstrapKey`) to the Fourier domain.

use crate::core_crypto::algorithms::par_convert_standard_lwe_bootstrap_key_to_fourier_128;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convert a standard-domain [`LweHalfRotateBootstrapKey`] to a Fourier-domain
/// [`Fourier128HalfRotateLweBootstrapKey`].
///
/// This is the single-call counterpart to
/// [`par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key`](crate::core_crypto::algorithms::par_allocate_and_generate_new_half_rotate_lwe_bootstrap_key):
/// generate the standard-domain key, then convert it with this function before use.
pub fn par_allocate_and_convert_standard_half_rotate_lwe_bootstrap_key_to_fourier_128<
    Scalar,
    Cont,
>(
    input_bsk: &LweHalfRotateBootstrapKey<Cont>,
) -> Fourier128HalfRotateLweBootstrapKeyOwned
where
    Scalar: UnsignedTorus + Sync,
    Cont: Container<Element = Scalar> + Sync,
{
    let start = input_bsk.start();
    let end = input_bsk.end();

    let mut output_bsk = Fourier128HalfRotateLweBootstrapKey::new(
        start.input_lwe_dimension(),
        start.decomposition_base_log(),
        start.decomposition_level_count(),
        end.input_lwe_dimension(),
        end.decomposition_base_log(),
        end.decomposition_level_count(),
        start.glwe_size(),
        start.polynomial_size(),
    );

    let (output_start, output_end) = output_bsk.as_mut_sections();

    // Convert the two sections concurrently; each conversion is itself parallelized over its GGSWs.
    rayon::join(
        || {
            par_convert_standard_lwe_bootstrap_key_to_fourier_128::<Scalar, _, _>(
                start,
                output_start,
            )
        },
        || par_convert_standard_lwe_bootstrap_key_to_fourier_128::<Scalar, _, _>(end, output_end),
    );

    output_bsk
}
