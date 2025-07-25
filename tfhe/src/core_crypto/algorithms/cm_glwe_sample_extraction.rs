//! Module containing primitives pertaining to the operation usually referred to as a
//! _sample extract_ in the literature. Allowing to extract a single
//! [`LWE Ciphertext`](`CmLweCiphertext`) from a given [`GLWE ciphertext`](`CmGlweCiphertext`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use itertools::Itertools;
use rayon::prelude::*;

pub fn extract_lwe_sample_from_cm_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_glwe: &CmGlweCiphertext<InputCont>,
    output_lwe: &mut CmLweCiphertext<OutputCont>,
    nth: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let in_lwe_dim = input_glwe
        .glwe_dimension()
        .to_equivalent_lwe_dimension(input_glwe.polynomial_size());

    let out_lwe_dim = output_lwe.lwe_dimension();

    assert_eq!(
        in_lwe_dim, out_lwe_dim,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {in_lwe_dim:?} for input and {out_lwe_dim:?} for output.",
    );

    assert_eq!(
        input_glwe.ciphertext_modulus(),
        output_lwe.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe.ciphertext_modulus(),
        output_lwe.ciphertext_modulus()
    );

    // We retrieve the bodies and masks of the two ciphertexts.
    let (mut lwe_mask, mut lwe_bodies) = output_lwe.get_mut_mask_and_bodies();
    let (glwe_mask, glwe_bodies) = input_glwe.get_mask_and_bodies();

    // We copy the body

    for (lwe_body, glwe_body) in lwe_bodies.iter_mut().zip_eq(glwe_bodies.iter()) {
        *lwe_body.data = glwe_body.as_ref()[nth.0];
    }

    // We copy the mask (each polynomial is in the wrong order)
    lwe_mask.as_mut().copy_from_slice(glwe_mask.as_ref());

    // We compute the number of elements which must be
    // turned into their opposite
    let opposite_count = input_glwe.polynomial_size().0 - nth.0 - 1;
    let ciphertext_modulus = input_glwe.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // We loop through the polynomials
        for lwe_mask_poly in lwe_mask
            .as_mut()
            .chunks_exact_mut(input_glwe.polynomial_size().0)
        {
            // We reverse the polynomial
            lwe_mask_poly.reverse();
            // We compute the opposite of the proper coefficients
            slice_wrapping_opposite_assign(&mut lwe_mask_poly[0..opposite_count]);
            // We rotate the polynomial properly
            lwe_mask_poly.rotate_left(opposite_count);
        }
    } else {
        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        // We loop through the polynomials
        for lwe_mask_poly in lwe_mask
            .as_mut()
            .chunks_exact_mut(input_glwe.polynomial_size().0)
        {
            // We reverse the polynomial
            lwe_mask_poly.reverse();
            // We compute the opposite of the proper coefficients
            slice_wrapping_opposite_assign_custom_mod(
                &mut lwe_mask_poly[0..opposite_count],
                modulus,
            );
            // We rotate the polynomial properly
            lwe_mask_poly.rotate_left(opposite_count);
        }
    }
}

/// Parallel variant of [`extract_lwe_sample_from_cm_glwe_ciphertext`] performing a sample extract
/// on all coefficients from a [`CmGlweCiphertext`] in an output [`LweCiphertextList`].
///
/// This will use all threads available in the current rayon thread pool.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
pub fn par_extract_lwe_sample_from_cm_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_glwe: &CmGlweCiphertext<InputCont>,
    output_lwe_list: &mut CmLweCiphertextList<OutputCont>,
) where
    Scalar: UnsignedInteger + Send + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let thread_count = ThreadCount(rayon::current_num_threads());
    par_extract_lwe_sample_from_cm_glwe_ciphertext_with_thread_count(
        input_glwe,
        output_lwe_list,
        thread_count,
    );
}

/// Parallel variant of [`extract_lwe_sample_from_cm_glwe_ciphertext`] performing a sample extract
/// on all coefficients from a [`CmGlweCiphertext`] in an output [`LweCiphertextList`].
///
/// This will try to use `thread_count` threads for the computation, if this number is bigger than
/// the available number of threads in the current rayon thread pool then only the number of
/// available threads will be used. Note that `thread_count` cannot be 0.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
pub fn par_extract_lwe_sample_from_cm_glwe_ciphertext_with_thread_count<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_glwe: &CmGlweCiphertext<InputCont>,
    output_lwe_list: &mut CmLweCiphertextList<OutputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let in_lwe_dim = input_glwe
        .glwe_dimension()
        .to_equivalent_lwe_dimension(input_glwe.polynomial_size());

    let out_lwe_dim = output_lwe_list.lwe_dimension();

    assert_eq!(
        in_lwe_dim, out_lwe_dim,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {in_lwe_dim:?} for input and {out_lwe_dim:?} for output.",
    );

    assert!(
        input_glwe.polynomial_size().0 <= output_lwe_list.cm_lwe_ciphertext_count().0,
        "The output LweCiphertextList does not have enough space ({:?}) \
    to extract all input CmGlweCiphertext coefficients ({})",
        output_lwe_list.cm_lwe_ciphertext_count(),
        input_glwe.polynomial_size().0
    );

    assert_eq!(
        input_glwe.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus()
    );

    let polynomial_size = input_glwe.polynomial_size();
    let (glwe_mask, glwe_body) = input_glwe.get_mask_and_bodies();

    let thread_count = thread_count.0.min(rayon::current_num_threads());
    let chunk_size = polynomial_size.0.div_ceil(thread_count);

    glwe_body
        .as_ref()
        .par_chunks(chunk_size)
        .zip(output_lwe_list.par_chunks_mut(chunk_size))
        .enumerate()
        .for_each(
            |(chunk_idx, (glwe_body_chunk, mut output_lwe_list_chunk))| {
                for (coeff_idx, (glwe_coeff, mut output_lwe)) in glwe_body_chunk
                    .iter()
                    .zip(output_lwe_list_chunk.iter_mut())
                    .enumerate()
                {
                    let nth = chunk_idx * chunk_size + coeff_idx;

                    let (mut lwe_mask, mut lwe_body) = output_lwe.get_mut_mask_and_bodies();

                    // We copy the body
                    lwe_body.as_mut().fill(*glwe_coeff);

                    // We copy the mask (each polynomial is in the wrong order)
                    lwe_mask.as_mut().copy_from_slice(glwe_mask.as_ref());

                    // We compute the number of elements which must be
                    // turned into their opposite
                    let opposite_count = input_glwe.polynomial_size().0 - nth - 1;
                    let ciphertext_modulus = input_glwe.ciphertext_modulus();

                    if ciphertext_modulus.is_compatible_with_native_modulus() {
                        // We loop through the polynomials
                        for lwe_mask_poly in lwe_mask
                            .as_mut()
                            .chunks_exact_mut(input_glwe.polynomial_size().0)
                        {
                            // We reverse the polynomial
                            lwe_mask_poly.reverse();
                            // We compute the opposite of the proper coefficients
                            slice_wrapping_opposite_assign(&mut lwe_mask_poly[0..opposite_count]);
                            // We rotate the polynomial properly
                            lwe_mask_poly.rotate_left(opposite_count);
                        }
                    } else {
                        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
                        // We loop through the polynomials
                        for lwe_mask_poly in lwe_mask
                            .as_mut()
                            .chunks_exact_mut(input_glwe.polynomial_size().0)
                        {
                            // We reverse the polynomial
                            lwe_mask_poly.reverse();
                            // We compute the opposite of the proper coefficients
                            slice_wrapping_opposite_assign_custom_mod(
                                &mut lwe_mask_poly[0..opposite_count],
                                modulus,
                            );
                            // We rotate the polynomial properly
                            lwe_mask_poly.rotate_left(opposite_count);
                        }
                    }
                }
            },
        );
}
