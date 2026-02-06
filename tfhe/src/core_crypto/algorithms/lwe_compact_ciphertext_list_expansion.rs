//! Module with primitives pertaining to [`LweCompactCiphertextList`] expansion.

use crate::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul;
use crate::core_crypto::commons::parameters::MonomialDegree;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Expand an [`LweCompactCiphertextList`] into an [`LweCiphertextList`].
///
/// Consider using [`par_expand_lwe_compact_ciphertext_list`] for better performance.
pub fn expand_lwe_compact_ciphertext_list<Scalar, InputCont, OutputCont>(
    output_lwe_ciphertext_list: &mut LweCiphertextList<OutputCont>,
    input_lwe_compact_ciphertext_list: &LweCompactCiphertextList<InputCont>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_lwe_ciphertext_list.entity_count()
            == input_lwe_compact_ciphertext_list.lwe_ciphertext_count().0
    );

    assert!(output_lwe_ciphertext_list.lwe_size() == input_lwe_compact_ciphertext_list.lwe_size());

    let (input_mask_list, input_body_list) =
        input_lwe_compact_ciphertext_list.get_mask_and_body_list();

    let lwe_dimension = input_mask_list.lwe_dimension();
    let max_ciphertext_per_bin = lwe_dimension.0;

    for (input_mask, (mut output_ct_chunk, input_body_chunk)) in input_mask_list.iter().zip(
        output_lwe_ciphertext_list
            .chunks_mut(max_ciphertext_per_bin)
            .zip(input_body_list.chunks(max_ciphertext_per_bin)),
    ) {
        for (ct_idx, (mut out_ct, input_body)) in output_ct_chunk
            .iter_mut()
            .zip(input_body_chunk.iter())
            .enumerate()
        {
            let (mut out_mask, out_body) = out_ct.get_mut_mask_and_body();

            let mut out_mask_as_polynomial = Polynomial::from_container(out_mask.as_mut());
            let input_mask_as_polynomial = Polynomial::from_container(input_mask.as_ref());

            // This is the Psi_jl from the paper, it's equivalent to a multiplication in the X^N + 1
            // ring for our choice of i == n
            polynomial_wrapping_monic_monomial_mul(
                &mut out_mask_as_polynomial,
                &input_mask_as_polynomial,
                MonomialDegree(ct_idx),
            );

            *out_body.data = *input_body.data;
        }
    }
}

/// Parallel variant of [`expand_lwe_compact_ciphertext_list`].
pub fn par_expand_lwe_compact_ciphertext_list<Scalar, InputCont, OutputCont>(
    output_lwe_ciphertext_list: &mut LweCiphertextList<OutputCont>,
    input_lwe_compact_ciphertext_list: &LweCompactCiphertextList<InputCont>,
) where
    Scalar: UnsignedInteger + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_lwe_ciphertext_list.entity_count()
            == input_lwe_compact_ciphertext_list.lwe_ciphertext_count().0
    );

    assert!(output_lwe_ciphertext_list.lwe_size() == input_lwe_compact_ciphertext_list.lwe_size());

    let (input_mask_list, input_body_list) =
        input_lwe_compact_ciphertext_list.get_mask_and_body_list();

    let lwe_dimension = input_mask_list.lwe_dimension();
    let max_ciphertext_per_bin = lwe_dimension.0;

    input_mask_list
        .par_iter()
        .zip(
            output_lwe_ciphertext_list
                .par_chunks_mut(max_ciphertext_per_bin)
                .zip(input_body_list.par_chunks(max_ciphertext_per_bin)),
        )
        .for_each(|(input_mask, (mut output_ct_chunk, input_body_chunk))| {
            output_ct_chunk
                .par_iter_mut()
                .zip(input_body_chunk.par_iter())
                .enumerate()
                .for_each(|(ct_idx, (mut out_ct, input_body))| {
                    let (mut out_mask, out_body) = out_ct.get_mut_mask_and_body();

                    let mut out_mask_as_polynomial = Polynomial::from_container(out_mask.as_mut());
                    let input_mask_as_polynomial = Polynomial::from_container(input_mask.as_ref());

                    // This is the Psi_jl from the paper, it's equivalent to a multiplication in the
                    // X^N + 1 ring for our choice of i == n
                    polynomial_wrapping_monic_monomial_mul(
                        &mut out_mask_as_polynomial,
                        &input_mask_as_polynomial,
                        MonomialDegree(ct_idx),
                    );

                    *out_body.data = *input_body.data;
                });
        });
}
