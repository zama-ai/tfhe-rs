#![allow(deprecated)] // For MonomialDegree for the time being
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{MonomialDegree, *};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn extract_lwe_sample_from_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_glwe: &GlweCiphertext<InputCont>,
    output_lwe: &mut LweCiphertext<OutputCont>,
    n_th: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_glwe.glwe_size().to_glwe_dimension().0 * input_glwe.polynomial_size().0
            == output_lwe.lwe_size().to_lwe_dimension().0,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {:?} for input and {:?} for output.",
        LweDimension(input_glwe.glwe_size().to_glwe_dimension().0 * input_glwe.polynomial_size().0),
        output_lwe.lwe_size().to_lwe_dimension(),
    );

    // We retrieve the bodies and masks of the two ciphertexts.
    let (mut lwe_mask, lwe_body) = output_lwe.get_mut_mask_and_body();
    let (glwe_mask, glwe_body) = input_glwe.get_mask_and_body();

    // We copy the body
    *lwe_body.0 = glwe_body.as_ref()[n_th.0];

    // We copy the mask (each polynomial is in the wrong order)
    lwe_mask.as_mut().copy_from_slice(glwe_mask.as_ref());

    // We compute the number of elements which must be
    // turned into their opposite
    let opposite_count = input_glwe.polynomial_size().0 - n_th.0 - 1;

    // We loop through the polynomials
    for lwe_mask_poly in lwe_mask.as_mut().chunks_mut(input_glwe.polynomial_size().0) {
        // We reverse the polynomial
        lwe_mask_poly.reverse();
        // We compute the opposite of the proper coefficients
        update_slice_with_wrapping_opposite(&mut lwe_mask_poly[0..opposite_count]);
        // We rotate the polynomial properly
        lwe_mask_poly.rotate_left(opposite_count);
    }
}
