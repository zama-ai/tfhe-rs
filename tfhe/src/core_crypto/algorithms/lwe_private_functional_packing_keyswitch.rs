//! Module containing primitives pertaining to LWE ciphertext private functional keyswitch and
//! packing keyswitch.
//!
//! Formal description can be found in: \
//! &nbsp;&nbsp;&nbsp;&nbsp; Chillotti, I., Gama, N., Georgieva, M. et al. \
//! &nbsp;&nbsp;&nbsp;&nbsp; TFHE: Fast Fully Homomorphic Encryption Over the Torus. \
//! &nbsp;&nbsp;&nbsp;&nbsp; J. Cryptol 33, 34–91 (2020). \
//! &nbsp;&nbsp;&nbsp;&nbsp; <https://doi.org/10.1007/s00145-019-09319-x>

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Apply a private functional keyswitch on an input [`LWE ciphertext`](`LweCiphertext`) and write
/// the result in an output [`GLWE ciphertext`](`GlweCiphertext`).
pub fn private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pfpksk: &LwePrivateFunctionalPackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lwe_pfpksk.input_lwe_key_dimension().0
            == input_lwe_ciphertext.lwe_size().to_lwe_dimension().0
    );
    assert!(
        lwe_pfpksk.output_glwe_key_dimension().0
            == output_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_pfpksk.decomposition_base_log(),
        lwe_pfpksk.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_lwe_element) in
        lwe_pfpksk.iter().zip(input_lwe_ciphertext.as_ref().iter())
    {
        // We decompose
        let rounded = decomposer.closest_representable(input_lwe_element);
        let decomp = decomposer.decompose(rounded);

        // Loop over the number of levels:
        // We compute the multiplication of a ciphertext from the private functional
        // keyswitching key with a piece of the decomposition and subtract it to the buffer
        for (level_key_cipher, decomposed) in keyswitch_key_block.iter().rev().zip(decomp) {
            slice_wrapping_sub_scalar_mul_assign(
                output_glwe_ciphertext.as_mut(),
                level_key_cipher.as_ref(),
                decomposed.value(),
            );
        }
    }
}

/// Apply a private functional keyswitch on each [`LWE ciphertext`](`LweCiphertext`) of an input
/// [`LWE ciphertext list`](`LweCiphertextList`) and pack the result in an output
/// [`GLWE ciphertext`](`GlweCiphertext`).
pub fn private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pfpksk: &LwePrivateFunctionalPackingKeyswitchKey<KeyCont>,
    output: &mut GlweCiphertext<OutputCont>,
    input: &LweCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(input.lwe_ciphertext_count().0 <= output.polynomial_size().0);
    output.as_mut().fill(Scalar::ZERO);
    let mut buffer =
        GlweCiphertext::new(Scalar::ZERO, output.glwe_size(), output.polynomial_size());
    // for each ciphertext, call mono_key_switch
    for (degree, input_ciphertext) in input.iter().enumerate() {
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            lwe_pfpksk,
            &mut buffer,
            &input_ciphertext,
        );
        buffer
            .as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(degree))
            });
        slice_wrapping_add_assign(output.as_mut(), buffer.as_ref());
    }
}
