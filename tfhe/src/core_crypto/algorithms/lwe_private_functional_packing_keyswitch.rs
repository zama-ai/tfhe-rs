#![allow(deprecated)] // For MonomialDegree for now
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

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
            update_slice_with_wrapping_sub_scalar_mul(
                output_glwe_ciphertext.as_mut(),
                level_key_cipher.as_ref(),
                decomposed.value(),
            );
        }
    }
}

pub fn private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_cipheretext<
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
    OutputCont: ContainerMut<Element = Scalar> + Clone,
{
    assert!(input.lwe_ciphertext_count().0 <= output.polynomial_size().0);
    output.as_mut().fill(Scalar::ZERO);
    let mut buffer = output.clone();
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
                update_polynomial_with_wrapping_monic_monomial_mul(
                    &mut poly,
                    MonomialDegree(degree),
                )
            });
        update_slice_with_wrapping_add(output.as_mut(), buffer.as_ref());
    }
}
