//! Module with primitives pertaining to [`SeededGlweCiphertextList`] decompression.

use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGlweCiphertextList`] between all functions needing it.
pub fn decompress_seeded_glwe_ciphertext_list_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut GlweCiphertextList<OutputCont>,
    input_seeded_list: &SeededGlweCiphertextList<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_list.ciphertext_modulus(),
        input_seeded_list.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededGlweCiphertextList ({:?}) and output GlweCiphertextList ({:?})",
        input_seeded_list.ciphertext_modulus(),
        output_list.ciphertext_modulus(),
    );

    let ciphertext_modulus = output_list.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    for (mut glwe_out, body_in) in output_list.iter_mut().zip(input_seeded_list.iter()) {
        let (mut output_mask, mut output_body) = glwe_out.get_mut_mask_and_body();

        // generate a uniformly random mask
        generator.fill_slice_with_random_uniform_mask_custom_mod(
            output_mask.as_mut(),
            ciphertext_modulus,
        );
        if !ciphertext_modulus.is_native_modulus() {
            slice_wrapping_scalar_mul_assign(
                output_mask.as_mut(),
                ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            );
        }
        output_body.as_mut().copy_from_slice(body_in.as_ref());
    }
}

/// Decompress a [`SeededGlweCiphertextList`], without consuming it, into a standard
/// [`GlweCiphertextList`].
pub fn decompress_seeded_glwe_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut GlweCiphertextList<OutputCont>,
    input_seeded_list: &SeededGlweCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_list.compression_seed());
    decompress_seeded_glwe_ciphertext_list_with_pre_seeded_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    );
}
