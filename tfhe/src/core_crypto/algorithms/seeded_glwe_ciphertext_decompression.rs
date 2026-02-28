//! Module with primitives pertaining to [`SeededGlweCiphertext`] decompression.

use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGlweCiphertext`] between all functions needing it.
pub fn decompress_seeded_glwe_ciphertext_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_glwe: &mut GlweCiphertext<OutputCont>,
    input_seeded_glwe: &SeededGlweCiphertext<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_glwe.ciphertext_modulus(),
        input_seeded_glwe.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededGlweCiphertext ({:?}) and output GlweCiphertext ({:?})",
        input_seeded_glwe.ciphertext_modulus(),
        output_glwe.ciphertext_modulus(),
    );

    let (mut output_mask, mut output_body) = output_glwe.get_mut_mask_and_body();

    let ciphertext_modulus = output_mask.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // generate a uniformly random mask
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    if !ciphertext_modulus.is_native_modulus() {
        slice_wrapping_scalar_mul_assign(
            output_mask.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );
    }
    output_body
        .as_mut()
        .copy_from_slice(input_seeded_glwe.get_body().as_ref());
}

/// Decompress a [`SeededGlweCiphertext`], without consuming it, into a standard
/// [`GlweCiphertext`].
pub fn decompress_seeded_glwe_ciphertext<Scalar, InputCont, OutputCont, Gen>(
    output_glwe: &mut GlweCiphertext<OutputCont>,
    input_seeded_glwe: &SeededGlweCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_glwe.compression_seed());
    decompress_seeded_glwe_ciphertext_with_pre_seeded_generator::<_, _, _, Gen>(
        output_glwe,
        input_seeded_glwe,
        &mut generator,
    );
}
