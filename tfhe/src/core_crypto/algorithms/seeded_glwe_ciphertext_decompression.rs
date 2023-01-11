//! Module with primitives pertaining to [`SeededGlweCiphertext`] decompression.

use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGlweCiphertext`] between all functions needing it.
pub fn decompress_seeded_glwe_ciphertext_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_glwe: &mut GlweCiphertext<OutputCont>,
    input_seeded_glwe: &SeededGlweCiphertext<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let (mut output_mask, mut output_body) = output_glwe.get_mut_mask_and_body();

    // generate a uniformly random mask
    generator.fill_slice_with_random_uniform(output_mask.as_mut());
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
    let mut generator = RandomGenerator::<Gen>::new(input_seeded_glwe.compression_seed().seed);
    decompress_seeded_glwe_ciphertext_with_existing_generator::<_, _, _, Gen>(
        output_glwe,
        input_seeded_glwe,
        &mut generator,
    )
}
