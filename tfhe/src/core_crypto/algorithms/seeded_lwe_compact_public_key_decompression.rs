//! Module with primitives pertaining to [`SeededLweCompactPublicKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweCompactPublicKey`] between all functions needing it.
pub fn decompress_seeded_lwe_compact_public_key_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_cpk: &mut LweCompactPublicKey<OutputCont>,
    input_seeded_cpk: &SeededLweCompactPublicKey<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    decompress_seeded_glwe_ciphertext_with_pre_seeded_generator(
        &mut output_cpk.as_mut_glwe_ciphertext(),
        &input_seeded_cpk.as_seeded_glwe_ciphertext(),
        generator,
    );
}

/// Decompress a [`SeededLweCompactPublicKey`], without consuming it, into a standard
/// [`LweCompactPublicKey`].
pub fn decompress_seeded_lwe_compact_public_key<Scalar, InputCont, OutputCont, Gen>(
    output_cpk: &mut LweCompactPublicKey<OutputCont>,
    input_seeded_cpk: &SeededLweCompactPublicKey<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_cpk.compression_seed());
    decompress_seeded_lwe_compact_public_key_with_pre_seeded_generator::<_, _, _, Gen>(
        output_cpk,
        input_seeded_cpk,
        &mut generator,
    );
}
