//! Module with primitives pertaining to [`SeededGgswCiphertext`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGgswCiphertext`] between all functions needing it.
pub fn decompress_seeded_ggsw_ciphertext_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_ggsw: &mut GgswCiphertext<OutputCont>,
    input_seeded_ggsw: &SeededGgswCiphertext<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    for (matrix_in, mut matrix_out) in input_seeded_ggsw.iter().zip(output_ggsw.iter_mut()) {
        for (row_glwe_in, mut row_glwe_out) in matrix_in
            .as_seeded_glwe_list()
            .iter()
            .zip(matrix_out.as_mut_glwe_list().iter_mut())
        {
            decompress_seeded_glwe_ciphertext_with_existing_generator::<_, _, _, Gen>(
                &mut row_glwe_out,
                &row_glwe_in,
                generator,
            );
        }
    }
}

/// Decompress a [`SeededGgswCiphertext`], without consuming it, into a standard
/// [`GgswCiphertext`].
pub fn decompress_seeded_ggsw_ciphertext<Scalar, InputCont, OutputCont, Gen>(
    output_ggsw: &mut GgswCiphertext<OutputCont>,
    input_seeded_ggsw: &SeededGgswCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = RandomGenerator::<Gen>::new(input_seeded_ggsw.compression_seed().seed);
    decompress_seeded_ggsw_ciphertext_with_existing_generator::<_, _, _, Gen>(
        output_ggsw,
        input_seeded_ggsw,
        &mut generator,
    )
}
