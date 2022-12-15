use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGgswCiphertextList`] between all functions needing it.
pub fn decompress_seeded_ggsw_ciphertext_list_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut GgswCiphertextList<OutputCont>,
    input_seeded_list: &SeededGgswCiphertextList<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    for (mut ggsw_out, ggsw_in) in output_list.iter_mut().zip(input_seeded_list.iter()) {
        decompress_seeded_ggsw_ciphertext_with_existing_generator(
            &mut ggsw_out,
            &ggsw_in,
            generator,
        )
    }
}

/// Decompress a [`SeededGgswCiphertextList`], without consuming it, into a standard
/// [`GgswCiphertextList`].
pub fn decompress_seeded_ggsw_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut GgswCiphertextList<OutputCont>,
    input_seeded_list: &SeededGgswCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = RandomGenerator::<Gen>::new(input_seeded_list.compression_seed().seed);
    decompress_seeded_ggsw_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    )
}
