use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweBootstrapKey`] between all functions needing it.
pub fn decompress_seeded_lwe_bootstrap_key_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_bsk: &mut LweBootstrapKey<OutputCont>,
    input_bsk: &SeededLweBootstrapKey<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    decompress_seeded_ggsw_ciphertext_list_with_existing_generator(output_bsk, input_bsk, generator)
}

/// Decompress a [`SeededLweBootstrapKey`], without consuming it, into a standard
/// [`LweBootstrapKey`].
pub fn decompress_seeded_lwe_bootstrap_key<Scalar, InputCont, OutputCont, Gen>(
    output_bsk: &mut LweBootstrapKey<OutputCont>,
    input_bsk: &SeededLweBootstrapKey<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = RandomGenerator::<Gen>::new(input_bsk.compression_seed().seed);
    decompress_seeded_lwe_bootstrap_key_with_existing_generator::<_, _, _, Gen>(
        output_bsk,
        input_bsk,
        &mut generator,
    )
}
