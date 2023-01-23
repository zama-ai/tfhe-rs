//! Module with primitives pertaining to [`SeededLweKeyswitchKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweKeyswitchKey`] between all functions needing it.
pub fn decompress_seeded_lwe_keyswitch_key_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_ksk: &mut LweKeyswitchKey<OutputCont>,
    input_ksk: &SeededLweKeyswitchKey<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    decompress_seeded_lwe_ciphertext_list_with_existing_generator(
        &mut output_ksk.as_mut_lwe_ciphertext_list(),
        &input_ksk.as_seeded_lwe_ciphertext_list(),
        generator,
    )
}

/// Decompress a [`SeededLweKeyswitchKey`], without consuming it, into a standard
/// [`LweKeyswitchKey`].
pub fn decompress_seeded_lwe_keyswitch_key<Scalar, InputCont, OutputCont, Gen>(
    output_ksk: &mut LweKeyswitchKey<OutputCont>,
    input_ksk: &SeededLweKeyswitchKey<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_ksk.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );
    let mut generator = RandomGenerator::<Gen>::new(input_ksk.compression_seed().seed);
    decompress_seeded_lwe_keyswitch_key_with_existing_generator::<_, _, _, Gen>(
        output_ksk,
        input_ksk,
        &mut generator,
    )
}
