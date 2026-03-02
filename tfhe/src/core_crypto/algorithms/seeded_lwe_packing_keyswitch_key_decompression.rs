//! Module with primitives pertaining to [`SeededLwePackingKeyswitchKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLwePackingKeyswitchKey`] between all functions needing it.
pub fn decompress_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_pksk: &mut LwePackingKeyswitchKey<OutputCont>,
    input_pksk: &SeededLwePackingKeyswitchKey<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    decompress_seeded_glwe_ciphertext_list_with_pre_seeded_generator(
        &mut output_pksk.as_mut_glwe_ciphertext_list(),
        &input_pksk.as_seeded_glwe_ciphertext_list(),
        generator,
    );
}

/// Decompress a [`SeededLwePackingKeyswitchKey`], without consuming it, into a standard
/// [`LwePackingKeyswitchKey`].
pub fn decompress_seeded_lwe_packing_keyswitch_key<Scalar, InputCont, OutputCont, Gen>(
    output_pksk: &mut LwePackingKeyswitchKey<OutputCont>,
    input_pksk: &SeededLwePackingKeyswitchKey<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_pksk.compression_seed());
    decompress_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator::<_, _, _, Gen>(
        output_pksk,
        input_pksk,
        &mut generator,
    );
}
