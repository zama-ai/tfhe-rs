//! Module with primitives pertaining to [`SeededLweMultiBitBootstrapKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweMultiBitBootstrapKey`] between all functions needing it.
pub fn decompress_seeded_lwe_multi_bit_bootstrap_key_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_bsk: &mut LweMultiBitBootstrapKey<OutputCont>,
    input_bsk: &SeededLweMultiBitBootstrapKey<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_bsk.ciphertext_modulus(),
        input_bsk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweMultiBitBootstrapKey ({:?}) and output LweMultiBitBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    decompress_seeded_ggsw_ciphertext_list_with_existing_generator(output_bsk, input_bsk, generator)
}

/// Decompress a [`SeededLweMultiBitBootstrapKey`], without consuming it, into a standard
/// [`LweMultiBitBootstrapKey`].
pub fn decompress_seeded_lwe_multi_bit_bootstrap_key<Scalar, InputCont, OutputCont, Gen>(
    output_bsk: &mut LweMultiBitBootstrapKey<OutputCont>,
    input_bsk: &SeededLweMultiBitBootstrapKey<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_bsk.ciphertext_modulus(),
        input_bsk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweMultiBitBootstrapKey ({:?}) and output LweMultiBitBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_bsk.compression_seed().seed);
    decompress_seeded_lwe_multi_bit_bootstrap_key_with_existing_generator::<_, _, _, Gen>(
        output_bsk,
        input_bsk,
        &mut generator,
    )
}
