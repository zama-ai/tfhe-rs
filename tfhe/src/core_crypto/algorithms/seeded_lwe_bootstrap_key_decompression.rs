//! Module with primitives pertaining to [`SeededLweBootstrapKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweBootstrapKey`] between all functions needing it.
pub fn decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_bsk: &mut LweBootstrapKey<OutputCont>,
    input_bsk: &SeededLweBootstrapKey<InputCont>,
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
    between input SeededLweBootstrapKey ({:?}) and output LweBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    decompress_seeded_ggsw_ciphertext_list_with_pre_seeded_generator(
        output_bsk, input_bsk, generator,
    );
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
    assert_eq!(
        output_bsk.ciphertext_modulus(),
        input_bsk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweBootstrapKey ({:?}) and output LweBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_bsk.compression_seed());
    decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator::<_, _, _, Gen>(
        output_bsk,
        input_bsk,
        &mut generator,
    );
}

/// Parallel variant of [`decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator`].
pub fn par_decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_bsk: &mut LweBootstrapKey<OutputCont>,
    input_bsk: &SeededLweBootstrapKey<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert_eq!(
        output_bsk.ciphertext_modulus(),
        input_bsk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweBootstrapKey ({:?}) and output LweBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    par_decompress_seeded_ggsw_ciphertext_list_with_pre_seeded_generator(
        output_bsk, input_bsk, generator,
    );
}

/// Parallel variant of [`decompress_seeded_lwe_bootstrap_key`]`.
pub fn par_decompress_seeded_lwe_bootstrap_key<Scalar, InputCont, OutputCont, Gen>(
    output_bsk: &mut LweBootstrapKey<OutputCont>,
    input_bsk: &SeededLweBootstrapKey<InputCont>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator + ByteRandomGenerator,
{
    assert_eq!(
        output_bsk.ciphertext_modulus(),
        input_bsk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweBootstrapKey ({:?}) and output LweBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_bsk.compression_seed());
    par_decompress_seeded_lwe_bootstrap_key_with_pre_seeded_generator::<_, _, _, Gen>(
        output_bsk,
        input_bsk,
        &mut generator,
    );
}
