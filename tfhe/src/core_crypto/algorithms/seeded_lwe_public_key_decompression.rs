//! Module with primitives pertaining to [`SeededLwePublicKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Decompress a [`SeededLwePublicKey`], without consuming it, into a standard
/// [`LwePublicKey`].
pub fn decompress_seeded_lwe_public_key<Scalar, InputCont, OutputCont, Gen>(
    output_pk: &mut LwePublicKey<OutputCont>,
    input_pk: &SeededLwePublicKey<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_pk.ciphertext_modulus(),
        input_pk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLwePublicKey ({:?}) and output LwePublicKey ({:?})",
        output_pk.ciphertext_modulus(),
        input_pk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_pk.compression_seed());
    decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator::<_, _, _, Gen>(
        output_pk,
        input_pk,
        &mut generator,
    );
}

/// Decompress a [`SeededLwePublicKey`], without consuming it, into a standard
/// [`LwePublicKey`] using multiple threads.
pub fn par_decompress_seeded_lwe_public_key<Scalar, InputCont, OutputCont, Gen>(
    output_pk: &mut LwePublicKey<OutputCont>,
    input_pk: &SeededLwePublicKey<InputCont>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator + ByteRandomGenerator,
{
    assert_eq!(
        output_pk.ciphertext_modulus(),
        input_pk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLwePublicKey ({:?}) and output LwePublicKey ({:?})",
        output_pk.ciphertext_modulus(),
        input_pk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_pk.compression_seed());
    par_decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator::<_, _, _, Gen>(
        output_pk,
        input_pk,
        &mut generator,
    );
}
