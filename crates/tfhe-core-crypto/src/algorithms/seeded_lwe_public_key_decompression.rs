//! Module with primitives pertaining to [`SeededLwePublicKey`] decompression.

use crate::algorithms::*;
use crate::commons::generators::MaskRandomGenerator;
use crate::commons::traits::*;
use crate::entities::*;

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

    let mut generator = MaskRandomGenerator::<Gen>::new(input_pk.compression_seed().seed);
    decompress_seeded_lwe_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
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
    Gen: ParallelByteRandomGenerator,
{
    assert_eq!(
        output_pk.ciphertext_modulus(),
        input_pk.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLwePublicKey ({:?}) and output LwePublicKey ({:?})",
        output_pk.ciphertext_modulus(),
        input_pk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_pk.compression_seed().seed);
    par_decompress_seeded_lwe_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_pk,
        input_pk,
        &mut generator,
    );
}
