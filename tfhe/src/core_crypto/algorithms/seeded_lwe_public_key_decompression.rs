//! Module with primitives pertaining to [`SeededLwePublicKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::RandomGenerator;
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
    let mut generator = RandomGenerator::<Gen>::new(input_pk.compression_seed().seed);
    decompress_seeded_lwe_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_pk,
        input_pk,
        &mut generator,
    );
}
