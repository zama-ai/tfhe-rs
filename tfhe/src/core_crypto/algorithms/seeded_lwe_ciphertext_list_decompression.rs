//! Module with primitives pertaining to [`SeededLweCiphertextList`] decompression.

use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweCiphertextList`] between all functions needing it.
pub fn decompress_seeded_lwe_ciphertext_list_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut LweCiphertextList<OutputCont>,
    input_seeded_list: &SeededLweCiphertextList<InputCont>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_list.ciphertext_modulus(),
        input_seeded_list.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweCiphertextList ({:?}) and output LweCiphertextList ({:?})",
        input_seeded_list.ciphertext_modulus(),
        output_list.ciphertext_modulus(),
    );

    let ciphertext_modulus = output_list.ciphertext_modulus();

    for (mut lwe_out, body_in) in output_list.iter_mut().zip(input_seeded_list.iter()) {
        let (mut output_mask, output_body) = lwe_out.get_mut_mask_and_body();

        // generate a uniformly random mask
        generator
            .fill_slice_with_random_uniform_custom_mod(output_mask.as_mut(), ciphertext_modulus);
        if !ciphertext_modulus.is_native_modulus() {
            slice_wrapping_scalar_mul_assign(
                output_mask.as_mut(),
                ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            );
        }
        *output_body.data = *body_in.data;
    }
}

/// Decompress a [`SeededLweCiphertextList`], without consuming it, into a standard
/// [`LweCiphertextList`].
pub fn decompress_seeded_lwe_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut LweCiphertextList<OutputCont>,
    input_seeded_list: &SeededLweCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_list.ciphertext_modulus(),
        input_seeded_list.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweCiphertextList ({:?}) and output LweCiphertextList ({:?})",
        input_seeded_list.ciphertext_modulus(),
        output_list.ciphertext_modulus(),
    );

    let mut generator = RandomGenerator::<Gen>::new(input_seeded_list.compression_seed().seed);
    decompress_seeded_lwe_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    )
}
