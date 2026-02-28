//! Module with primitives pertaining to [`SeededLweCiphertextList`] decompression.

use crate::core_crypto::algorithms::slice_algorithms::slice_wrapping_scalar_mul_assign;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::math::random::Uniform;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweCiphertextList`] between all functions needing it.
pub fn decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut LweCiphertextList<OutputCont>,
    input_seeded_list: &SeededLweCiphertextList<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
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

    // Generator forking and decompression computations must match the SeededLweCiphertextList
    // encryption algorithm
    let gen_iter = generator
        .try_fork_from_config(input_seeded_list.decompression_fork_config(Uniform))
        .expect("Error while forking generator for SeededLweCiphertextList decompression.");

    for ((mut lwe_out, body_in), mut loop_generator) in output_list
        .iter_mut()
        .zip(input_seeded_list.iter())
        .zip(gen_iter)
    {
        let (mut output_mask, output_body) = lwe_out.get_mut_mask_and_body();

        // Generate a uniformly random mask
        loop_generator.fill_slice_with_random_uniform_mask_custom_mod(
            output_mask.as_mut(),
            ciphertext_modulus,
        );
        match ciphertext_modulus.kind() {
            // Manage the specific encoding for non native power of 2
            CiphertextModulusKind::NonNativePowerOfTwo => {
                slice_wrapping_scalar_mul_assign(
                    output_mask.as_mut(),
                    ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
                );
            }
            // Nothing to do
            CiphertextModulusKind::Native | CiphertextModulusKind::Other => (),
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

    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_list.compression_seed());
    decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    );
}

/// Parllel variant of [`decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator`].
pub fn par_decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut LweCiphertextList<OutputCont>,
    input_seeded_list: &SeededLweCiphertextList<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
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

    // Generator forking and decompression computations must match the SeededLweCiphertextList
    // encryption algorithm
    let gen_iter = generator
        .par_try_fork_from_config(input_seeded_list.decompression_fork_config(Uniform))
        .expect("Error while forking generator for SeededLweCiphertextList decompression.");

    output_list
        .par_iter_mut()
        .zip(input_seeded_list.par_iter())
        .zip(gen_iter)
        .for_each(|((mut lwe_out, body_in), mut loop_generator)| {
            let (mut output_mask, output_body) = lwe_out.get_mut_mask_and_body();

            // Generate a uniformly random mask
            loop_generator.fill_slice_with_random_uniform_mask_custom_mod(
                output_mask.as_mut(),
                ciphertext_modulus,
            );
            match ciphertext_modulus.kind() {
                // Manage the specific encoding for non native power of 2
                CiphertextModulusKind::NonNativePowerOfTwo => {
                    slice_wrapping_scalar_mul_assign(
                        output_mask.as_mut(),
                        ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
                    );
                }
                // Nothing to do
                CiphertextModulusKind::Native | CiphertextModulusKind::Other => (),
            }
            *output_body.data = *body_in.data;
        });
}

/// Parallel variant of [`decompress_seeded_lwe_ciphertext_list`].
pub fn par_decompress_seeded_lwe_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut LweCiphertextList<OutputCont>,
    input_seeded_list: &SeededLweCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator + ByteRandomGenerator,
{
    assert_eq!(
        output_list.ciphertext_modulus(),
        input_seeded_list.ciphertext_modulus(),
        "Mismatched CiphertextModulus \
    between input SeededLweCiphertextList ({:?}) and output LweCiphertextList ({:?})",
        input_seeded_list.ciphertext_modulus(),
        output_list.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_list.compression_seed());
    par_decompress_seeded_lwe_ciphertext_list_with_pre_seeded_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    );
}
