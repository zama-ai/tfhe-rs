//! Module with primitives pertaining to [`SeededGgswCiphertextList`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::parameters::LweDimension;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGgswCiphertextList`] between all functions needing it.
pub fn decompress_seeded_ggsw_ciphertext_list_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut GgswCiphertextList<OutputCont>,
    input_seeded_list: &SeededGgswCiphertextList<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let output_ciphertext_count = LweDimension(output_list.ggsw_ciphertext_count().0);
    let output_decomp_level = output_list.decomposition_level_count();
    let output_glwe_size = output_list.glwe_size();
    let output_polynomial_size = output_list.polynomial_size();

    // As we only generate ciphertext lists in the context of BSK generation we use the bsk forking
    // If we ever have GGSW list encryption then it's easy to have a generic forking for GGSW
    // ciphertext lists and adapt the bsk formula to forward to the GGSW primitive
    let gen_iter = generator
        .fork_bsk_to_ggsw::<Scalar>(
            output_ciphertext_count,
            output_decomp_level,
            output_glwe_size,
            output_polynomial_size,
        )
        .unwrap();

    for ((mut ggsw_out, ggsw_in), mut loop_generator) in output_list
        .iter_mut()
        .zip(input_seeded_list.iter())
        .zip(gen_iter)
    {
        decompress_seeded_ggsw_ciphertext_with_existing_generator(
            &mut ggsw_out,
            &ggsw_in,
            &mut loop_generator,
        );
    }
}

/// Decompress a [`SeededGgswCiphertextList`], without consuming it, into a standard
/// [`GgswCiphertextList`].
pub fn decompress_seeded_ggsw_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut GgswCiphertextList<OutputCont>,
    input_seeded_list: &SeededGgswCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_list.compression_seed().seed);
    decompress_seeded_ggsw_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    );
}

/// Parallel variant of [`decompress_seeded_ggsw_ciphertext_list_with_existing_generator`].
pub fn par_decompress_seeded_ggsw_ciphertext_list_with_existing_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_list: &mut GgswCiphertextList<OutputCont>,
    input_seeded_list: &SeededGgswCiphertextList<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    let output_ciphertext_count = LweDimension(output_list.ggsw_ciphertext_count().0);
    let output_decomp_level = output_list.decomposition_level_count();
    let output_glwe_size = output_list.glwe_size();
    let output_polynomial_size = output_list.polynomial_size();

    // As we only generate ciphertext lists in the context of BSK generation we use the bsk forking
    // If we ever have GGSW list encryption then it's easy to have a generic forking for GGSW
    // ciphertext lists and adapt the bsk formula to forward to the GGSW primitive
    let gen_iter = generator
        .par_fork_bsk_to_ggsw::<Scalar>(
            output_ciphertext_count,
            output_decomp_level,
            output_glwe_size,
            output_polynomial_size,
        )
        .unwrap();

    output_list
        .par_iter_mut()
        .zip(input_seeded_list.par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw_out, ggsw_in), mut loop_generator)| {
            par_decompress_seeded_ggsw_ciphertext_with_existing_generator(
                &mut ggsw_out,
                &ggsw_in,
                &mut loop_generator,
            );
        });
}

/// Parallel variant of [`decompress_seeded_ggsw_ciphertext_list`].
pub fn par_decompress_seeded_ggsw_ciphertext_list<Scalar, InputCont, OutputCont, Gen>(
    output_list: &mut GgswCiphertextList<OutputCont>,
    input_seeded_list: &SeededGgswCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_list.compression_seed().seed);
    par_decompress_seeded_ggsw_ciphertext_list_with_existing_generator::<_, _, _, Gen>(
        output_list,
        input_seeded_list,
        &mut generator,
    );
}
