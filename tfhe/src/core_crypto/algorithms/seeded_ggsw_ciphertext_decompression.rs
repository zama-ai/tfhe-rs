//! Module with primitives pertaining to [`SeededGgswCiphertext`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::math::random::Uniform;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededGgswCiphertext`] between all functions needing it.
pub fn decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_ggsw: &mut GgswCiphertext<OutputCont>,
    input_seeded_ggsw: &SeededGgswCiphertext<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ggsw_forking_configuration = input_seeded_ggsw.decompression_fork_config(Uniform);

    let gen_iter = generator
        .try_fork_from_config(ggsw_forking_configuration)
        .expect("Failed to split generator into ggsw levels");

    for ((matrix_in, mut matrix_out), mut loop_generator) in input_seeded_ggsw
        .iter()
        .zip(output_ggsw.iter_mut())
        .zip(gen_iter)
    {
        let ggsw_level_forking_configuration = matrix_in.decompression_fork_config(Uniform);

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = loop_generator
            .try_fork_from_config(ggsw_level_forking_configuration)
            .expect("Failed to split generator into glwe");

        for ((row_glwe_in, mut row_glwe_out), mut inner_loop_generator) in matrix_in
            .as_seeded_glwe_list()
            .iter()
            .zip(matrix_out.as_mut_glwe_list().iter_mut())
            .zip(gen_iter)
        {
            decompress_seeded_glwe_ciphertext_with_pre_seeded_generator::<_, _, _, Gen>(
                &mut row_glwe_out,
                &row_glwe_in,
                &mut inner_loop_generator,
            );
        }
    }
}

/// Decompress a [`SeededGgswCiphertext`], without consuming it, into a standard
/// [`GgswCiphertext`].
pub fn decompress_seeded_ggsw_ciphertext<Scalar, InputCont, OutputCont, Gen>(
    output_ggsw: &mut GgswCiphertext<OutputCont>,
    input_seeded_ggsw: &SeededGgswCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_ggsw.compression_seed());
    decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator::<_, _, _, Gen>(
        output_ggsw,
        input_seeded_ggsw,
        &mut generator,
    );
}

/// Parallel variant of [`decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator`].
pub fn par_decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_ggsw: &mut GgswCiphertext<OutputCont>,
    input_seeded_ggsw: &SeededGgswCiphertext<InputCont>,
    generator: &mut MaskRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    let ggsw_forking_configuration = input_seeded_ggsw.decompression_fork_config(Uniform);

    let gen_iter = generator
        .par_try_fork_from_config(ggsw_forking_configuration)
        .expect("Failed to split generator into ggsw levels");

    input_seeded_ggsw
        .par_iter()
        .zip(output_ggsw.par_iter_mut())
        .zip(gen_iter)
        .for_each(|((matrix_in, mut matrix_out), mut loop_generator)| {
            let ggsw_level_forking_configuration = matrix_in.decompression_fork_config(Uniform);

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = loop_generator
                .par_try_fork_from_config(ggsw_level_forking_configuration)
                .expect("Failed to split generator into glwe");

            matrix_in
                .as_seeded_glwe_list()
                .par_iter()
                .zip(matrix_out.as_mut_glwe_list().par_iter_mut())
                .zip(gen_iter)
                .for_each(
                    |((row_glwe_in, mut row_glwe_out), mut inner_loop_generator)| {
                        decompress_seeded_glwe_ciphertext_with_pre_seeded_generator::<_, _, _, Gen>(
                            &mut row_glwe_out,
                            &row_glwe_in,
                            &mut inner_loop_generator,
                        );
                    },
                );
        });
}

/// Parallel variant of [`decompress_seeded_ggsw_ciphertext`].
pub fn par_decompress_seeded_ggsw_ciphertext<Scalar, InputCont, OutputCont, Gen>(
    output_ggsw: &mut GgswCiphertext<OutputCont>,
    input_seeded_ggsw: &SeededGgswCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus + Send + Sync,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator + ByteRandomGenerator,
{
    let mut generator = MaskRandomGenerator::<Gen>::new(input_seeded_ggsw.compression_seed());
    par_decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator::<_, _, _, Gen>(
        output_ggsw,
        input_seeded_ggsw,
        &mut generator,
    );
}
