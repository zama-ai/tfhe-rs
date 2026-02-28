//! Module with primitives pertaining to [`SeededLweMultiBitBootstrapKey`] decompression.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::math::random::Uniform;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweMultiBitBootstrapKey`] between all functions needing it.
pub fn decompress_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator<
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

    // Forking logic must match multi bit BSK generation
    let output_grouping_factor = output_bsk.grouping_factor();
    let ggsw_per_multi_bit_element = output_grouping_factor.ggsw_per_multi_bit_element();

    let forking_config = input_bsk.decompression_fork_config(Uniform);

    let gen_iter = generator.try_fork_from_config(forking_config).unwrap();

    for ((mut output_ggsw_group, input_ggsw_group), mut loop_generator) in output_bsk
        .chunks_exact_mut(ggsw_per_multi_bit_element.0)
        .zip(input_bsk.chunks_exact(ggsw_per_multi_bit_element.0))
        .zip(gen_iter)
    {
        let group_forking_config = input_ggsw_group.decompression_fork_config(Uniform);

        let gen_iter = loop_generator
            .try_fork_from_config(group_forking_config)
            .unwrap();

        for ((mut output_ggsw, input_ggsw), mut inner_loop_generator) in output_ggsw_group
            .iter_mut()
            .zip(input_ggsw_group.iter())
            .zip(gen_iter)
        {
            decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator(
                &mut output_ggsw,
                &input_ggsw,
                &mut inner_loop_generator,
            );
        }
    }
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

    let mut generator = MaskRandomGenerator::<Gen>::new(input_bsk.compression_seed());
    decompress_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator::<_, _, _, Gen>(
        output_bsk,
        input_bsk,
        &mut generator,
    );
}

/// Parallel variant of [`decompress_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator`].
pub fn par_decompress_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator<
    Scalar,
    InputCont,
    OutputCont,
    Gen,
>(
    output_bsk: &mut LweMultiBitBootstrapKey<OutputCont>,
    input_bsk: &SeededLweMultiBitBootstrapKey<InputCont>,
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
    between input SeededLweMultiBitBootstrapKey ({:?}) and output LweMultiBitBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    // Forking logic must match multi bit BSK generation
    let output_grouping_factor = output_bsk.grouping_factor();
    let ggsw_per_multi_bit_element = output_grouping_factor.ggsw_per_multi_bit_element();

    let forking_config = input_bsk.decompression_fork_config(Uniform);

    let gen_iter = generator.par_try_fork_from_config(forking_config).unwrap();

    output_bsk
        .par_chunks_exact_mut(ggsw_per_multi_bit_element.0)
        .zip(input_bsk.par_chunks_exact(ggsw_per_multi_bit_element.0))
        .zip(gen_iter)
        .for_each(
            |((mut output_ggsw_group, input_ggsw_group), mut loop_generator)| {
                let group_forking_config = input_ggsw_group.decompression_fork_config(Uniform);

                let gen_iter = loop_generator
                    .par_try_fork_from_config(group_forking_config)
                    .unwrap();

                output_ggsw_group
                    .par_iter_mut()
                    .zip(input_ggsw_group.par_iter())
                    .zip(gen_iter)
                    .for_each(
                        |((mut output_ggsw, input_ggsw), mut inner_loop_generator)| {
                            decompress_seeded_ggsw_ciphertext_with_pre_seeded_generator(
                                &mut output_ggsw,
                                &input_ggsw,
                                &mut inner_loop_generator,
                            );
                        },
                    );
            },
        );
}

/// Parallel variant of [`decompress_seeded_lwe_multi_bit_bootstrap_key`].
pub fn par_decompress_seeded_lwe_multi_bit_bootstrap_key<Scalar, InputCont, OutputCont, Gen>(
    output_bsk: &mut LweMultiBitBootstrapKey<OutputCont>,
    input_bsk: &SeededLweMultiBitBootstrapKey<InputCont>,
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
    between input SeededLweMultiBitBootstrapKey ({:?}) and output LweMultiBitBootstrapKey ({:?})",
        input_bsk.ciphertext_modulus(),
        output_bsk.ciphertext_modulus(),
    );

    let mut generator = MaskRandomGenerator::<Gen>::new(input_bsk.compression_seed());
    par_decompress_seeded_lwe_multi_bit_bootstrap_key_with_pre_seeded_generator::<_, _, _, Gen>(
        output_bsk,
        input_bsk,
        &mut generator,
    );
}
