use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::{ByteRandomGenerator, ParallelByteRandomGenerator};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::dispersion::DispersionParameter;
use crate::core_crypto::specification::parameters::*;
use rayon::prelude::*;

pub fn generate_lwe_private_functional_packing_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
    ScalarFunc,
    PolyCont,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    lwe_pfpksk: &mut LwePrivateFunctionalPackingKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
    f: ScalarFunc,
    polynomial: &Polynomial<PolyCont>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
    ScalarFunc: Fn(Scalar) -> Scalar,
    PolyCont: Container<Element = Scalar>,
{
    assert!(
        input_lwe_secret_key.lwe_dimension() == lwe_pfpksk.input_lwe_key_dimension(),
        "TODO error message"
    );
    assert!(
        output_glwe_secret_key.glwe_dimension() == lwe_pfpksk.output_glwe_key_dimension(),
        "TODO error message"
    );
    assert!(
        output_glwe_secret_key.polynomial_size() == lwe_pfpksk.output_polynomial_size(),
        "TODO error message"
    );

    // We instantiate a buffer
    let mut messages = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(
            lwe_pfpksk.decomposition_level_count().0 * lwe_pfpksk.output_polynomial_size().0,
        ),
    );

    // We retrieve decomposition arguments
    let decomp_level_count = lwe_pfpksk.decomposition_level_count();
    let decomp_base_log = lwe_pfpksk.decomposition_base_log();
    let polynomial_size = lwe_pfpksk.output_polynomial_size();

    let last_key_iter_bit = [Scalar::MAX];
    // add minus one for the function which will be applied to the decomposed body
    // ( Scalar::MAX = -Scalar::ONE )
    let input_key_bit_iter = input_lwe_secret_key
        .as_ref()
        .iter()
        .chain(last_key_iter_bit.iter());

    let gen_iter = generator
        .fork_pfpksk_to_pfpksk_chunks::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
        )
        .unwrap();

    // loop over the before key blocks
    for ((&input_key_bit, mut keyswitch_key_block), mut loop_generator) in
        input_key_bit_iter.zip(lwe_pfpksk.iter_mut()).zip(gen_iter)
    {
        // We fill the buffer with the powers of the key bits
        for (level, mut message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .zip(messages.chunks_exact_mut(polynomial_size.0))
        {
            update_slice_with_wrapping_add_scalar_mul(
                message.as_mut(),
                polynomial.as_ref(),
                DecompositionTerm::new(
                    level,
                    decomp_base_log,
                    f(Scalar::ONE).wrapping_mul(input_key_bit),
                )
                .to_recomposition_summand(),
            );
        }

        // We encrypt the buffer
        encrypt_glwe_ciphertext_list(
            output_glwe_secret_key,
            &messages,
            &mut keyswitch_key_block,
            noise_parameters,
            &mut loop_generator,
        )
    }
}

pub fn par_generate_lwe_private_functional_packing_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
    ScalarFunc,
    PolyCont,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    lwe_pfpksk: &mut LwePrivateFunctionalPackingKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
    f: ScalarFunc,
    polynomial: &Polynomial<PolyCont>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
    ScalarFunc: Fn(Scalar) -> Scalar + Sync,
    PolyCont: Container<Element = Scalar> + Sync,
{
    assert!(
        input_lwe_secret_key.lwe_dimension() == lwe_pfpksk.input_lwe_key_dimension(),
        "TODO error message"
    );
    assert!(
        output_glwe_secret_key.glwe_dimension() == lwe_pfpksk.output_glwe_key_dimension(),
        "TODO error message"
    );
    assert!(
        output_glwe_secret_key.polynomial_size() == lwe_pfpksk.output_polynomial_size(),
        "TODO error message"
    );

    // We retrieve decomposition arguments
    let decomp_level_count = lwe_pfpksk.decomposition_level_count();
    let decomp_base_log = lwe_pfpksk.decomposition_base_log();
    let polynomial_size = lwe_pfpksk.output_polynomial_size();

    let last_key_iter_bit = [Scalar::MAX];
    // add minus one for the function which will be applied to the decomposed body
    // ( Scalar::MAX = -Scalar::ONE )
    let input_key_bit_iter = input_lwe_secret_key
        .as_ref()
        .par_iter()
        .chain(last_key_iter_bit.par_iter());

    let gen_iter = generator
        .par_fork_pfpksk_to_pfpksk_chunks::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
        )
        .unwrap();

    let palintext_count = PlaintextCount(
        lwe_pfpksk.decomposition_level_count().0 * lwe_pfpksk.output_polynomial_size().0,
    );

    // loop over the before key blocks
    input_key_bit_iter
        .zip(lwe_pfpksk.par_iter_mut())
        .zip(gen_iter)
        .for_each(
            |((&input_key_bit, mut keyswitch_key_block), mut loop_generator)| {
                // We instantiate a buffer
                let mut messages = PlaintextListOwned::new(Scalar::ZERO, palintext_count);

                // We fill the buffer with the powers of the key bits
                for (level, mut message) in (1..=decomp_level_count.0)
                    .map(DecompositionLevel)
                    .zip(messages.chunks_exact_mut(polynomial_size.0))
                {
                    update_slice_with_wrapping_add_scalar_mul(
                        message.as_mut(),
                        polynomial.as_ref(),
                        DecompositionTerm::new(
                            level,
                            decomp_base_log,
                            f(Scalar::ONE).wrapping_mul(input_key_bit),
                        )
                        .to_recomposition_summand(),
                    );
                }

                // We encrypt the buffer
                encrypt_glwe_ciphertext_list(
                    output_glwe_secret_key,
                    &messages,
                    &mut keyswitch_key_block,
                    noise_parameters,
                    &mut loop_generator,
                )
            },
        );
}
