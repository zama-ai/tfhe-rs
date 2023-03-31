//! Module containing primitives pertaining to [`LWE public functional packing keyswitch key
//! generation`](`LwePublicFunctionalPackingKeyswitchKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Fill an [`LWE public functional packing keyswitch
/// key`](`LwePublicFunctionalPackingKeyswitchKey`) with an actual key.
///
/// # Example
/// ```
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// use tfhe::core_crypto::prelude::*;
/// let lwe_dimension = LweDimension(8);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// let input_lwe_secret_key =
///     LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let output_glwe_secret_key = GlweSecretKey::generate_new_binary(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(3);
/// let mut lwe_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_dimension,
///     glwe_size,
///     polynomial_size,
///     ciphertext_modulus,
/// );
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// generate_lwe_public_functional_packing_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut lwe_pubfpksk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
/// ```
pub fn generate_lwe_public_functional_packing_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    lwe_pubfpksk: &mut LwePublicFunctionalPackingKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        input_lwe_secret_key.lwe_dimension() == lwe_pubfpksk.input_lwe_key_dimension(),
        "Mismatched LweDimension between input_lwe_secret_key {:?} and lwe_pfpksk input dimension \
        {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        lwe_pubfpksk.input_lwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.glwe_dimension() == lwe_pubfpksk.output_glwe_key_dimension(),
        "Mismatched GlweDimension between output_glwe_secret_key {:?} and lwe_pfpksk output \
        dimension {:?}.",
        output_glwe_secret_key.glwe_dimension(),
        lwe_pubfpksk.output_glwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.polynomial_size() == lwe_pubfpksk.output_polynomial_size(),
        "Mismatched PolynomialSize between output_glwe_secret_key {:?} and lwe_pfpksk output \
        polynomial size {:?}.",
        output_glwe_secret_key.polynomial_size(),
        lwe_pubfpksk.output_polynomial_size()
    );

    // We instantiate a buffer
    let mut messages = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(
            lwe_pubfpksk.decomposition_level_count().0 * lwe_pubfpksk.output_polynomial_size().0,
        ),
    );

    // We retrieve decomposition arguments
    let decomp_level_count = lwe_pubfpksk.decomposition_level_count();
    let decomp_base_log = lwe_pubfpksk.decomposition_base_log();
    let polynomial_size = lwe_pubfpksk.output_polynomial_size();

    let last_key_iter_bit = [Scalar::MAX];
    // add minus one for the function which will be applied to the decomposed body
    // ( Scalar::MAX = -Scalar::ONE )
    let input_key_bit_iter = input_lwe_secret_key
        .as_ref()
        .iter()
        .chain(last_key_iter_bit.iter());

    //TODO should we rename fork_pfpksk_to_pfpksk_chunks?
    let gen_iter = generator
        .fork_pfpksk_to_pfpksk_chunks::<Scalar>(
            decomp_level_count,
            output_glwe_secret_key.glwe_dimension().to_glwe_size(),
            output_glwe_secret_key.polynomial_size(),
            input_lwe_secret_key.lwe_dimension().to_lwe_size(),
        )
        .unwrap();

    // loop over the before key blocks
    for ((&input_key_bit, mut keyswitch_key_block), mut loop_generator) in input_key_bit_iter
        .zip(lwe_pubfpksk.iter_mut())
        .zip(gen_iter)
    {
        //we reset the buffer

        // We fill the buffer with the powers of the decomposition scale times the key bits
        for (level, mut message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .zip(messages.chunks_exact_mut(polynomial_size.0))
        {
            message.as_mut()[0] = DecompositionTerm::new(level, decomp_base_log, input_key_bit)
                .to_recomposition_summand();
        }

        // We encrypt the buffer
        encrypt_glwe_ciphertext_list(
            output_glwe_secret_key,
            &mut keyswitch_key_block,
            &messages,
            noise_parameters,
            &mut loop_generator,
        )
    }
}

/// Parallel variant of [`generate_lwe_public_functional_packing_keyswitch_key`]. You may want to
/// use this variant for better key generation times.
pub fn par_generate_lwe_public_functional_packing_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    lwe_pubfpksk: &mut LwePublicFunctionalPackingKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    KSKeyCont: ContainerMut<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        input_lwe_secret_key.lwe_dimension() == lwe_pubfpksk.input_lwe_key_dimension(),
        "Mismatched LweDimension between input_lwe_secret_key {:?} and lwe_pfpksk input dimension \
        {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        lwe_pubfpksk.input_lwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.glwe_dimension() == lwe_pubfpksk.output_glwe_key_dimension(),
        "Mismatched GlweDimension between output_glwe_secret_key {:?} and lwe_pfpksk output \
        dimension {:?}.",
        output_glwe_secret_key.glwe_dimension(),
        lwe_pubfpksk.output_glwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.polynomial_size() == lwe_pubfpksk.output_polynomial_size(),
        "Mismatched PolynomialSize between output_glwe_secret_key {:?} and lwe_pfpksk output \
        polynomial size {:?}.",
        output_glwe_secret_key.polynomial_size(),
        lwe_pubfpksk.output_polynomial_size()
    );

    // We retrieve decomposition arguments
    let decomp_level_count = lwe_pubfpksk.decomposition_level_count();
    let decomp_base_log = lwe_pubfpksk.decomposition_base_log();
    let polynomial_size = lwe_pubfpksk.output_polynomial_size();

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

    let plaintext_count = PlaintextCount(
        lwe_pubfpksk.decomposition_level_count().0 * lwe_pubfpksk.output_polynomial_size().0,
    );

    // loop over the before key blocks
    input_key_bit_iter
        .zip(lwe_pubfpksk.par_iter_mut())
        .zip(gen_iter)
        .for_each(
            |((&input_key_bit, mut keyswitch_key_block), mut loop_generator)| {
                // We instantiate a buffer
                let mut messages = PlaintextListOwned::new(Scalar::ZERO, plaintext_count);

                // We fill the buffer with the powers of the key bits
                for (level, mut message) in (1..=decomp_level_count.0)
                    .map(DecompositionLevel)
                    .zip(messages.chunks_exact_mut(polynomial_size.0))
                {
                    message.as_mut()[0] =
                        DecompositionTerm::new(level, decomp_base_log, input_key_bit)
                            .to_recomposition_summand();
                }

                // We encrypt the buffer
                encrypt_glwe_ciphertext_list(
                    output_glwe_secret_key,
                    &mut keyswitch_key_block,
                    &messages,
                    noise_parameters,
                    &mut loop_generator,
                )
            },
        );
}

#[cfg(test)]
mod test {
    use crate::core_crypto::commons::generators::DeterministicSeeder;
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::prelude::*;

    #[test]
    fn test_pubfpksk_list_gen_equivalence() {
        const NB_TESTS: usize = 10;

        for _ in 0..NB_TESTS {
            // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield
            // correct computations
            let glwe_dimension =
                GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let polynomial_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let pubfpksk_level_count = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let pubfpksk_base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let ciphertext_modulus = CiphertextModulus::new_native();

            let common_encryption_seed =
                Seed(crate::core_crypto::commons::test_tools::random_uint_between(0..u128::MAX));

            let var_small = Variance::from_variance(2f64.powf(-80.0));

            // Create the PRNG
            let mut seeder = new_seeder();
            let mut secret_generator =
                SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

            let glwe_sk: GlweSecretKeyOwned<u64> = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dimension,
                polynomial_size,
                &mut secret_generator,
            );
            let lwe_big_sk = glwe_sk.clone().into_lwe_secret_key();

            let mut par_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
                0u64,
                pubfpksk_base_log,
                pubfpksk_level_count,
                lwe_big_sk.lwe_dimension(),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let mut ser_pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
                0u64,
                pubfpksk_base_log,
                pubfpksk_level_count,
                lwe_big_sk.lwe_dimension(),
                glwe_dimension.to_glwe_size(),
                polynomial_size,
                ciphertext_modulus,
            );

            let mut seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(common_encryption_seed);
            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    seeder.seed(),
                    &mut seeder,
                );

            par_generate_lwe_public_functional_packing_keyswitch_key(
                &lwe_big_sk,
                &glwe_sk,
                &mut par_pubfpksk,
                var_small,
                &mut encryption_generator,
            );

            let mut seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(common_encryption_seed);
            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    seeder.seed(),
                    &mut seeder,
                );

            generate_lwe_public_functional_packing_keyswitch_key(
                &lwe_big_sk,
                &glwe_sk,
                &mut ser_pubfpksk,
                var_small,
                &mut encryption_generator,
            );

            assert_eq!(par_pubfpksk, ser_pubfpksk)
        }
    }
}
