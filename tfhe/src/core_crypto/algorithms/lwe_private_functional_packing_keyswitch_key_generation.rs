//! Module containing primitives pertaining to [`LWE private functional packing keyswitch key
//! generation`](`LwePrivateFunctionalPackingKeyswitchKey`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Fill an [`LWE private functional packing keyswitch
/// key`](`LwePrivateFunctionalPackingKeyswitchKey`) with an actual key.
///
/// Consider using [`par_generate_lwe_private_functional_packing_keyswitch_key`] for better key
/// generation times.
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
        "Mismatched LweDimension between input_lwe_secret_key {:?} and lwe_pfpksk input dimension \
        {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        lwe_pfpksk.input_lwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.glwe_dimension() == lwe_pfpksk.output_glwe_key_dimension(),
        "Mismatched GlweDimension between output_glwe_secret_key {:?} and lwe_pfpksk output \
        dimension {:?}.",
        output_glwe_secret_key.glwe_dimension(),
        lwe_pfpksk.output_glwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.polynomial_size() == lwe_pfpksk.output_polynomial_size(),
        "Mismatched PolynomialSize between output_glwe_secret_key {:?} and lwe_pfpksk output \
        polynomial size {:?}.",
        output_glwe_secret_key.polynomial_size(),
        lwe_pfpksk.output_polynomial_size()
    );
    assert!(
        lwe_pfpksk.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        lwe_pfpksk.ciphertext_modulus()
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
        // Reset the buffer before using it in assign operations
        messages.as_mut().fill(Scalar::ZERO);

        // We fill the buffer with the powers of the key bits
        for (level, mut message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .zip(messages.chunks_exact_mut(polynomial_size.0))
        {
            slice_wrapping_add_scalar_mul_assign(
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
            &mut keyswitch_key_block,
            &messages,
            noise_parameters,
            &mut loop_generator,
        )
    }
}

/// Parallel variant of [`generate_lwe_private_functional_packing_keyswitch_key`]. You may want to
/// use this variant for better key generation times.
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
        "Mismatched LweDimension between input_lwe_secret_key {:?} and lwe_pfpksk input dimension \
        {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        lwe_pfpksk.input_lwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.glwe_dimension() == lwe_pfpksk.output_glwe_key_dimension(),
        "Mismatched GlweDimension between output_glwe_secret_key {:?} and lwe_pfpksk output \
        dimension {:?}.",
        output_glwe_secret_key.glwe_dimension(),
        lwe_pfpksk.output_glwe_key_dimension()
    );
    assert!(
        output_glwe_secret_key.polynomial_size() == lwe_pfpksk.output_polynomial_size(),
        "Mismatched PolynomialSize between output_glwe_secret_key {:?} and lwe_pfpksk output \
        polynomial size {:?}.",
        output_glwe_secret_key.polynomial_size(),
        lwe_pfpksk.output_polynomial_size()
    );
    assert!(
        lwe_pfpksk.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli, got modulus {:?}",
        lwe_pfpksk.ciphertext_modulus()
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

    let plaintext_count = PlaintextCount(
        lwe_pfpksk.decomposition_level_count().0 * lwe_pfpksk.output_polynomial_size().0,
    );

    // loop over the before key blocks
    input_key_bit_iter
        .zip(lwe_pfpksk.par_iter_mut())
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
                    slice_wrapping_add_scalar_mul_assign(
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
    fn test_pfpksk_list_gen_equivalence() {
        const NB_TESTS: usize = 10;

        for _ in 0..NB_TESTS {
            // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield
            // correct computations
            let glwe_dimension =
                GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let polynomial_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let pfpksk_level_count = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let pfpksk_base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );

            let common_encryption_seed =
                Seed(crate::core_crypto::commons::test_tools::random_uint_between(0..u128::MAX));

            let var_small = Variance::from_variance(2f64.powf(-80.0));

            let ciphertext_modulus = CiphertextModulus::new_native();

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

            let mut seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(common_encryption_seed);
            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    seeder.seed(),
                    &mut seeder,
                );

            let par_cbs_pfpksk = par_allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
                &lwe_big_sk,
                &glwe_sk,
                pfpksk_base_log,
                pfpksk_level_count,
                var_small,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let mut seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(common_encryption_seed);
            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    seeder.seed(),
                    &mut seeder,
                );

            let ser_cbs_pfpksk = allocate_and_generate_new_circuit_bootstrap_lwe_pfpksk_list(
                &lwe_big_sk,
                &glwe_sk,
                pfpksk_base_log,
                pfpksk_level_count,
                var_small,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            assert_eq!(par_cbs_pfpksk, ser_cbs_pfpksk)
        }
    }
}
