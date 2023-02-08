//! Module containing primitives pertaining to the generation of
//! [`standard LWE bootstrap keys`](`LweBootstrapKey`) and [`seeded standard LWE bootstrap
//! keys`](`SeededLweBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Fill an [`LWE bootstrap key`](`LweBootstrapKey`) with an actual bootstrapping key constructed
/// from an input key [`LWE secret key`](`LweSecretKey`) and an output key
/// [`GLWE secret key`](`GlweSecretKey`)
///
/// Consider using [`par_generate_lwe_bootstrap_key`] for better key generation times.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweBootstrapKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut bsk = LweBootstrapKey::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
/// );
///
/// generate_lwe_bootstrap_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut bsk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// for (ggsw, &input_key_bit) in bsk.iter().zip(input_lwe_secret_key.as_ref()) {
///     let decrypted_ggsw = decrypt_constant_ggsw_ciphertext(&output_glwe_secret_key, &ggsw);
///     assert_eq!(decrypted_ggsw.0, input_key_bit)
/// }
/// ```
pub fn generate_lwe_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, OutputCont, Gen>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .fork_bsk_to_ggsw::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref())
        .zip(gen_iter)
    {
        encrypt_constant_ggsw_ciphertext(
            output_glwe_secret_key,
            &mut ggsw,
            Plaintext(input_key_element),
            noise_parameters,
            &mut generator,
        );
    }
}

/// Allocate a new [`LWE bootstrap key`](`LweBootstrapKey`) and fill it with an actual bootstrapping
/// key constructed from an input key [`LWE secret key`](`LweSecretKey`) and an output key
/// [`GLWE secret key`](`GlweSecretKey`).
///
/// Consider using [`par_allocate_and_generate_new_lwe_bootstrap_key`] for better key generation
/// times.
pub fn allocate_and_generate_new_lwe_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut bsk = LweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
    );

    generate_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        generator,
    );

    bsk
}

/// Parallel variant of [`generate_lwe_bootstrap_key`], it is recommended to use this function for
/// better key generation times as LWE bootstrapping keys can be quite large.
pub fn par_generate_lwe_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, OutputCont, Gen>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .par_fork_bsk_to_ggsw::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_ggsw_ciphertext(
                output_glwe_secret_key,
                &mut ggsw,
                Plaintext(input_key_element),
                noise_parameters,
                &mut generator,
            );
        })
}

/// Parallel variant of [`allocate_and_generate_new_lwe_bootstrap_key`], it is recommended to use
/// this function for better key generation times as LWE bootstrapping keys can be quite large.
///
/// See [`programmable_bootstrap_lwe_ciphertext`] for usage.
pub fn par_allocate_and_generate_new_lwe_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut bsk = LweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
    );

    par_generate_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        generator,
    );

    bsk
}

/// Fill a [`seeded LWE bootstrap key`](`SeededLweBootstrapKey`) with an actual seeded bootstrapping
/// key constructed from an input key [`LWE secret key`](`LweSecretKey`) and an output key
/// [`GLWE secret key`](`GlweSecretKey`)
///
/// Consider using [`par_generate_seeded_lwe_bootstrap_key`] for better key generation times.
pub fn generate_seeded_lwe_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    let gen_iter = generator
        .fork_bsk_to_ggsw::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref())
        .zip(gen_iter)
    {
        encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator(
            output_glwe_secret_key,
            &mut ggsw,
            Plaintext(input_key_element),
            noise_parameters,
            &mut generator,
        );
    }
}

/// Allocate a new [`seeded LWE bootstrap key`](`SeededLweBootstrapKey`) and fill it with an actual
/// seeded bootstrapping key constructed from an input key [`LWE secret key`](`LweSecretKey`) and an
/// output key [`GLWE secret key`](`GlweSecretKey`)
///
/// Consider using [`par_allocate_and_generate_new_seeded_lwe_bootstrap_key`] for better key
/// generation times.
pub fn allocate_and_generate_new_seeded_lwe_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        noise_seeder.seed().into(),
    );

    generate_seeded_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        noise_seeder,
    );

    bsk
}

/// Parallel variant of [`generate_seeded_lwe_bootstrap_key`], it is recommended to use this
/// function for better key generation times as LWE bootstrapping keys can be quite large.
pub fn par_generate_seeded_lwe_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKey<OutputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    let gen_iter = generator
        .par_fork_bsk_to_ggsw::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_seeded_ggsw_ciphertext_with_existing_generator(
                output_glwe_secret_key,
                &mut ggsw,
                Plaintext(input_key_element),
                noise_parameters,
                &mut generator,
            );
        })
}

/// Parallel variant of [`allocate_and_generate_new_seeded_lwe_bootstrap_key`], it is recommended to
/// use this function for better key generation times as LWE bootstrapping keys can be quite large.
pub fn par_allocate_and_generate_new_seeded_lwe_bootstrap_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        noise_seeder.seed().into(),
    );

    par_generate_seeded_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_parameters,
        noise_seeder,
    );

    bsk
}

#[cfg(test)]
mod parallel_test {
    use crate::core_crypto::algorithms::*;
    use crate::core_crypto::commons::dispersion::StandardDev;
    use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
    use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seed};
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    };
    use crate::core_crypto::commons::test_tools::new_secret_random_generator;
    use crate::core_crypto::entities::*;

    fn test_parallel_and_seeded_bsk_gen_equivalence<T: UnsignedTorus + Sync + Send>() {
        for _ in 0..10 {
            let lwe_dim =
                LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let glwe_dim =
                GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let poly_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let level = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
            let deterministic_seeder_seed =
                Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

            let mut secret_generator = new_secret_random_generator();
            let lwe_sk =
                allocate_and_generate_new_binary_lwe_secret_key(lwe_dim, &mut secret_generator);
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dim,
                poly_size,
                &mut secret_generator,
            );

            let mut parallel_bsk = LweBootstrapKeyOwned::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<ActivatedRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            par_generate_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut parallel_bsk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut sequential_bsk = LweBootstrapKeyOwned::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<ActivatedRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            generate_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut sequential_bsk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            assert_eq!(parallel_bsk, sequential_bsk);

            let mut sequential_seeded_bsk = SeededLweBootstrapKey::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
                mask_seed.into(),
            );

            generate_seeded_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut sequential_seeded_bsk,
                StandardDev::from_standard_dev(10.),
                &mut DeterministicSeeder::<ActivatedRandomGenerator>::new(
                    deterministic_seeder_seed,
                ),
            );

            let mut parallel_seeded_bsk = SeededLweBootstrapKey::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
                mask_seed.into(),
            );

            par_generate_seeded_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut parallel_seeded_bsk,
                StandardDev::from_standard_dev(10.),
                &mut DeterministicSeeder::<ActivatedRandomGenerator>::new(
                    deterministic_seeder_seed,
                ),
            );

            assert_eq!(sequential_seeded_bsk, parallel_seeded_bsk);

            let decompressed_bsk = sequential_seeded_bsk.decompress_into_lwe_bootstrap_key();

            assert_eq!(decompressed_bsk, sequential_bsk);
        }
    }

    #[test]
    fn test_parallel_and_seeded_bsk_gen_equivalence_u32() {
        test_parallel_and_seeded_bsk_gen_equivalence::<u32>()
    }

    #[test]
    fn test_parallel_and_seeded_bsk_gen_equivalence_u64() {
        test_parallel_and_seeded_bsk_gen_equivalence::<u64>()
    }
}
