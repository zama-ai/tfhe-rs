//! Module containing primitives pertaining to the generation of
//! [`standard LWE bootstrap keys`](`LweBootstrapKey`) and [`seeded standard LWE bootstrap
//! keys`](`SeededLweBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{
    CompressionSeed, DefaultRandomGenerator, Distribution, Uniform,
};
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweBootstrapKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
///     ciphertext_modulus,
/// );
///
/// generate_lwe_bootstrap_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut bsk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// for (ggsw, &input_key_bit) in bsk.iter().zip(input_lwe_secret_key.as_ref()) {
///     let decrypted_ggsw = decrypt_constant_ggsw_ciphertext(&output_glwe_secret_key, &ggsw);
///     assert_eq!(decrypted_ggsw.0, input_key_bit)
/// }
/// ```
pub fn generate_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref())
        .zip(gen_iter)
    {
        encrypt_constant_ggsw_ciphertext(
            output_glwe_secret_key,
            &mut ggsw,
            Cleartext(input_key_element.cast_into()),
            noise_distribution,
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
pub fn allocate_and_generate_new_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweBootstrapKeyOwned<OutputScalar>
where
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let mut bsk = LweBootstrapKeyOwned::new(
        OutputScalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        generator,
    );

    bsk
}

/// Parallel variant of [`generate_lwe_bootstrap_key`], it is recommended to use this function for
/// better key generation times as LWE bootstrapping keys can be quite large.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweBootstrapKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key::<u64, _>(
///     input_lwe_dimension,
///     &mut secret_generator,
/// );
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
///     ciphertext_modulus,
/// );
///
/// par_generate_lwe_bootstrap_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut bsk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// assert!(!bsk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn par_generate_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    OutputCont: ContainerMut<Element = OutputScalar>,
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
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_ggsw_ciphertext(
                output_glwe_secret_key,
                &mut ggsw,
                Cleartext(input_key_element.cast_into()),
                noise_distribution,
                &mut generator,
            );
        });
}

/// Parallel variant of [`allocate_and_generate_new_lwe_bootstrap_key`], it is recommended to use
/// this function for better key generation times as LWE bootstrapping keys can be quite large.
///
/// See [`programmable_bootstrap_lwe_ciphertext`] for usage.
pub fn par_allocate_and_generate_new_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweBootstrapKeyOwned<OutputScalar>
where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut bsk = LweBootstrapKeyOwned::new(
        OutputScalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
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
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed(),
        noise_seeder,
    );

    generate_seeded_lwe_bootstrap_key_with_pre_seeded_generator(
        input_lwe_secret_key,
        output_glwe_secret_key,
        output,
        noise_distribution,
        &mut generator,
    )
}

pub fn generate_seeded_lwe_bootstrap_key_with_pre_seeded_generator<
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    ByteGen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<ByteGen>,
) where
    NoiseDistribution: Distribution,
    InputKeyCont: Container,
    OutputKeyCont: Container,
    OutputCont: ContainerMut<Element = OutputKeyCont::Element>,
    InputKeyCont::Element: Copy + CastInto<OutputKeyCont::Element>,
    OutputKeyCont::Element: Encryptable<Uniform, NoiseDistribution>,
    ByteGen: ByteRandomGenerator,
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref())
        .zip(gen_iter)
    {
        encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator(
            output_glwe_secret_key,
            &mut ggsw,
            Cleartext(input_key_element.cast_into()),
            noise_distribution,
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
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweBootstrapKeyOwned<OutputScalar>
where
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweBootstrapKeyOwned::new(
        OutputScalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        noise_seeder,
    );

    bsk
}

pub fn allocate_and_generate_lwe_bootstrapping_key_with_pre_seeded_generator<
    LweCont,
    GlweCont,
    ByteGen,
>(
    input_lwe_secret_key: &LweSecretKey<LweCont>,
    output_glwe_secret_key: &GlweSecretKey<GlweCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: DynamicDistribution<GlweCont::Element>,
    ciphertext_modulus: CiphertextModulus<GlweCont::Element>,
    generator: &mut EncryptionRandomGenerator<ByteGen>,
) -> SeededLweBootstrapKeyOwned<GlweCont::Element>
where
    LweCont: Container,
    GlweCont: Container,
    LweCont::Element: Copy + CastInto<GlweCont::Element>,
    GlweCont::Element:
        UnsignedInteger + Encryptable<Uniform, DynamicDistribution<GlweCont::Element>>,
    ByteGen: ByteRandomGenerator,
{
    let mut lwe_bootstrapping_key = SeededLweBootstrapKeyOwned::new(
        GlweCont::Element::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        generator.mask_generator().current_compression_seed(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_bootstrap_key_with_pre_seeded_generator(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut lwe_bootstrapping_key,
        noise_distribution,
        generator,
    );

    lwe_bootstrapping_key
}

/// Parallel variant of [`generate_seeded_lwe_bootstrap_key`], it is recommended to use this
/// function for better key generation times as LWE bootstrapping keys can be quite large.
pub fn par_generate_seeded_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    OutputCont: ContainerMut<Element = OutputScalar>,
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

    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed(),
        noise_seeder,
    );

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator(
                output_glwe_secret_key,
                &mut ggsw,
                Cleartext(input_key_element.cast_into()),
                noise_distribution,
                &mut generator,
            );
        });
}

/// Parallel variant of [`allocate_and_generate_new_seeded_lwe_bootstrap_key`], it is recommended to
/// use this function for better key generation times as LWE bootstrapping keys can be quite large.
pub fn par_allocate_and_generate_new_seeded_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweBootstrapKeyOwned<OutputScalar>
where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut bsk = SeededLweBootstrapKeyOwned::new(
        OutputScalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    par_generate_seeded_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        noise_seeder,
    );

    bsk
}

/// A generator for producing chunks of an LWE bootstrap key.
///
/// This struct allows for the generation of LWE bootstrap key chunks, which can be used to
/// construct a full LWE bootstrap key. The generator ensures that the final key would be equivalent
/// to the non-chunked generation.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// let input_lwe_dimension = LweDimension(742);
/// let chunk_size = ChunkSize(100);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus: CiphertextModulus<u64> = CiphertextModulus::new_native();
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
/// let chunk_generator = LweBootstrapKeyChunkGenerator::new(
///     &mut encryption_generator,
///     chunk_size,
///     input_lwe_dimension,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     glwe_noise_distribution,
///     false,
/// );
/// let chunks = chunk_generator.collect::<Vec<_>>();
/// let assembled_bsk = allocate_and_assemble_lwe_bootstrap_key_from_chunks(chunks.as_slice());
///
/// for (ggsw, &input_key_bit) in assembled_bsk.iter().zip(input_lwe_secret_key.as_ref()) {
///     let decrypted_ggsw = decrypt_constant_ggsw_ciphertext(&output_glwe_secret_key, &ggsw);
///     assert_eq!(decrypted_ggsw.0, input_key_bit)
/// }
/// ```
pub struct LweBootstrapKeyChunkGenerator<'a, Gen, Cont, Scalar, NoiseDistribution>
where
    Gen: ByteRandomGenerator,
    NoiseDistribution: Distribution,
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Cont: Container<Element = Scalar>,
{
    enc_generator: &'a mut EncryptionRandomGenerator<Gen>,
    chunk_size: ChunkSize,
    lwe_dim: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    input_lwe_secret_key: &'a LweSecretKey<Cont>,
    output_glwe_secret_key: &'a GlweSecretKey<Cont>,
    noise_distribution: NoiseDistribution,
    position: usize,
    parallel: bool,
}

impl<'a, Gen, Cont, Scalar, NoiseDistribution>
    LweBootstrapKeyChunkGenerator<'a, Gen, Cont, Scalar, NoiseDistribution>
where
    Gen: ByteRandomGenerator,
    NoiseDistribution: Distribution,
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Cont: Container<Element = Scalar>,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::use_self)]
    pub fn new(
        enc_generator: &'a mut EncryptionRandomGenerator<Gen>,
        chunk_size: ChunkSize,
        lwe_dim: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        input_lwe_secret_key: &'a LweSecretKey<Cont>,
        output_glwe_secret_key: &'a GlweSecretKey<Cont>,
        noise_distribution: NoiseDistribution,
        parallel: bool,
    ) -> LweBootstrapKeyChunkGenerator<'a, Gen, Cont, Scalar, NoiseDistribution> {
        assert!(chunk_size.0 <= lwe_dim.0);
        Self {
            enc_generator,
            chunk_size,
            lwe_dim,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
            input_lwe_secret_key,
            output_glwe_secret_key,
            noise_distribution,
            position: 0,
            parallel,
        }
    }
}

impl<Gen, Cont, Scalar, NoiseDistribution> Iterator
    for LweBootstrapKeyChunkGenerator<'_, Gen, Cont, Scalar, NoiseDistribution>
where
    Gen: ParallelByteRandomGenerator,
    NoiseDistribution: Distribution + Sync,
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Cont: Container<Element = Scalar> + Sync,
{
    type Item = LweBootstrapKeyChunkOwned<Scalar>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_size.0 == 0 || self.position >= self.lwe_dim.0 {
            return None;
        }

        let left = self.lwe_dim.0 - self.position;
        let chunk_size = if left < self.chunk_size.0 {
            ChunkSize(left)
        } else {
            self.chunk_size
        };

        let mut chunk = LweBootstrapKeyChunkOwned::new(
            Scalar::ZERO,
            self.glwe_size,
            self.polynomial_size,
            self.decomposition_base_log,
            self.decomposition_level_count,
            chunk_size,
            self.ciphertext_modulus,
        );

        if self.parallel {
            par_generate_chunked_lwe_bootstrap_key(
                self.input_lwe_secret_key,
                self.output_glwe_secret_key,
                &mut chunk,
                self.noise_distribution,
                self.enc_generator,
                self.position,
            )
        } else {
            generate_chunked_lwe_bootstrap_key(
                self.input_lwe_secret_key,
                self.output_glwe_secret_key,
                &mut chunk,
                self.noise_distribution,
                self.enc_generator,
                self.position,
            )
        }

        self.position += chunk_size.0;

        Some(chunk)
    }
}

/// Fill an [`LWE bootstrap key chunk`](`LweBootstrapKeyChunk`) with a part of a bootstrapping key.
/// It is constructed from a target chunk of an input key [`LWE secret key`](`LweSecretKey`)
/// and an output key [`GLWE secret key`](`GlweSecretKey`).
///
/// The chunk is defined by `chunk_start`, and the chunk size of the output.
///
/// Chunks can be assembled into a full [`LweBootstrapKey`] using
/// [`assemble_lwe_bootstrap_key_from_chunks`].
///
/// Consider using the [`ChunkGenerator`](`LweBootstrapKeyChunkGenerator`) to make sure you have
/// an equivalent key to the non-chunked version.
///
/// Consider using [`par_generate_chunked_lwe_bootstrap_key`] for better key generation times.
///
/// WARNING: this assumes the caller manages the random generator and the order of generation to
/// make sure the key is equivalent to the non-chunked version.
pub fn generate_chunked_lwe_bootstrap_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKeyChunk<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let chunk_end = chunk_start + output.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_secret_key.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_secret_key.lwe_dimension()
    );

    assert!(
        output.chunk_size().0 <= input_lwe_secret_key.lwe_dimension().0,
        "Chunk size is larger than the input LWE secret key LweDimension. \
        LWE bootstrap key ChunkSize: {:?}, Input LWE secret key LweDimension {:?}.",
        output.chunk_size(),
        input_lwe_secret_key.lwe_dimension()
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref()[chunk_start..chunk_end].iter())
        .zip(gen_iter)
    {
        encrypt_constant_ggsw_ciphertext(
            output_glwe_secret_key,
            &mut ggsw,
            Cleartext(input_key_element),
            noise_distribution,
            &mut generator,
        );
    }
}

/// Parallel variant of [`generate_chunked_lwe_bootstrap_key`] for better key generation times.
pub fn par_generate_chunked_lwe_bootstrap_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKeyChunk<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    let chunk_end = chunk_start + output.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_secret_key.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_secret_key.lwe_dimension()
    );

    assert!(
        output.chunk_size().0 <= input_lwe_secret_key.lwe_dimension().0,
        "Chunk size is larger than the input LWE secret key LweDimension. \
        LWE bootstrap key ChunkSize: {:?}, Input LWE secret key LweDimension {:?}.",
        output.chunk_size(),
        input_lwe_secret_key.lwe_dimension()
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
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref()[chunk_start..chunk_end].par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_ggsw_ciphertext(
                output_glwe_secret_key,
                &mut ggsw,
                Cleartext(input_key_element),
                noise_distribution,
                &mut generator,
            );
        });
}

/// Assemble a vector of [`LweBootstrapKeyChunk`] into an [`LweBootstrapKey`].
///
/// This function takes a vector of `LweBootstrapKeyChunk` and assemble them into a single
/// `LweBootstrapKey`. It considers that chunks are in the correct order, and that they would fill
/// the `LweBootstrapKey`.
pub fn assemble_lwe_bootstrap_key_from_chunks<Scalar, Cont, ContMut>(
    output: &mut LweBootstrapKey<ContMut>,
    chunks: &[LweBootstrapKeyChunk<Cont>],
) where
    Scalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
    ContMut: ContainerMut<Element = Scalar>,
{
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let chunks_lwe_dimension = LweDimension(total_chunk_size);
    assert!(chunks_lwe_dimension == output.input_lwe_dimension());

    let mut start: usize = 0;
    for chunk in chunks {
        assert!(output.glwe_size() == chunk.glwe_size());
        assert!(output.polynomial_size() == chunk.polynomial_size());
        assert!(output.decomposition_base_log() == chunk.decomposition_base_log());
        assert!(output.decomposition_level_count() == chunk.decomposition_level_count());
        assert!(output.ciphertext_modulus() == chunk.ciphertext_modulus());

        let end = start + chunk.as_ref().len();
        output.as_mut()[start..end].copy_from_slice(chunk.as_ref());
        start = end;
    }
}

/// Allocate a new [`LweBootstrapKey`] and assemble it from a vector of [`LweBootstrapKeyChunk`].
///
/// This function takes multiple `LweBootstrapKeyChunk` and assemble them into a single
/// `LweBootstrapKey`. It considers that chunks are in the correct order.
pub fn allocate_and_assemble_lwe_bootstrap_key_from_chunks<Scalar, Cont>(
    chunks: &[LweBootstrapKeyChunk<Cont>],
) -> LweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element = Scalar>,
{
    assert!(!chunks.is_empty());
    let glwe_size = chunks[0].glwe_size();
    let polynomial_size = chunks[0].polynomial_size();
    let decomp_base_log = chunks[0].decomposition_base_log();
    let decomp_level_count = chunks[0].decomposition_level_count();
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let input_lwe_dimension = LweDimension(total_chunk_size);
    let ciphertext_modulus = chunks[0].ciphertext_modulus();

    let mut assembled_bsk = LweBootstrapKey::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        ciphertext_modulus,
    );

    assemble_lwe_bootstrap_key_from_chunks(&mut assembled_bsk, chunks);

    assembled_bsk
}

/// A generator for producing chunks of a Seeded LWE bootstrap key.
///
/// This struct allows for the generation of Seeded LWE bootstrap key chunks, which can be used to
/// construct a full Seeded LWE bootstrap key. The generator ensures that the final key would be
/// equivalent to the non-chunked generation.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::commons::math::random::CompressionSeed;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// let input_lwe_dimension = LweDimension(742);
/// let chunk_size = ChunkSize(100);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let glwe_dimension = GlweDimension(1);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus: CiphertextModulus<u64> = CiphertextModulus::new_native();
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let compression_seed = CompressionSeed::from(seeder.seed());
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_dimension,
///     polynomial_size,
///     &mut secret_generator,
/// );
/// let chunk_generator = SeededLweBootstrapKeyChunkGenerator::new(
///     chunk_size,
///     input_lwe_dimension,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     glwe_noise_distribution,
///     compression_seed,
///     seeder,
///     false,
/// );
/// let chunks = chunk_generator.collect::<Vec<_>>();
/// let assembled_bsk =
///     allocate_and_assemble_seeded_lwe_bootstrap_key_from_chunks(chunks.as_slice());
/// ```
pub struct SeededLweBootstrapKeyChunkGenerator<'a, Cont, Scalar, NoiseDistribution>
where
    NoiseDistribution: Distribution,
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Cont: Container<Element = Scalar>,
{
    enc_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    chunk_size: ChunkSize,
    lwe_dim: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    input_lwe_secret_key: &'a LweSecretKey<Cont>,
    output_glwe_secret_key: &'a GlweSecretKey<Cont>,
    noise_distribution: NoiseDistribution,
    compression_seed: CompressionSeed,
    position: usize,
    parallel: bool,
}

impl<'a, Cont, Scalar, NoiseDistribution>
    SeededLweBootstrapKeyChunkGenerator<'a, Cont, Scalar, NoiseDistribution>
where
    NoiseDistribution: Distribution,
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Cont: Container<Element = Scalar>,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::use_self)]
    pub fn new<NoiseSeeder>(
        chunk_size: ChunkSize,
        lwe_dim: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        input_lwe_secret_key: &'a LweSecretKey<Cont>,
        output_glwe_secret_key: &'a GlweSecretKey<Cont>,
        noise_distribution: NoiseDistribution,
        compression_seed: CompressionSeed,
        noise_seeder: &'a mut NoiseSeeder,
        parallel: bool,
    ) -> SeededLweBootstrapKeyChunkGenerator<'a, Cont, Scalar, NoiseDistribution>
    where
        // Maybe Sized allows to pass Box<dyn Seeder>.
        NoiseSeeder: Seeder + ?Sized,
    {
        assert!(chunk_size.0 <= lwe_dim.0);
        let enc_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            compression_seed.clone(),
            noise_seeder,
        );
        Self {
            enc_generator,
            chunk_size,
            lwe_dim,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
            input_lwe_secret_key,
            output_glwe_secret_key,
            noise_distribution,
            compression_seed,
            position: 0,
            parallel,
        }
    }
}

impl<Cont, Scalar, NoiseDistribution> Iterator
    for SeededLweBootstrapKeyChunkGenerator<'_, Cont, Scalar, NoiseDistribution>
where
    NoiseDistribution: Distribution + Sync,
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    Cont: Container<Element = Scalar> + Sync,
{
    type Item = SeededLweBootstrapKeyChunkOwned<Scalar>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_size.0 == 0 || self.position >= self.lwe_dim.0 {
            return None;
        }

        let left = self.lwe_dim.0 - self.position;
        let chunk_size = if left < self.chunk_size.0 {
            ChunkSize(left)
        } else {
            self.chunk_size
        };

        let mut chunk = SeededLweBootstrapKeyChunkOwned::new(
            Scalar::ZERO,
            self.glwe_size,
            self.polynomial_size,
            self.decomposition_base_log,
            self.decomposition_level_count,
            chunk_size,
            self.compression_seed.clone(),
            self.ciphertext_modulus,
        );

        if self.parallel {
            par_generate_chunked_seeded_lwe_bootstrap_key(
                self.input_lwe_secret_key,
                self.output_glwe_secret_key,
                &mut chunk,
                self.noise_distribution,
                &mut self.enc_generator,
                self.position,
            )
        } else {
            generate_chunked_seeded_lwe_bootstrap_key(
                self.input_lwe_secret_key,
                self.output_glwe_secret_key,
                &mut chunk,
                self.noise_distribution,
                &mut self.enc_generator,
                self.position,
            )
        }

        self.position += chunk_size.0;

        Some(chunk)
    }
}

/// Fill a [`seeded LWE bootstrap key chunk`](`SeededLweBootstrapKeyChunk`) with a part of a seeded
/// bootstrapping key constructed from a target chunk of an input key [`LWE secret
/// key`](`LweSecretKey`) and an output key [`GLWE secret key`](`GlweSecretKey`)
///
/// Consider using [`par_generate_chunked_seeded_lwe_bootstrap_key`] for better key generation
/// times.
///
/// WARNING: this assumes the caller manages the random generator and the order of generation to
/// make sure the key is equivalent to the non-chunked version.
pub fn generate_chunked_seeded_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKeyChunk<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    InputScalar: Copy + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let chunk_end = chunk_start + output.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_secret_key.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_secret_key.lwe_dimension()
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref()[chunk_start..chunk_end].iter())
        .zip(gen_iter)
    {
        encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator(
            output_glwe_secret_key,
            &mut ggsw,
            Cleartext(input_key_element.cast_into()),
            noise_distribution,
            &mut generator,
        );
    }
}

/// Parallel variant of [`generate_chunked_seeded_lwe_bootstrap_key`], it is recommended to use this
/// function for better key generation times as LWE bootstrapping keys can be quite large.
pub fn par_generate_chunked_seeded_lwe_bootstrap_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut SeededLweBootstrapKeyChunk<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    InputScalar: Copy + CastInto<OutputScalar> + Sync,
    OutputScalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar> + Sync,
    OutputCont: ContainerMut<Element = OutputScalar>,
    Gen: ParallelByteRandomGenerator,
{
    let chunk_end = chunk_start + output.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_secret_key.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_secret_key.lwe_dimension()
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
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref()[chunk_start..chunk_end].par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_constant_seeded_ggsw_ciphertext_with_pre_seeded_generator(
                output_glwe_secret_key,
                &mut ggsw,
                Cleartext(input_key_element.cast_into()),
                noise_distribution,
                &mut generator,
            );
        });
}

/// Assemble a vector of [`SeededLweBootstrapKeyChunk`] into an [`SeededLweBootstrapKey`].
///
/// This function takes a vector of `SeededLweBootstrapKeyChunk` and assemble them into a single
/// `SeededLweBootstrapKey`. It considers that chunks are in the correct order, and that they would
/// fill the `SeededLweBootstrapKey`.
pub fn assemble_seeded_lwe_bootstrap_key_from_chunks<Scalar, Cont, ContMut>(
    output: &mut SeededLweBootstrapKey<ContMut>,
    chunks: &[SeededLweBootstrapKeyChunk<Cont>],
) where
    Scalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
    ContMut: ContainerMut<Element = Scalar>,
{
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let chunks_lwe_dimension = LweDimension(total_chunk_size);
    assert!(chunks_lwe_dimension == output.input_lwe_dimension());

    let mut start: usize = 0;
    for chunk in chunks {
        assert!(output.glwe_size() == chunk.glwe_size());
        assert!(output.polynomial_size() == chunk.polynomial_size());
        assert!(output.decomposition_base_log() == chunk.decomposition_base_log());
        assert!(output.decomposition_level_count() == chunk.decomposition_level_count());
        assert!(output.ciphertext_modulus() == chunk.ciphertext_modulus());
        assert!(output.compression_seed() == chunk.compression_seed());

        let end = start + chunk.as_ref().len();
        output.as_mut()[start..end].copy_from_slice(chunk.as_ref());
        start = end;
    }
}

/// Allocate a new [`SeededLweBootstrapKey`] and assemble it from a vector of
/// [`SeededLweBootstrapKeyChunk`].
///
/// This function takes multiple `SeededLweBootstrapKeyChunk` and assemble them into a single
/// `SeededLweBootstrapKey`. It considers that chunks are in the correct order.
pub fn allocate_and_assemble_seeded_lwe_bootstrap_key_from_chunks<Scalar, Cont>(
    chunks: &[SeededLweBootstrapKeyChunk<Cont>],
) -> SeededLweBootstrapKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element = Scalar>,
{
    assert!(!chunks.is_empty());
    let glwe_size = chunks[0].glwe_size();
    let polynomial_size = chunks[0].polynomial_size();
    let decomp_base_log = chunks[0].decomposition_base_log();
    let decomp_level_count = chunks[0].decomposition_level_count();
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let input_lwe_dimension = LweDimension(total_chunk_size);
    let ciphertext_modulus = chunks[0].ciphertext_modulus();
    let compression_seed = chunks[0].compression_seed();

    let mut assembled_bsk = SeededLweBootstrapKey::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        decomp_base_log,
        decomp_level_count,
        input_lwe_dimension,
        compression_seed,
        ciphertext_modulus,
    );

    assemble_seeded_lwe_bootstrap_key_from_chunks(&mut assembled_bsk, chunks);

    assembled_bsk
}
