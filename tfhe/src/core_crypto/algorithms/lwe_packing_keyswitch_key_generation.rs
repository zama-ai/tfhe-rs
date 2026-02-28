//! Module containing primitives pertaining to [`LWE packing keyswitch keys
//! generation`](`LwePackingKeyswitchKey`) and [`seeded LWE packing keyswitch keys
//! generation`](`SeededLwePackingKeyswitchKey`).

use crate::core_crypto::algorithms::{
    encrypt_glwe_ciphertext_list, encrypt_seeded_glwe_ciphertext_list_with_pre_seeded_generator,
};
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::{
    GlweSecretKey, LwePackingKeyswitchKey, LwePackingKeyswitchKeyOwned, LweSecretKey,
    PlaintextListOwned, SeededLwePackingKeyswitchKey, SeededLwePackingKeyswitchKeyOwned,
};

/// Fill an [`LWE packing keyswitch key`](`LwePackingKeyswitchKey`) with an actual packing
/// keyswitching key constructed from an input [`LWE secret key`](`LweSecretKey`) and an output
/// [`GLWE secret key`](`GlweSecretKey`).
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LwePackingKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let output_glwe_dimension = GlweDimension(1);
/// let output_polynomial_size = PolynomialSize(2048);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
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
///     output_glwe_dimension,
///     output_polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut pksk = LwePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     output_glwe_dimension,
///     output_polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_packing_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut pksk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// assert!(!pksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_lwe_packing_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    lwe_packing_keyswitch_key: &mut LwePackingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_packing_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LwePackingKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_packing_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_packing_keyswitch_key.output_key_glwe_dimension() == output_glwe_sk.glwe_dimension(),
        "The destination LwePackingKeyswitchKey output LweDimension is not equal \
    to the output GlweSecretKey GlweDimension. Destination: {:?}, output: {:?}",
        lwe_packing_keyswitch_key.output_key_glwe_dimension(),
        output_glwe_sk.glwe_dimension()
    );
    assert!(
        lwe_packing_keyswitch_key.output_key_polynomial_size() == output_glwe_sk.polynomial_size(),
        "The destination LwePackingKeyswitchKey output PolynomialSize is not equal \
        to the output GlweSecretKey PolynomialSize. Destination: {:?}, output: {:?}",
        lwe_packing_keyswitch_key.output_key_polynomial_size(),
        output_glwe_sk.polynomial_size()
    );

    let decomp_base_log = lwe_packing_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_packing_keyswitch_key.decomposition_level_count();
    let polynomial_size = lwe_packing_keyswitch_key.output_polynomial_size();
    let ciphertext_modulus = lwe_packing_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(decomp_level_count.0 * polynomial_size.0),
    );

    // Iterate over the input key elements and the destination lwe_packing_keyswitch_key memory
    for (input_key_element, mut packing_keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_packing_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, mut messages) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *messages.get_mut(0).0 =
                DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_glwe_ciphertext_list(
            output_glwe_sk,
            &mut packing_keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

/// Allocate a new [`LWE packing keyswitch key`](`LwePackingKeyswitchKey`) and fill it with an
/// actual packing keyswitching key constructed from an input [`LWE secret key`](`LweSecretKey`) and
/// an output [`GLWE secret key`](`GlweSecretKey`).
///
/// See [`keyswitch_lwe_ciphertext_into_glwe_ciphertext`](`super::keyswitch_lwe_ciphertext_into_glwe_ciphertext`)
///  for usage.
pub fn allocate_and_generate_new_lwe_packing_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LwePackingKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_packing_keyswitch_key = LwePackingKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_glwe_sk.glwe_dimension(),
        output_glwe_sk.polynomial_size(),
        ciphertext_modulus,
    );

    generate_lwe_packing_keyswitch_key(
        input_lwe_sk,
        output_glwe_sk,
        &mut new_lwe_packing_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_lwe_packing_keyswitch_key
}

pub fn generate_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    lwe_packing_keyswitch_key: &mut SeededLwePackingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_packing_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LwePackingKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_packing_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_packing_keyswitch_key.output_key_glwe_dimension() == output_glwe_sk.glwe_dimension(),
        "The destination LwePackingKeyswitchKey output LweDimension is not equal \
    to the output GlweSecretKey GlweDimension. Destination: {:?}, output: {:?}",
        lwe_packing_keyswitch_key.output_key_glwe_dimension(),
        output_glwe_sk.glwe_dimension()
    );
    assert!(
        lwe_packing_keyswitch_key.output_key_polynomial_size() == output_glwe_sk.polynomial_size(),
        "The destination LwePackingKeyswitchKey output PolynomialSize is not equal \
        to the output GlweSecretKey PolynomialSize. Destination: {:?}, output: {:?}",
        lwe_packing_keyswitch_key.output_key_polynomial_size(),
        output_glwe_sk.polynomial_size()
    );

    let decomp_base_log = lwe_packing_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_packing_keyswitch_key.decomposition_level_count();
    let polynomial_size = lwe_packing_keyswitch_key.output_polynomial_size();
    let ciphertext_modulus = lwe_packing_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer = PlaintextListOwned::new(
        Scalar::ZERO,
        PlaintextCount(decomp_level_count.0 * polynomial_size.0),
    );

    // Iterate over the input key elements and the destination lwe_packing_keyswitch_key memory
    for (input_key_element, mut packing_keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_packing_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, mut messages) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *messages.get_mut(0).0 =
                DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_seeded_glwe_ciphertext_list_with_pre_seeded_generator(
            output_glwe_sk,
            &mut packing_keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

/// Fill an [`LWE keyswitch key`](`SeededLwePackingKeyswitchKey`) with an actual keyswitching key
/// constructed from an input [`LWE secret key`](`LweSecretKey`) and an output
/// [`GLWE secret key`](`GlweSecretKey`).
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LwePackingKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let output_glwe_dimension = GlweDimension(1);
/// let output_polynomial_size = PolynomialSize(2048);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     output_glwe_dimension,
///     output_polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut seeded_pksk = SeededLwePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     output_glwe_dimension,
///     output_polynomial_size,
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// generate_seeded_lwe_packing_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut seeded_pksk,
///     glwe_noise_distribution,
///     seeder,
/// );
///
/// assert!(!seeded_pksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_seeded_lwe_packing_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    NoiseSeeder,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    lwe_packing_keyswitch_key: &mut SeededLwePackingKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        lwe_packing_keyswitch_key.compression_seed(),
        noise_seeder,
    );

    generate_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator(
        input_lwe_sk,
        output_glwe_sk,
        lwe_packing_keyswitch_key,
        noise_distribution,
        &mut generator,
    )
}

/// Allocate a new [`seeded LWE keyswitch key`](`SeededLwePackingKeyswitchKey`) and fill it with an
/// actual packing keyswitching key constructed from an input [`LWE secret key`](`LweSecretKey`) and
/// an output [`GLWE secret key`](`GlweSecretKey`).
pub fn allocate_and_generate_new_seeded_lwe_packing_keyswitch_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLwePackingKeyswitchKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut new_lwe_packing_keyswitch_key = SeededLwePackingKeyswitchKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_glwe_sk.glwe_dimension(),
        output_glwe_sk.polynomial_size(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_packing_keyswitch_key(
        input_lwe_sk,
        output_glwe_sk,
        &mut new_lwe_packing_keyswitch_key,
        noise_distribution,
        noise_seeder,
    );

    new_lwe_packing_keyswitch_key
}
