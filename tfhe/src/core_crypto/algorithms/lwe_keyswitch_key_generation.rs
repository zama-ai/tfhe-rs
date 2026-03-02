//! Module containing primitives pertaining to [`LWE keyswitch keys
//! generation`](`LweKeyswitchKey#key-switching-key`) and [`seeded LWE keyswitch keys
//! generation`](`SeededLweKeyswitchKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{
    DecompositionLevel, DecompositionTerm, DecompositionTermNonNative,
};
use crate::core_crypto::commons::math::random::{
    CompressionSeed, DefaultRandomGenerator, Distribution, Uniform,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Fill an [`LWE keyswitch key`](`LweKeyswitchKey`) with an actual keyswitching key constructed
/// from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
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
/// let input_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(
///         output_lwe_dimension,
///         &mut secret_generator,
///     );
///
/// let mut ksk = LweKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     output_lwe_dimension,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     &mut ksk,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// assert!(!ksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_lwe_keyswitch_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        generate_lwe_keyswitch_key_native_mod_compatible(
            input_lwe_sk,
            output_lwe_sk,
            lwe_keyswitch_key,
            noise_distribution,
            generator,
        )
    } else {
        generate_lwe_keyswitch_key_other_mod(
            input_lwe_sk,
            output_lwe_sk,
            lwe_keyswitch_key,
            noise_distribution,
            generator,
        )
    }
}

pub fn generate_lwe_keyswitch_key_native_mod_compatible<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.decomposition_base_log().0
            * lwe_keyswitch_key.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(OutputScalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(
                level,
                decomp_base_log,
                CastInto::<OutputScalar>::cast_into(*input_key_element),
            )
            .to_recomposition_summand()
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

pub fn generate_lwe_keyswitch_key_other_mod<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.decomposition_base_log().0
            * lwe_keyswitch_key.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(OutputScalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTermNonNative::new(
                level,
                decomp_base_log,
                CastInto::<OutputScalar>::cast_into(*input_key_element),
                ciphertext_modulus,
            )
            .to_recomposition_summand();
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

/// Allocate a new [`LWE keyswitch key`](`LweKeyswitchKey`) and fill it with an actual keyswitching
/// key constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// See [`keyswitch_lwe_ciphertext`] for usage.
pub fn allocate_and_generate_new_lwe_keyswitch_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweKeyswitchKeyOwned<OutputScalar>
where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        OutputScalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_lwe_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_distribution,
        generator,
    );

    new_lwe_keyswitch_key
}

/// Fill an [`LWE keyswitch key`](`SeededLweKeyswitchKey`) with an actual keyswitching key
/// constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
///     output_lwe_dimension,
///     &mut secret_generator,
/// );
///
/// let mut ksk = SeededLweKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     output_lwe_dimension,
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// generate_seeded_lwe_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     &mut ksk,
///     lwe_noise_distribution,
///     seeder,
/// );
///
/// assert!(!ksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_seeded_lwe_keyswitch_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    NoiseSeeder,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut SeededLweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        lwe_keyswitch_key.compression_seed(),
        noise_seeder,
    );

    generate_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
        input_lwe_sk,
        output_lwe_sk,
        lwe_keyswitch_key,
        noise_distribution,
        &mut generator,
    )
}

pub fn generate_seeded_lwe_keyswitch_key_with_pre_seeded_generator<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    ByteGen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut SeededLweKeyswitchKey<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<ByteGen>,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    ByteGen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination SeededLweKeyswitchKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination SeededLweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key.decomposition_base_log().0
            * lwe_keyswitch_key.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(OutputScalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elmements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(
                level,
                decomp_base_log,
                CastInto::<OutputScalar>::cast_into(*input_key_element),
            )
            .to_recomposition_summand()
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

/// Allocate a new [`seeded LWE keyswitch key`](`SeededLweKeyswitchKey`) and fill it with an actual
/// keyswitching key constructed from an input and an output key
/// [`LWE secret key`](`LweSecretKey`).
pub fn allocate_and_generate_new_seeded_lwe_keyswitch_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweKeyswitchKeyOwned<OutputScalar>
where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut new_lwe_keyswitch_key = SeededLweKeyswitchKeyOwned::new(
        OutputScalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk.lwe_dimension(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_keyswitch_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_distribution,
        noise_seeder,
    );

    new_lwe_keyswitch_key
}

pub fn allocate_and_generate_new_seeded_lwe_key_switching_key_with_pre_seeded_generator<
    InputLweCont,
    OutputLweCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputLweCont>,
    output_lwe_secret_key: &LweSecretKey<OutputLweCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: DynamicDistribution<OutputLweCont::Element>,
    ciphertext_modulus: CiphertextModulus<OutputLweCont::Element>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> SeededLweKeyswitchKeyOwned<OutputLweCont::Element>
where
    InputLweCont: Container,
    OutputLweCont: Container,
    InputLweCont::Element: UnsignedInteger + CastInto<OutputLweCont::Element>,
    OutputLweCont::Element: Encryptable<Uniform, DynamicDistribution<OutputLweCont::Element>>,
    Gen: ByteRandomGenerator,
{
    let mut key_switching_key = SeededLweKeyswitchKeyOwned::new(
        OutputLweCont::Element::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        output_lwe_secret_key.lwe_dimension(),
        generator.mask_generator().current_compression_seed(),
        ciphertext_modulus,
    );

    generate_seeded_lwe_keyswitch_key_with_pre_seeded_generator(
        input_lwe_secret_key,
        output_lwe_secret_key,
        &mut key_switching_key,
        noise_distribution,
        generator,
    );

    key_switching_key
}

/// A generator for producing chunks of an LWE keyswitch key.
///
/// This struct allows for the generation of LWE keyswitch key chunks, which can be used to
/// construct a full LWE keyswitch key. The generator ensures that the final key would be equivalent
/// to the non-chunked generation.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let chunk_size = ChunkSize(73);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(
///         output_lwe_dimension,
///         &mut secret_generator,
///     );
///
/// let chunk_generator = LweKeyswitchKeyChunkGenerator::new(
///     &mut encryption_generator,
///     chunk_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     lwe_noise_distribution,
/// );
///
/// let chunks = chunk_generator.collect::<Vec<_>>();
/// let assembled_ksk = allocate_and_assemble_lwe_keyswitch_key_from_chunks(chunks.as_slice());
///
/// assert!(!assembled_ksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub struct LweKeyswitchKeyChunkGenerator<
    'a,
    Gen,
    InputScalar,
    OutputScalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseDistribution,
> where
    Gen: ByteRandomGenerator,
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    NoiseDistribution: Distribution,
{
    enc_generator: &'a mut EncryptionRandomGenerator<Gen>,
    chunk_size: ChunkSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    input_lwe_sk: &'a LweSecretKey<InputKeyCont>,
    output_lwe_sk: &'a LweSecretKey<OutputKeyCont>,
    noise_distribution: NoiseDistribution,
    position: usize,
}

impl<'a, Gen, InputScalar, OutputScalar, InputKeyCont, OutputKeyCont, NoiseDistribution>
    LweKeyswitchKeyChunkGenerator<
        'a,
        Gen,
        InputScalar,
        OutputScalar,
        InputKeyCont,
        OutputKeyCont,
        NoiseDistribution,
    >
where
    Gen: ByteRandomGenerator,
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    NoiseDistribution: Distribution,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::use_self)]
    pub fn new(
        enc_generator: &'a mut EncryptionRandomGenerator<Gen>,
        chunk_size: ChunkSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<OutputScalar>,
        input_lwe_sk: &'a LweSecretKey<InputKeyCont>,
        output_lwe_sk: &'a LweSecretKey<OutputKeyCont>,
        noise_distribution: NoiseDistribution,
    ) -> LweKeyswitchKeyChunkGenerator<
        'a,
        Gen,
        InputScalar,
        OutputScalar,
        InputKeyCont,
        OutputKeyCont,
        NoiseDistribution,
    > {
        assert!(
            chunk_size.0 <= input_lwe_sk.lwe_dimension().0,
            "The chunk size must be smaller or equal to the input LWE secret key dimension.\
            Chunk size: {:?}, input LWE secret key dimension: {:?}",
            chunk_size,
            input_lwe_sk.lwe_dimension()
        );
        Self {
            enc_generator,
            chunk_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
            input_lwe_sk,
            output_lwe_sk,
            noise_distribution,
            position: 0,
        }
    }
}

impl<Gen, NoiseDistribution, InputScalar, OutputScalar, InputKeyCont, OutputKeyCont> Iterator
    for LweKeyswitchKeyChunkGenerator<
        '_,
        Gen,
        InputScalar,
        OutputScalar,
        InputKeyCont,
        OutputKeyCont,
        NoiseDistribution,
    >
where
    Gen: ByteRandomGenerator,
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    NoiseDistribution: Distribution,
{
    type Item = LweKeyswitchKeyChunkOwned<OutputScalar>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_size.0 == 0 || self.position >= self.input_lwe_sk.lwe_dimension().0 {
            return None;
        }

        let left = self.input_lwe_sk.lwe_dimension().0 - self.position;
        let chunk_size = if left < self.chunk_size.0 {
            ChunkSize(left)
        } else {
            self.chunk_size
        };

        let mut chunk = LweKeyswitchKeyChunkOwned::new(
            OutputScalar::ZERO,
            self.decomposition_base_log,
            self.decomposition_level_count,
            chunk_size,
            self.output_lwe_sk.lwe_dimension(),
            self.ciphertext_modulus,
        );

        generate_chunked_lwe_keyswitch_key(
            self.input_lwe_sk,
            self.output_lwe_sk,
            &mut chunk,
            self.noise_distribution,
            self.enc_generator,
            self.position,
        );

        self.position += chunk_size.0;

        Some(chunk)
    }
}

/// Fill an [`LWE keyswitch key chunk`](`LweKeyswitchKeyChunk`) with a part of a keyswitching key.
/// It is constructed from a target chunk of an input key [`LWE secret key`](`LweSecretKey`)
/// and an output key [`LWE secret key`](`LweSecretKey`).
///
/// The chunk is defined by `chunk_start`, and the chunk size of the output.
///
/// Chunks can be assembled into a full [`LweKeyswitchKey`] using
/// [`assemble_lwe_keyswitch_key_from_chunks`].
///
/// Consider using the [`ChunkGenerator`](`LweKeyswitchKeyChunkGenerator`) to make sure you have
/// an equivalent key to the non-chunked version.
///
/// WARNING: this assumes the caller manages the random generator and the order of generation to
/// make sure the key is equivalent to the non-chunked version.
pub fn generate_chunked_lwe_keyswitch_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key_chunk: &mut LweKeyswitchKeyChunk<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = lwe_keyswitch_key_chunk.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        generate_chunked_lwe_keyswitch_key_native_mod_compatible(
            input_lwe_sk,
            output_lwe_sk,
            lwe_keyswitch_key_chunk,
            noise_distribution,
            generator,
            chunk_start,
        )
    } else {
        generate_chunked_lwe_keyswitch_key_other_mod(
            input_lwe_sk,
            output_lwe_sk,
            lwe_keyswitch_key_chunk,
            noise_distribution,
            generator,
            chunk_start,
        )
    }
}

pub fn generate_chunked_lwe_keyswitch_key_native_mod_compatible<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key_chunk: &mut LweKeyswitchKeyChunk<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let chunk_end = chunk_start + lwe_keyswitch_key_chunk.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_sk.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key_chunk.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKeyChunk output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key_chunk.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key_chunk.decomposition_base_log().0
            * lwe_keyswitch_key_chunk.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

    let decomp_base_log = lwe_keyswitch_key_chunk.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key_chunk.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key_chunk.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(OutputScalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk.as_ref()
        [chunk_start..chunk_end]
        .iter()
        .zip(lwe_keyswitch_key_chunk.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(
                level,
                decomp_base_log,
                CastInto::<OutputScalar>::cast_into(*input_key_element),
            )
            .to_recomposition_summand()
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

pub fn generate_chunked_lwe_keyswitch_key_other_mod<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key_chunk: &mut LweKeyswitchKeyChunk<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
    chunk_start: usize,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
    Gen: ByteRandomGenerator,
{
    let chunk_end = chunk_start + lwe_keyswitch_key_chunk.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_sk.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key_chunk.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination LweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key_chunk.output_key_lwe_dimension(),
        output_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key_chunk.decomposition_base_log().0
            * lwe_keyswitch_key_chunk.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

    let decomp_base_log = lwe_keyswitch_key_chunk.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key_chunk.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key_chunk.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(OutputScalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk.as_ref()
        [chunk_start..chunk_end]
        .iter()
        .zip(lwe_keyswitch_key_chunk.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTermNonNative::new(
                level,
                decomp_base_log,
                CastInto::<OutputScalar>::cast_into(*input_key_element),
                ciphertext_modulus,
            )
            .to_recomposition_summand();
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

pub fn assemble_lwe_keyswitch_key_from_chunks<Scalar, Cont, ContMut>(
    output: &mut LweKeyswitchKey<ContMut>,
    chunks: &[LweKeyswitchKeyChunk<Cont>],
) where
    Scalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
    ContMut: ContainerMut<Element = Scalar>,
{
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let chunks_lwe_dimension = LweDimension(total_chunk_size);
    assert!(chunks_lwe_dimension == output.input_key_lwe_dimension());

    let mut start: usize = 0;
    for chunk in chunks {
        assert!(output.decomposition_base_log() == chunk.decomposition_base_log());
        assert!(output.decomposition_level_count() == chunk.decomposition_level_count());
        assert!(output.output_lwe_size() == chunk.output_lwe_size());
        assert!(output.ciphertext_modulus() == chunk.ciphertext_modulus());

        let end = start + chunk.as_ref().len();
        output.as_mut()[start..end].copy_from_slice(chunk.as_ref());
        start = end;
    }
}

pub fn allocate_and_assemble_lwe_keyswitch_key_from_chunks<Scalar, Cont>(
    chunks: &[LweKeyswitchKeyChunk<Cont>],
) -> LweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element = Scalar>,
{
    assert!(!chunks.is_empty());
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let mut lwe_keyswitch_key = LweKeyswitchKey::new(
        Scalar::ZERO,
        chunks[0].decomposition_base_log(),
        chunks[0].decomposition_level_count(),
        LweDimension(total_chunk_size),
        chunks[0].output_key_lwe_dimension(),
        chunks[0].ciphertext_modulus(),
    );

    assemble_lwe_keyswitch_key_from_chunks(&mut lwe_keyswitch_key, chunks);

    lwe_keyswitch_key
}

/// A generator for producing chunks of a seeded LWE keyswitch key.
///
/// This struct allows for the generation of seeded LWE keyswitch key chunks, which can be used to
/// construct a full seeded LWE keyswitch key. The generator ensures that the final key would be
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
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let chunk_size = ChunkSize(73);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let compression_seed = CompressionSeed::from(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_lwe_secret_key: LweSecretKeyOwned<u64> =
///     allocate_and_generate_new_binary_lwe_secret_key(
///         output_lwe_dimension,
///         &mut secret_generator,
///     );
///
/// let chunk_generator = SeededLweKeyswitchKeyChunkGenerator::new(
///     chunk_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     lwe_noise_distribution,
///     compression_seed,
///     seeder,
/// );
///
/// let chunks = chunk_generator.collect::<Vec<_>>();
/// let assembled_ksk =
///     allocate_and_assemble_seeded_lwe_keyswitch_key_from_chunks(chunks.as_slice());
///
/// assert!(!assembled_ksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub struct SeededLweKeyswitchKeyChunkGenerator<
    'a,
    InputScalar,
    OutputScalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseDistribution,
> where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    NoiseDistribution: Distribution,
{
    enc_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    chunk_size: ChunkSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<OutputScalar>,
    input_lwe_sk: &'a LweSecretKey<InputKeyCont>,
    output_lwe_sk: &'a LweSecretKey<OutputKeyCont>,
    noise_distribution: NoiseDistribution,
    compression_seed: CompressionSeed,
    position: usize,
}

impl<'a, InputScalar, OutputScalar, InputKeyCont, OutputKeyCont, NoiseDistribution>
    SeededLweKeyswitchKeyChunkGenerator<
        'a,
        InputScalar,
        OutputScalar,
        InputKeyCont,
        OutputKeyCont,
        NoiseDistribution,
    >
where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    NoiseDistribution: Distribution,
{
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::use_self)]
    pub fn new<NoiseSeeder>(
        chunk_size: ChunkSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<OutputScalar>,
        input_lwe_sk: &'a LweSecretKey<InputKeyCont>,
        output_lwe_sk: &'a LweSecretKey<OutputKeyCont>,
        noise_distribution: NoiseDistribution,
        compression_seed: CompressionSeed,
        noise_seeder: &'a mut NoiseSeeder,
    ) -> SeededLweKeyswitchKeyChunkGenerator<
        'a,
        InputScalar,
        OutputScalar,
        InputKeyCont,
        OutputKeyCont,
        NoiseDistribution,
    >
    where
        NoiseSeeder: Seeder + ?Sized,
    {
        let enc_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
            compression_seed.clone(),
            noise_seeder,
        );
        assert!(
            chunk_size.0 <= input_lwe_sk.lwe_dimension().0,
            "The chunk size must be smaller or equal to the input LWE secret key dimension.\
            Chunk size: {:?}, input LWE secret key dimension: {:?}",
            chunk_size,
            input_lwe_sk.lwe_dimension()
        );
        Self {
            enc_generator,
            chunk_size,
            decomposition_base_log,
            decomposition_level_count,
            ciphertext_modulus,
            input_lwe_sk,
            output_lwe_sk,
            noise_distribution,
            compression_seed,
            position: 0,
        }
    }
}

impl<NoiseDistribution, InputScalar, OutputScalar, InputKeyCont, OutputKeyCont> Iterator
    for SeededLweKeyswitchKeyChunkGenerator<
        '_,
        InputScalar,
        OutputScalar,
        InputKeyCont,
        OutputKeyCont,
        NoiseDistribution,
    >
where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    NoiseDistribution: Distribution,
{
    type Item = SeededLweKeyswitchKeyChunkOwned<OutputScalar>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chunk_size.0 == 0 || self.position >= self.input_lwe_sk.lwe_dimension().0 {
            return None;
        }

        let left = self.input_lwe_sk.lwe_dimension().0 - self.position;
        let chunk_size = if left < self.chunk_size.0 {
            ChunkSize(left)
        } else {
            self.chunk_size
        };

        let mut chunk = SeededLweKeyswitchKeyChunkOwned::new(
            OutputScalar::ZERO,
            self.decomposition_base_log,
            self.decomposition_level_count,
            chunk_size,
            self.output_lwe_sk.lwe_dimension(),
            self.compression_seed.clone(),
            self.ciphertext_modulus,
        );

        generate_chunked_seeded_lwe_keyswitch_key(
            self.input_lwe_sk,
            self.output_lwe_sk,
            &mut chunk,
            self.noise_distribution,
            &mut self.enc_generator,
            self.position,
        );

        self.position += chunk_size.0;

        Some(chunk)
    }
}

/// Fill a [`seeded LWE keyswitch key chunk`](`SeededLweKeyswitchKeyChunk`) with a part of a seeded
/// keyswitching key. It is constructed from a target chunk of an input key
/// [`LWE secret key`](`LweSecretKey`) and an output key [`LWE secret key`](`LweSecretKey`).
///
/// The chunk is defined by `chunk_start`, and the chunk size of the output.
///
/// Chunks can be assembled into a full [`SeededLweKeyswitchKey`] using
/// [`assemble_seeded_lwe_keyswitch_key_from_chunks`].
///
/// Consider using the [`ChunkGenerator`](`SeededLweKeyswitchKeyChunkGenerator`) to make sure you
/// have an equivalent key to the non-chunked version.
///
/// WARNING: this assumes the caller manages the random generator and the order of generation to
/// make sure the key is equivalent to the non-chunked version.
pub fn generate_chunked_seeded_lwe_keyswitch_key<
    InputScalar,
    OutputScalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key_chunk: &mut SeededLweKeyswitchKeyChunk<KSKeyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    chunk_start: usize,
) where
    InputScalar: UnsignedInteger + CastInto<OutputScalar>,
    OutputScalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = InputScalar>,
    OutputKeyCont: Container<Element = OutputScalar>,
    KSKeyCont: ContainerMut<Element = OutputScalar>,
{
    let chunk_end = chunk_start + lwe_keyswitch_key_chunk.chunk_size().0;
    assert!(
        chunk_end <= input_lwe_sk.lwe_dimension().0,
        "Expected chunk out of bound of the input LWE secret key \
        Chunk ending at: {:?}, Input LWE secret key LweDimension {:?}.",
        chunk_end,
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key_chunk.output_key_lwe_dimension() == output_lwe_sk.lwe_dimension(),
        "The destination SeededLweKeyswitchKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
        lwe_keyswitch_key_chunk.output_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );
    assert!(
        lwe_keyswitch_key_chunk.decomposition_base_log().0
            * lwe_keyswitch_key_chunk.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

    let decomp_base_log = lwe_keyswitch_key_chunk.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key_chunk.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key_chunk.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(OutputScalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk.as_ref()
        [chunk_start..chunk_end]
        .iter()
        .zip(lwe_keyswitch_key_chunk.iter_mut())
    {
        // We fill the buffer with the powers of the key elmements
        for (level, message) in (1..=decomp_level_count.0)
            .map(DecompositionLevel)
            .rev()
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(
                level,
                decomp_base_log,
                CastInto::<OutputScalar>::cast_into(*input_key_element),
            )
            .to_recomposition_summand()
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_distribution,
            generator,
        );
    }
}

pub fn assemble_seeded_lwe_keyswitch_key_from_chunks<Scalar, Cont, ContMut>(
    output: &mut SeededLweKeyswitchKey<ContMut>,
    chunks: &[SeededLweKeyswitchKeyChunk<Cont>],
) where
    Scalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
    ContMut: ContainerMut<Element = Scalar>,
{
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let chunks_lwe_dimension = LweDimension(total_chunk_size);
    assert!(chunks_lwe_dimension == output.input_key_lwe_dimension());

    let mut start: usize = 0;
    for chunk in chunks {
        assert!(output.decomposition_base_log() == chunk.decomposition_base_log());
        assert!(output.decomposition_level_count() == chunk.decomposition_level_count());
        assert!(output.output_lwe_size() == chunk.output_lwe_size());
        assert!(output.ciphertext_modulus() == chunk.ciphertext_modulus());
        assert!(output.compression_seed() == chunk.compression_seed());

        let end = start + chunk.as_ref().len();
        output.as_mut()[start..end].copy_from_slice(chunk.as_ref());
        start = end;
    }
}

pub fn allocate_and_assemble_seeded_lwe_keyswitch_key_from_chunks<Scalar, Cont>(
    chunks: &[SeededLweKeyswitchKeyChunk<Cont>],
) -> SeededLweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedInteger,
    Cont: ContainerMut<Element = Scalar>,
{
    assert!(!chunks.is_empty());
    let total_chunk_size: usize = chunks.iter().map(|c| c.chunk_size().0).sum();
    let mut lwe_keyswitch_key = SeededLweKeyswitchKey::new(
        Scalar::ZERO,
        chunks[0].decomposition_base_log(),
        chunks[0].decomposition_level_count(),
        LweDimension(total_chunk_size),
        chunks[0].output_key_lwe_dimension(),
        chunks[0].compression_seed(),
        chunks[0].ciphertext_modulus(),
    );

    assemble_seeded_lwe_keyswitch_key_from_chunks(&mut lwe_keyswitch_key, chunks);

    lwe_keyswitch_key
}
