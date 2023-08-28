//! Module containing primitives pertaining to [`LWE keyswitch keys
//! generation`](`LweKeyswitchKey#key-switching-key`) and [`seeded LWE keyswitch keys
//! generation`](`SeededLweKeyswitchKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Fill an [`LWE keyswitch key`](`LweKeyswitchKey`) with an actual keyswitching key constructed
/// from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let ciphertext_modulus = CiphertextModulus::new_native();
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
/// let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
///     output_lwe_dimension,
///     &mut secret_generator,
/// );
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
///     lwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// assert!(ksk.as_ref().iter().all(|&x| x == 0) == false);
/// ```
pub fn generate_lwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, KSKeyCont, Gen>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut LweKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
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

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elements
        for (level, message) in (1..=decomp_level_count.0)
            .rev()
            .map(DecompositionLevel)
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                .to_recomposition_summand()
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_lwe_ciphertext_list(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            generator,
        );
    }
}

/// Allocate a new [`LWE keyswitch key`](`LweKeyswitchKey`) and fill it with an actual keyswitching
/// key constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// See [`keyswitch_lwe_ciphertext`] for usage.
pub fn allocate_and_generate_new_lwe_keyswitch_key<Scalar, InputKeyCont, OutputKeyCont, Gen>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = LweKeyswitchKeyOwned::new(
        Scalar::ZERO,
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
        noise_parameters,
        generator,
    );

    new_lwe_keyswitch_key
}

/// Fill an [`LWE keyswitch key`](`SeededLweKeyswitchKey`) with an actual keyswitching key
/// constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
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
///     lwe_modular_std_dev,
///     seeder,
/// );
///
/// assert!(ksk.as_ref().iter().all(|&x| x == 0) == false);
/// ```
pub fn generate_seeded_lwe_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    NoiseSeeder,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    lwe_keyswitch_key: &mut SeededLweKeyswitchKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
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

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        lwe_keyswitch_key.compression_seed().seed,
        noise_seeder,
    );

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (input_key_element, mut keyswitch_key_block) in input_lwe_sk
        .as_ref()
        .iter()
        .zip(lwe_keyswitch_key.iter_mut())
    {
        // We fill the buffer with the powers of the key elmements
        for (level, message) in (1..=decomp_level_count.0)
            .rev()
            .map(DecompositionLevel)
            .zip(decomposition_plaintexts_buffer.iter_mut())
        {
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                .to_recomposition_summand()
                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
        }

        encrypt_seeded_lwe_ciphertext_list_with_existing_generator(
            output_lwe_sk,
            &mut keyswitch_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            &mut generator,
        );
    }
}

/// Allocate a new [`seeded LWE keyswitch key`](`SeededLweKeyswitchKey`) and fill it with an actual
/// keyswitching key constructed from an input and an output key
/// [`LWE secret key`](`LweSecretKey`).
pub fn allocate_and_generate_new_seeded_lwe_keyswitch_key<
    Scalar,
    InputKeyCont,
    OutputKeyCont,
    NoiseSeeder,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &LweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweKeyswitchKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut new_lwe_keyswitch_key = SeededLweKeyswitchKeyOwned::new(
        Scalar::ZERO,
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
        noise_parameters,
        noise_seeder,
    );

    new_lwe_keyswitch_key
}
