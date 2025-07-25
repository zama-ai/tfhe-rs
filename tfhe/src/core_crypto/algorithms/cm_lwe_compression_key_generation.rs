//! Module containing primitives pertaining to [`CRS LWE compression keys
//! generation`](`CmLweCompressionKey#key-switching-key`)

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use cm_lwe_compression_key_generation::cm_lwe_encryption::encrypt_cm_lwe_ciphertext_list;
use itertools::Itertools;

/// Fill an [`LWE keyswitch key`](`CmLweCompressionKey`) with an actual keyswitching key
/// constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for CmLweCompressionKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.000007069849454709433));
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
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
///
/// let cm_dimension = CmDimension(1);
///
/// let output_lwe_secret_key = vec![
///     allocate_and_generate_new_binary_lwe_secret_key(
///         output_lwe_dimension,
///         &mut secret_generator,
///     );
///     cm_dimension.0
/// ];
///
/// let mut ksk = CmLweCompressionKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     output_lwe_dimension,
///     cm_dimension,
///     ciphertext_modulus,
/// );
///
/// generate_cm_lwe_compression_key(
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     &mut ksk,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// assert!(!ksk.as_ref().iter().all(|&x| x == 0));
/// ```
pub fn generate_cm_lwe_compression_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    KSKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sks: &[LweSecretKey<OutputKeyCont>],
    lwe_keyswitch_key: &mut CmLweCompressionKey<KSKeyCont>,
    noise_parameters: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
        "The destination CmLweCompressionKey input LweDimension is not equal \
    to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_sk.lwe_dimension()
    );

    for output_lwe_sk in output_lwe_sks {
        assert!(
            lwe_keyswitch_key.output_lwe_dimension() == output_lwe_sk.lwe_dimension(),
            "The destination CmLweCompressionKey output LweDimension is not equal \
    to the output LweSecretKey LweDimension. Destination: {:?}, output: {:?}",
            lwe_keyswitch_key.output_lwe_dimension(),
            output_lwe_sk.lwe_dimension()
        );
    }

    let cm_dimension = CmDimension(output_lwe_sks.len());

    let decomp_base_log = lwe_keyswitch_key.decomposition_base_log();
    let decomp_level_count = lwe_keyswitch_key.decomposition_level_count();
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer =
        PlaintextListOwned::new(Scalar::ZERO, PlaintextCount(decomp_level_count.0));

    // Iterate over the input key elements and the destination lwe_keyswitch_key memory
    for (i, mut keyswitch_key_block) in lwe_keyswitch_key.iter_mut().enumerate() {
        for (input_key_element, mut keyswitch_key_block_block) in input_lwe_sk
            .as_ref()
            .iter()
            .zip_eq(keyswitch_key_block.iter_mut())
        {
            // assert_eq!(
            //     keyswitch_key_block_block.len(),
            //     (out_lwe_dimension.0 + cm_dimension.0) * decomp_level_count.0
            // );

            // We fill the buffer with the powers of the key elements
            for (level, message) in (1..=decomp_level_count.0)
                .rev()
                .map(DecompositionLevel)
                .zip_eq(decomposition_plaintexts_buffer.iter_mut())
            {
                // Here  we take the decomposition term from the native torus, bring it to the
                // torus
                // we are working with by dividing by the scaling factor and the
                // encryption will take care of mapping that back to the native
                // torus
                *message.0 = DecompositionTerm::new(level, decomp_base_log, *input_key_element)
                    .to_recomposition_summand()
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
            }

            let list = decomposition_plaintexts_buffer
                .iter()
                .map(|decomposition_plaintext| {
                    PlaintextList::from_container(
                        (0..cm_dimension.0)
                            .map(|j| {
                                if i == j {
                                    *decomposition_plaintext.0
                                } else {
                                    Scalar::ZERO
                                }
                            })
                            .collect_vec(),
                    )
                })
                .collect_vec();

            encrypt_cm_lwe_ciphertext_list(
                output_lwe_sks,
                &mut keyswitch_key_block_block,
                &list,
                noise_parameters,
                generator,
            );
        }
    }
}

/// Allocate a new [`LWE keyswitch key`](`CmLweCompressionKey`) and fill it with an actual
/// keyswitching key constructed from an input and an output key [`LWE secret key`](`LweSecretKey`).
///
/// See [`keyswitch_lwe_ciphertext`] for usage.
pub fn allocate_and_generate_new_cm_lwe_compression_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_sk: &LweSecretKey<InputKeyCont>,
    output_lwe_sk: &[LweSecretKey<OutputKeyCont>],
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> CmLweCompressionKeyOwned<Scalar>
where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_lwe_keyswitch_key = CmLweCompressionKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_lwe_sk.lwe_dimension(),
        output_lwe_sk[0].lwe_dimension(),
        CmDimension(output_lwe_sk.len()),
        ciphertext_modulus,
    );

    generate_cm_lwe_compression_key(
        input_lwe_sk,
        output_lwe_sk,
        &mut new_lwe_keyswitch_key,
        noise_parameters,
        generator,
    );

    new_lwe_keyswitch_key
}
