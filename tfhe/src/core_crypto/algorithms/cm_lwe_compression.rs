//! Module containing primitives pertaining to [`LWE ciphertext
//! keyswitch`](`CmLweCompressionKey#lwe-keyswitch`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use itertools::Itertools;

/// Keyswitch an [`LWE ciphertext`](`LweCiphertext`) encrypted under an
/// [`LWE secret key`](`LweSecretKey`) to another [`LWE secret key`](`LweSecretKey`).
///
/// # Formal Definition
///
/// See [`LWE keyswitch key`](`CmLweCompressionKey#lwe-keyswitch`).
///
/// # Example
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
/// let output_lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
///     output_lwe_dimension,
///     &mut secret_generator,
/// );
///
/// let ksk = allocate_and_generate_new_lwe_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let input_lwe = allocate_and_encrypt_new_lwe_ciphertext(
///     &input_lwe_secret_key,
///     plaintext,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut output_lwe = LweCiphertext::new(
///     0,
///     output_lwe_secret_key.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&output_lwe_secret_key, &output_lwe);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let rounded = decomposer.closest_representable(decrypted_plaintext.0);
///
/// // Remove the encoding
/// let cleartext = rounded >> 60;
///
/// // Check we recovered the original message
/// assert_eq!(cleartext, msg);
/// ```
pub fn compress_lwe_ciphertexts_into_cm<Scalar, KSKCont, InputCont, OutputCont>(
    cm_lwe_compression_key: &CmLweCompressionKey<KSKCont>,
    input_lwe_ciphertexts: &[LweCiphertext<InputCont>],
    output_cm_lwe_ciphertext: &mut CmLweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        cm_lwe_compression_key.input_key_lwe_dimension(),
        input_lwe_ciphertexts[0].lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        CmLweCompressionKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        cm_lwe_compression_key.input_key_lwe_dimension(),
        input_lwe_ciphertexts[0].lwe_size().to_lwe_dimension(),
    );

    assert_eq!(
        cm_lwe_compression_key.output_lwe_dimension(),
        output_cm_lwe_ciphertext.lwe_dimension(),
        "Mismatched output LweDimension. \
        CmLweCompressionKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        cm_lwe_compression_key.output_lwe_dimension(),
        output_cm_lwe_ciphertext.lwe_dimension(),
    );

    assert_eq!(
        cm_lwe_compression_key.output_cm_dimension(),
        output_cm_lwe_ciphertext.cm_dimension(),
        "Mismatched output LweDimension. \
        CmLweCompressionKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        cm_lwe_compression_key.output_lwe_dimension(),
        output_cm_lwe_ciphertext.lwe_dimension(),
    );

    let output_ciphertext_modulus = output_cm_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        cm_lwe_compression_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        CmLweCompressionKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        cm_lwe_compression_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertexts[0].ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_cm_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    for (i, (key_part, input_lwe_ciphertext)) in cm_lwe_compression_key
        .iter()
        .zip_eq(input_lwe_ciphertexts.iter())
        .enumerate()
    {
        output_cm_lwe_ciphertext.get_mut_bodies().data()[i] =
            output_cm_lwe_ciphertext.get_mut_bodies().data()[i]
                .wrapping_add(*input_lwe_ciphertext.get_body().data);

        // We instantiate a decomposer
        let decomposer = SignedDecomposer::new(
            cm_lwe_compression_key.decomposition_base_log(),
            cm_lwe_compression_key.decomposition_level_count(),
        );

        for (keyswitch_key_block, &input_mask_element) in key_part
            .iter()
            .zip_eq(input_lwe_ciphertext.get_mask().as_ref())
        {
            let decomposition_iter = decomposer.decompose(input_mask_element);
            // Loop over the levels

            for (level_key_ciphertext, decomposed) in
                keyswitch_key_block.iter().zip_eq(decomposition_iter)
            {
                slice_wrapping_sub_scalar_mul_assign(
                    output_cm_lwe_ciphertext.as_mut(),
                    level_key_ciphertext.into_container(),
                    decomposed.value(),
                );
            }
        }
    }
}
