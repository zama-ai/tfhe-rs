//! Module containing primitives pertaining to [`LWE ciphertext
//! keyswitch`](`LweKeyswitchKey#lwe-keyswitch`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Keyswitch an [`LWE ciphertext`](`LweCiphertext`) encrytped under an
/// [`LWE secret key`](`LweSecretKey`) to another [`LWE secret key`](`LweSecretKey`).
///
/// # Formal Definition
///
/// See [`LWE keyswitch key`](`LweKeyswitchKey#lwe-keyswitch`).
///
/// # Example
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
/// let ksk = allocate_and_generate_new_lwe_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_lwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_modular_std_dev,
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
///     lwe_modular_std_dev,
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
pub fn keyswitch_lwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lwe_keyswitch_key.input_key_lwe_dimension()
            == input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        LweKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.output_key_lwe_dimension()
            == output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        LweKeyswitchKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        lwe_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_keyswitch_key.ciphertext_modulus() == input_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, input LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        lwe_keyswitch_key.ciphertext_modulus() == output_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus()
    );
    assert!(
        lwe_keyswitch_key
            .ciphertext_modulus()
            .is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_mask_element) in lwe_keyswitch_key
        .iter()
        .zip(input_lwe_ciphertext.get_mask().as_ref())
    {
        let decomposition_iter = decomposer.decompose(input_mask_element);
        // Loop over the levels
        for (level_key_ciphertext, decomposed) in keyswitch_key_block.iter().zip(decomposition_iter)
        {
            slice_wrapping_sub_scalar_mul_assign(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.value(),
            );
        }
    }
}
