//! Module containing primitives pertaining to [`LWE ciphertext shrinking
//! keyswitch`](`crate::core_crypto::entities::LweKeyswitchKey#lwe-keyswitch`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::LweCiphertext;
use crate::core_crypto::experimental::entities::LweShrinkingKeyswitchKey;

/// Keyswitch an LWE ciphertext under an LWE secret key S1 to an LWE ciphertext under an LWE secret
/// key S2 where S1 is bigger than S2 and S2 takes all its coefficients from the start of S1.
///
/// ```rust
/// use tfhe::core_crypto::experimental::prelude::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweShrinkingKeyswitchKey creation
/// let large_lwe_dimension = LweDimension(10);
/// let lwe_noise_distribution =
///     Gaussian::from_standard_dev(StandardDev(8.881784197001252e-16), 0.0);
/// let small_lwe_dimension = LweDimension(5);
/// let lwe_secret_key_shared_coef_count = LweSecretKeySharedCoefCount(small_lwe_dimension.0);
/// let decomp_base_log = DecompositionBaseLog(30);
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
/// // Create the large LweSecretKey
/// let large_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(large_lwe_dimension, &mut secret_generator);
///
/// // Generate a small LweSecretKey that shares part of its coefficients with the large secret key
/// let small_lwe_secret_key = allocate_and_generate_fully_shared_binary_lwe_secret_key(
///     &large_lwe_secret_key,
///     small_lwe_dimension,
/// );
///
/// let ksk = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
///     &large_lwe_secret_key,
///     lwe_secret_key_shared_coef_count,
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
///     &large_lwe_secret_key,
///     plaintext,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut output_lwe = LweCiphertext::new(
///     0,
///     small_lwe_secret_key.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// shrinking_keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&small_lwe_secret_key, &output_lwe);
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
pub fn shrinking_keyswitch_lwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_shrinking_keyswitch_key: &LweShrinkingKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        lwe_shrinking_keyswitch_key.input_key_lwe_dimension()
            == input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched input LweDimension. \
        LweShrinkingKeyswitchKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        lwe_shrinking_keyswitch_key.input_key_lwe_dimension(),
        input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );
    assert!(
        lwe_shrinking_keyswitch_key.output_key_lwe_dimension()
            == output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        "Mismatched output LweDimension. \
        LweShrinkingKeyswitchKey output LweDimension: {:?}, output LweCiphertext LweDimension {:?}.",
        lwe_shrinking_keyswitch_key.output_key_lwe_dimension(),
        output_lwe_ciphertext.lwe_size().to_lwe_dimension(),
    );

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_shrinking_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweShrinkingKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_shrinking_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_shrinking_keyswitch_key.ciphertext_modulus(),
        input_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweShrinkingKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_shrinking_keyswitch_key.ciphertext_modulus(),
        input_ciphertext_modulus
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    let shared_randomness = lwe_shrinking_keyswitch_key.shared_randomness();

    let input_lwe_ciphertext_mask = input_lwe_ciphertext.get_mask();
    let (input_shared_mask_slice, input_unshared_mask_slice) = input_lwe_ciphertext_mask
        .as_ref()
        .split_at(shared_randomness.0);

    // Copy the shared elements of the mask
    output_lwe_ciphertext
        .get_mut_mask()
        .as_mut()
        .copy_from_slice(input_shared_mask_slice);

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_shrinking_keyswitch_key.decomposition_base_log(),
        lwe_shrinking_keyswitch_key.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_mask_element) in lwe_shrinking_keyswitch_key
        .as_lwe_keyswitch_key()
        .iter()
        .zip(input_unshared_mask_slice.iter())
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
