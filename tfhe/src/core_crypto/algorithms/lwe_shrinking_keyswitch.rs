//! Module containing primitives pertaining to [`LWE ciphertext
//! keyswitch`](`LweKeyswitchKey#lwe-keyswitch`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// From ct_1 to ct_0 with n_1 > n_0 and shared randomness
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweShrinkingKeyswitchKey creation
/// let large_lwe_dimension = LweDimension(10);
/// let lwe_modular_std_dev = StandardDev(0.0000000000000000000000000000000007069849454709433);
/// let small_lwe_dimension = LweDimension(5);
/// let decomp_base_log = DecompositionBaseLog(30);
/// let decomp_level_count = DecompositionLevelCount(1);
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
/// let shared_randomness_dimension = LweDimension(large_lwe_dimension.0 - small_lwe_dimension.0);
/// // Create the LweSecretKey
/// let large_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(large_lwe_dimension, &mut secret_generator);
/// let mut small_lwe_secret_key = LweSecretKey::new_empty_key(0_u64, small_lwe_dimension);
/// small_lwe_secret_key
///     .as_mut()
///     .iter_mut()
///     .zip(large_lwe_secret_key.as_ref().iter())
///     .for_each(|(dst, &src)| *dst = src);
///
/// let ksk = allocate_and_generate_new_lwe_shrinking_keyswitch_key(
///     &large_lwe_secret_key,
///     &small_lwe_secret_key,
///     shared_randomness_dimension,
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
///     &large_lwe_secret_key,
///     plaintext,
///     lwe_modular_std_dev,
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
    assert_eq!(
        input_lwe_ciphertext.lwe_size().to_lwe_dimension(),
        LweDimension(
            output_lwe_ciphertext.lwe_size().to_lwe_dimension().0
                + lwe_shrinking_keyswitch_key
                    .unshared_randomness_lwe_dimension()
                    .0
        )
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    let shared_randomness_lwe_dimension =
        lwe_shrinking_keyswitch_key.shared_randomness_lwe_dimension();

    let input_lwe_ciphertext_mask = input_lwe_ciphertext.get_mask();
    let (input_shared_mask_slice, input_unshared_mask_slice) = input_lwe_ciphertext_mask
        .as_ref()
        .split_at(shared_randomness_lwe_dimension.0);

    // Copy the shared elements of the mask
    output_lwe_ciphertext.get_mut_mask().as_mut()[0..shared_randomness_lwe_dimension.0]
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
