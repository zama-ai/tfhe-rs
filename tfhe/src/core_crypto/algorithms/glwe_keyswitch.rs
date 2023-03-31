//! Module containing primitives pertaining to [`GLWE ciphertext
//! keyswitch`](`GlweKeyswitchKey#glwe-keyswitch`).

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Keyswitch an [`GLWE ciphertext`](`GlweCiphertext`) encrytped under an
/// [`GLWE secret key`](`GlweSecretKey`) to another [`GLWE secret key`](`GlweSecretKey`).
///
/// # Formal Definition
///
/// See [`GLWE keyswitch key`](`GlweKeyswitchKey#glwe-keyswitch`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_glwe_dimension = GlweDimension(2);
/// let poly_size = PolynomialSize(512);
/// let glwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_glwe_dimension = GlweDimension(1);
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
/// let input_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     input_glwe_dimension,
///     poly_size,
///     &mut secret_generator,
/// );
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     output_glwe_dimension,
///     poly_size,
///     &mut secret_generator,
/// );
///
/// let ksk = allocate_and_generate_new_glwe_keyswitch_key(
///     &input_glwe_secret_key,
///     &output_glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext_list = PlaintextList::new(msg << 60, PlaintextCount(poly_size.0));
///
/// // Create a new GlweCiphertext
/// let mut input_glwe = GlweCiphertext::new(
///     0u64,
///     input_glwe_dimension.to_glwe_size(),
///     poly_size,
///     ciphertext_modulus,
/// );
///
/// encrypt_glwe_ciphertext(
///     &input_glwe_secret_key,
///     &mut input_glwe,
///     &plaintext_list,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe = GlweCiphertext::new(
///     0u64,
///     output_glwe_secret_key.glwe_dimension().to_glwe_size(),
///     output_glwe_secret_key.polynomial_size(),
///     ciphertext_modulus,
/// );
///
/// keyswitch_glwe_ciphertext(&ksk, &mut input_glwe, &mut output_glwe);
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// let decrypted_plaintext = decrypt_glwe_ciphertext(
///     &output_glwe_secret_key,
///     &output_glwe,
///     &mut output_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|elt| *elt.0 = decomposer.closest_representable(*elt.0));
///
/// // Get the raw vector
/// let mut cleartext_list = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext_list.iter_mut().for_each(|elt| *elt = *elt >> 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn keyswitch_glwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    glwe_keyswitch_key: &GlweKeyswitchKey<KSKCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: ContainerMut<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        glwe_keyswitch_key.input_key_glwe_dimension()
            == input_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        "Mismatched input GlweDimension. \
        GlweKeyswitchKey input GlweDimension: {:?}, input GlweCiphertext GlweDimension {:?}.",
        glwe_keyswitch_key.input_key_glwe_dimension(),
        input_glwe_ciphertext.glwe_size().to_glwe_dimension(),
    );
    assert!(
        glwe_keyswitch_key.output_key_glwe_dimension()
            == output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        "Mismatched output GlweDimension. \
        GlweKeyswitchKey output GlweDimension: {:?}, output GlweCiphertext GlweDimension {:?}.",
        glwe_keyswitch_key.output_key_glwe_dimension(),
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
    );
    assert!(
        glwe_keyswitch_key.polynomial_size() == input_glwe_ciphertext.polynomial_size(),
        "Mismatched input PolynomialSize. \
        GlweKeyswithcKey input PolynomialSize: {:?}, input GlweCiphertext PolynomialSize {:?}.",
        glwe_keyswitch_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size(),
    );
    assert!(
        glwe_keyswitch_key.polynomial_size() == output_glwe_ciphertext.polynomial_size(),
        "Mismatched output PolynomialSize. \
        GlweKeyswitchKey output PolynomialSize: {:?}, output GlweCiphertext PolynomialSize {:?}.",
        glwe_keyswitch_key.polynomial_size(),
        output_glwe_ciphertext.polynomial_size(),
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        glwe_keyswitch_key.decomposition_base_log(),
        glwe_keyswitch_key.decomposition_level_count(),
    );

    for (keyswitch_key_block, input_mask_element) in glwe_keyswitch_key
        .iter()
        .zip(input_glwe_ciphertext.get_mask().as_polynomial_list().iter())
    {
        let mut decomposition_iter = decomposer.decompose_slice(input_mask_element.as_ref());
        // loop over the number of levels in reverse (from highest to lowest)
        for level_key_ciphertext in keyswitch_key_block.iter().rev() {
            let decomposed = decomposition_iter.next_term().unwrap();
            polynomial_list_wrapping_sub_scalar_mul_assign(
                &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                &level_key_ciphertext.as_polynomial_list(),
                &Polynomial::from_container(decomposed.as_slice()),
            );
        }
    }
}
