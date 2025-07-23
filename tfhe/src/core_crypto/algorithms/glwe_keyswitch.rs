//! Module containing primitives pertaining to [`GLWE ciphertext
//! keyswitch`](`GlweKeyswitchKey#glwe-keyswitch`).

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposer, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Keyswitch a [`GLWE ciphertext`](`GlweCiphertext`) encrypted under a
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
/// // Define parameters for GlweKeyswitchKey creation
/// let input_glwe_dimension = GlweDimension(4);
/// let poly_size = PolynomialSize(512);
/// let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
///     StandardDev(0.00000000000000000000007069849454709433),
///     0.0,
/// );
/// let output_glwe_dimension = GlweDimension(3);
/// let decomp_base_log = DecompositionBaseLog(21);
/// let decomp_level_count = DecompositionLevelCount(2);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let delta = 1 << 59;
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext_list = PlaintextList::new(msg * delta, PlaintextCount(poly_size.0));
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
///     glwe_noise_distribution,
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
/// keyswitch_glwe_ciphertext(&ksk, &input_glwe, &mut output_glwe);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 5 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext(
///     &output_glwe_secret_key,
///     &output_glwe,
///     &mut output_plaintext_list,
/// );
///
/// // Get the raw vector
/// let cleartext_list: Vec<_> = output_plaintext_list
///     .as_ref()
///     .iter()
///     .map(|elt| decomposer.decode_plaintext(Plaintext(*elt)).0)
///     .collect();
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
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    if glwe_keyswitch_key
        .ciphertext_modulus()
        .is_compatible_with_native_modulus()
    {
        keyswitch_glwe_ciphertext_native_mod_compatible(
            glwe_keyswitch_key,
            input_glwe_ciphertext,
            output_glwe_ciphertext,
        )
    } else {
        keyswitch_glwe_ciphertext_other_mod(
            glwe_keyswitch_key,
            input_glwe_ciphertext,
            output_glwe_ciphertext,
        )
    }
}

pub fn keyswitch_glwe_ciphertext_native_mod_compatible<Scalar, KSKCont, InputCont, OutputCont>(
    glwe_keyswitch_key: &GlweKeyswitchKey<KSKCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
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
        GlweKeyswitchKey input PolynomialSize: {:?}, input GlweCiphertext PolynomialSize {:?}.",
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
    assert!(glwe_keyswitch_key
        .ciphertext_modulus()
        .is_compatible_with_native_modulus());

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    output_glwe_ciphertext
        .get_mut_body()
        .as_mut()
        .copy_from_slice(input_glwe_ciphertext.get_body().as_ref());

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
        // loop over the number of levels

        let mut keyswitch_key_block_iter = keyswitch_key_block.iter();

        while let (Some(level_key_ciphertext), Some(decomposed)) = (
            keyswitch_key_block_iter.next(),
            decomposition_iter.next_term(),
        ) {
            polynomial_list_wrapping_sub_mul_assign(
                &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                &level_key_ciphertext.as_polynomial_list(),
                &Polynomial::from_container(decomposed.as_slice()),
            );
        }
    }
}

pub fn keyswitch_glwe_ciphertext_other_mod<Scalar, KSKCont, InputCont, OutputCont>(
    glwe_keyswitch_key: &GlweKeyswitchKey<KSKCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
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
        GlweKeyswitchKey input PolynomialSize: {:?}, input GlweCiphertext PolynomialSize {:?}.",
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
    let ciphertext_modulus = glwe_keyswitch_key.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    // Clear the output ciphertext, as it will get updated gradually
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext (no need to use non native addition here)
    polynomial_wrapping_add_assign(
        &mut output_glwe_ciphertext.get_mut_body().as_mut_polynomial(),
        &input_glwe_ciphertext.get_body().as_polynomial(),
    );

    // We instantiate a decomposer
    let decomposer = SignedDecomposerNonNative::new(
        glwe_keyswitch_key.decomposition_base_log(),
        glwe_keyswitch_key.decomposition_level_count(),
        ciphertext_modulus,
    );

    let mut scalar_poly = Polynomial::new(Scalar::ZERO, input_glwe_ciphertext.polynomial_size());

    for (keyswitch_key_block, input_mask_element) in glwe_keyswitch_key
        .iter()
        .zip(input_glwe_ciphertext.get_mask().as_polynomial_list().iter())
    {
        let mut decomposition_iter = decomposer.decompose_slice(input_mask_element.as_ref());
        // loop over the number of levels

        let mut keyswitch_key_block_iter = keyswitch_key_block.iter();

        while let (Some(level_key_ciphertext), Some(decomposed)) = (
            keyswitch_key_block_iter.next(),
            decomposition_iter.next_term(),
        ) {
            decomposed.modular_value(scalar_poly.as_mut());
            polynomial_list_wrapping_sub_mul_assign_custom_mod(
                &mut output_glwe_ciphertext.as_mut_polynomial_list(),
                &level_key_ciphertext.as_polynomial_list(),
                &scalar_poly,
                ciphertext_modulus.get_custom_modulus().cast_into(),
            );
        }
    }
}
