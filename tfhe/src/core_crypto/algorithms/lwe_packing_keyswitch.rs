use crate::core_crypto::algorithms::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use crate::core_crypto::algorithms::slice_algorithms::{
    slice_wrapping_add_assign, slice_wrapping_sub_scalar_mul_assign,
};
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::{
    GlweCiphertext, LweCiphertext, LweCiphertextList, LwePackingKeyswitchKey,
};

/// Apply a keyswitch on an input [`LWE ciphertext`](`LweCiphertext`) and
/// write the result in an output [`GLWE ciphertext`](`GlweCiphertext`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
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
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
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
/// let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
///     &input_lwe_secret_key,
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
/// let mut output_glwe = GlweCiphertext::new(
///     0u64,
///     output_glwe_secret_key.glwe_dimension().to_glwe_size(),
///     output_glwe_secret_key.polynomial_size(),
///     ciphertext_modulus,
/// );
///
/// keyswitch_lwe_ciphertext_into_glwe_ciphertext(&pksk, &input_lwe, &mut output_glwe);
///
/// let mut decrypted_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(output_glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(
///     &output_glwe_secret_key,
///     &output_glwe,
///     &mut decrypted_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let rounded = decomposer.closest_representable(*decrypted_plaintext_list.get(0).0);
///
/// // Remove the encoding
/// let cleartext = rounded >> 60;
///
/// // Check we recovered the original message
/// assert_eq!(cleartext, msg);
/// ```
pub fn keyswitch_lwe_ciphertext_into_glwe_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    lwe_pksk: &LwePackingKeyswitchKey<KeyCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        lwe_pksk.input_key_lwe_dimension().0,
        input_lwe_ciphertext.lwe_size().to_lwe_dimension().0
    );
    assert_eq!(
        lwe_pksk.output_key_glwe_dimension().0,
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );

    assert_eq!(
        lwe_pksk.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus()
    );

    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );

    assert!(
        input_lwe_ciphertext
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);
    output_glwe_ciphertext.get_mut_body().as_mut()[0] = *input_lwe_ciphertext.get_body().data;

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_pksk.decomposition_base_log(),
        lwe_pksk.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_lwe_element) in
        lwe_pksk.iter().zip(input_lwe_ciphertext.as_ref().iter())
    {
        // We decompose
        let rounded = decomposer.closest_representable(input_lwe_element);
        let decomp = decomposer.decompose(rounded);

        // Loop over the number of levels:
        // We compute the multiplication of a ciphertext from the private functional
        // keyswitching key with a piece of the decomposition and subtract it to the buffer
        for (level_key_cipher, decomposed) in keyswitch_key_block.iter().zip(decomp) {
            slice_wrapping_sub_scalar_mul_assign(
                output_glwe_ciphertext.as_mut(),
                level_key_cipher.as_ref(),
                decomposed.value(),
            );
        }
    }
}

/// Apply a private functional keyswitch on each [`LWE ciphertext`](`LweCiphertext`) of an input
/// [`LWE ciphertext list`](`LweCiphertextList`) and pack the result in an output [`GLWE
/// ciphertext`](`GlweCiphertext`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweKeyswitchKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
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
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
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
/// let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     decomp_base_log,
///     decomp_level_count,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// // Create a new LweCiphertext
/// let mut input_lwe_list = LweCiphertextList::new(
///     0u64,
///     input_lwe_secret_key.lwe_dimension().to_lwe_size(),
///     LweCiphertextCount(output_glwe_secret_key.polynomial_size().0),
///     ciphertext_modulus,
/// );
///
/// let mut input_plaintext_list = PlaintextList::new(
///     0u64,
///     PlaintextCount(output_glwe_secret_key.polynomial_size().0),
/// );
///
/// input_plaintext_list
///     .iter_mut()
///     .enumerate()
///     .for_each(|(idx, dst)| *dst.0 = (idx as u64 % 16) << 60);
///
/// encrypt_lwe_ciphertext_list(
///     &input_lwe_secret_key,
///     &mut input_lwe_list,
///     &input_plaintext_list,
///     lwe_modular_std_dev,
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
/// keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
///     &pksk,
///     &input_lwe_list,
///     &mut output_glwe,
/// );
///
/// let mut decrypted_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(output_glwe.polynomial_size().0));
///
/// decrypt_glwe_ciphertext(
///     &output_glwe_secret_key,
///     &output_glwe,
///     &mut decrypted_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// decrypted_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
/// input_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = *x.0 >> 60);
///
/// // Check we recovered the original message
/// assert_eq!(input_plaintext_list, decrypted_plaintext_list);
/// ```
pub fn keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pksk: &LwePackingKeyswitchKey<KeyCont>,
    input: &LweCiphertextList<InputCont>,
    output: &mut GlweCiphertext<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(lwe_pksk.ciphertext_modulus(), output.ciphertext_modulus());
    assert_eq!(output.ciphertext_modulus(), input.ciphertext_modulus());
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    assert!(input.lwe_ciphertext_count().0 <= output.polynomial_size().0);
    output.as_mut().fill(Scalar::ZERO);
    let mut buffer = GlweCiphertext::new(
        Scalar::ZERO,
        output.glwe_size(),
        output.polynomial_size(),
        output.ciphertext_modulus(),
    );
    // for each ciphertext, call mono_key_switch
    for (degree, input_ciphertext) in input.iter().enumerate() {
        keyswitch_lwe_ciphertext_into_glwe_ciphertext(lwe_pksk, &input_ciphertext, &mut buffer);
        buffer
            .as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(degree))
            });
        slice_wrapping_add_assign(output.as_mut(), buffer.as_ref());
    }
}
