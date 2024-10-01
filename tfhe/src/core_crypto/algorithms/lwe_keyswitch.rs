//! Module containing primitives pertaining to [`LWE ciphertext
//! keyswitch`](`LweKeyswitchKey#lwe-keyswitch`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposer, SignedDecomposerNonNative,
};
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, ThreadCount,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Keyswitch an [`LWE ciphertext`](`LweCiphertext`) encrypted under an
/// [`LWE secret key`](`LweSecretKey`) to another [`LWE secret key`](`LweSecretKey`).
///
/// Automatically dispatches to [`keyswitch_lwe_ciphertext_native_mod_compatible`] or
/// [`keyswitch_lwe_ciphertext_other_mod`] depending on the ciphertext modulus of the input
/// `lwe_keyswitch_key`.
///
/// # Formal Definition
///
/// See [`LWE keyswitch key`](`LweKeyswitchKey#lwe-keyswitch`).
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
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        keyswitch_lwe_ciphertext_native_mod_compatible(
            lwe_keyswitch_key,
            input_lwe_ciphertext,
            output_lwe_ciphertext,
        )
    } else {
        keyswitch_lwe_ciphertext_other_mod(
            lwe_keyswitch_key,
            input_lwe_ciphertext,
            output_lwe_ciphertext,
        )
    }
}

/// Specialized implementation of an LWE keyswitch when inputs have power of two moduli.
///
/// # Panics
///
/// Panics if the modulus of the inputs are not power of twos.
/// Panics if the output `output_lwe_ciphertext` modulus is not equal to the `lwe_keyswitch_key`
/// modulus.
pub fn keyswitch_lwe_ciphertext_native_mod_compatible<Scalar, KSKCont, InputCont, OutputCont>(
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

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // If the moduli are not the same, we need to round the body in the output ciphertext
    if output_ciphertext_modulus != input_ciphertext_modulus
        && !output_ciphertext_modulus.is_native_modulus()
    {
        let modulus_bits = output_ciphertext_modulus.get_custom_modulus().ilog2() as usize;
        let output_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(modulus_bits),
            DecompositionLevelCount(1),
        );

        *output_lwe_ciphertext.get_mut_body().data =
            output_decomposer.closest_representable(*output_lwe_ciphertext.get_mut_body().data);
    }

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

/// Specialized implementation of an LWE keyswitch when inputs have non power of two moduli.
///
/// # Panics
///
/// Panics if the modulus of the inputs are power of twos.
/// Panics if the modulus of the inputs are not all equal.
pub fn keyswitch_lwe_ciphertext_other_mod<Scalar, KSKCont, InputCont, OutputCont>(
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

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus()
    );

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, input LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );

    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    assert!(
        !ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports non power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // We instantiate a decomposer
    let decomposer = SignedDecomposerNonNative::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
        ciphertext_modulus,
    );

    for (keyswitch_key_block, &input_mask_element) in lwe_keyswitch_key
        .iter()
        .zip(input_lwe_ciphertext.get_mask().as_ref())
    {
        let decomposition_iter = decomposer.decompose(input_mask_element);
        // Loop over the levels
        for (level_key_ciphertext, decomposed) in keyswitch_key_block.iter().zip(decomposition_iter)
        {
            slice_wrapping_sub_scalar_mul_assign_custom_modulus(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.modular_value(),
                ciphertext_modulus.get_custom_modulus().cast_into(),
            );
        }
    }
}

/// Keyswitch an [`LWE ciphertext`](`LweCiphertext`) with a certain InputScalar type to represent
/// data encrypted under an [`LWE secret key`](`LweSecretKey`) to another [`LWE secret
/// key`](`LweSecretKey`) using a different OutputScalar type to represent data.
///
/// # Notes
///
/// This function only supports power of 2 moduli and going from a large InputScalar with
/// `input_bits` to a a smaller OutputScalar with `output_bits` and `output_bits` < `input_bits`.
///
/// The product of the `lwe_keyswitch_key`'s
/// [`DecompositionBaseLog`](`crate::core_crypto::commons::parameters::DecompositionBaseLog`) and
/// [`DecompositionLevelCount`](`crate::core_crypto::commons::parameters::DecompositionLevelCount`)
/// needs to be smaller than `output_bits`.
pub fn keyswitch_lwe_ciphertext_with_scalar_change<
    InputScalar,
    OutputScalar,
    KSKCont,
    InputCont,
    OutputCont,
>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    InputScalar: UnsignedInteger,
    OutputScalar: UnsignedInteger + CastFrom<InputScalar>,
    KSKCont: Container<Element = OutputScalar>,
    InputCont: Container<Element = InputScalar>,
    OutputCont: ContainerMut<Element = OutputScalar>,
{
    assert!(
        InputScalar::BITS > OutputScalar::BITS,
        "This operation only supports going from a large InputScalar type \
        to a strictly smaller OutputScalar type."
    );
    assert!(
        lwe_keyswitch_key.decomposition_base_log().0
            * lwe_keyswitch_key.decomposition_level_count().0
            <= OutputScalar::BITS,
        "This operation only supports a DecompositionBaseLog and DecompositionLevelCount product \
        smaller than the OutputScalar bit count."
    );

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

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(OutputScalar::ZERO);

    let output_modulus_bits = match output_ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => OutputScalar::BITS,
        CiphertextModulusKind::NonNativePowerOfTwo => {
            output_ciphertext_modulus.get_custom_modulus().ilog2() as usize
        }
        CiphertextModulusKind::Other => unreachable!(),
    };

    let input_body_decomposer = SignedDecomposer::new(
        DecompositionBaseLog(output_modulus_bits),
        DecompositionLevelCount(1),
    );

    // Power of two are encoded in the MSBs of the types so we need to scale the type to the other
    // one without having to worry about the moduli
    let input_to_output_scaling_factor = InputScalar::BITS - OutputScalar::BITS;

    let rounded_downscaled_body = input_body_decomposer
        .closest_representable(*input_lwe_ciphertext.get_body().data)
        >> input_to_output_scaling_factor;

    *output_lwe_ciphertext.get_mut_body().data = rounded_downscaled_body.cast_into();

    // We instantiate a decomposer
    let input_decomposer = SignedDecomposer::<InputScalar>::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_mask_element) in lwe_keyswitch_key
        .iter()
        .zip(input_lwe_ciphertext.get_mask().as_ref())
    {
        let decomposition_iter = input_decomposer.decompose(input_mask_element);
        // Loop over the levels
        for (level_key_ciphertext, decomposed) in keyswitch_key_block.iter().zip(decomposition_iter)
        {
            slice_wrapping_sub_scalar_mul_assign(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.value().cast_into(),
            );
        }
    }
}

/// Parallel variant of [`keyswitch_lwe_ciphertext`].
///
/// This will use all threads available in the current rayon thread pool.
///
/// Automatically dispatches to
/// [`par_keyswitch_lwe_ciphertext_with_thread_count_native_mod_compatible`] or
/// [`par_keyswitch_lwe_ciphertext_with_thread_count_other_mod`] depending on the ciphertext modulus
/// of the input `lwe_keyswitch_key`.
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
/// // Use all threads available in the current rayon thread pool
/// par_keyswitch_lwe_ciphertext(&ksk, &input_lwe, &mut output_lwe);
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
pub fn par_keyswitch_lwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger + Send + Sync,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let thread_count = ThreadCount(rayon::current_num_threads());
    par_keyswitch_lwe_ciphertext_with_thread_count(
        lwe_keyswitch_key,
        input_lwe_ciphertext,
        output_lwe_ciphertext,
        thread_count,
    );
}

/// Parallel variant of [`keyswitch_lwe_ciphertext`].
///
/// This will try to use `thread_count` threads for the computation, if this number is bigger than
/// the available number of threads in the current rayon thread pool then only the number of
/// available threads will be used. Note that `thread_count` cannot be 0.
///
/// Automatically dispatches to
/// [`par_keyswitch_lwe_ciphertext_with_thread_count_native_mod_compatible`] or
/// [`par_keyswitch_lwe_ciphertext_with_thread_count_other_mod`] depending on the ciphertext modulus
/// of the input `lwe_keyswitch_key`.
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
/// // Try to use 4 threads for the keyswitch if enough are available
/// // in the current rayon thread pool
/// par_keyswitch_lwe_ciphertext_with_thread_count(
///     &ksk,
///     &input_lwe,
///     &mut output_lwe,
///     ThreadCount(4),
/// );
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
pub fn par_keyswitch_lwe_ciphertext_with_thread_count<Scalar, KSKCont, InputCont, OutputCont>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        par_keyswitch_lwe_ciphertext_with_thread_count_native_mod_compatible(
            lwe_keyswitch_key,
            input_lwe_ciphertext,
            output_lwe_ciphertext,
            thread_count,
        )
    } else {
        par_keyswitch_lwe_ciphertext_with_thread_count_other_mod(
            lwe_keyswitch_key,
            input_lwe_ciphertext,
            output_lwe_ciphertext,
            thread_count,
        )
    }
}

/// Specialized implementation of a parallel LWE keyswitch when inputs have power of two moduli.
///
/// # Panics
///
/// Panics if the modulus of the inputs are not power of twos.
/// Panics if the output `output_lwe_ciphertext` modulus is not equal to the `lwe_keyswitch_key`
/// modulus.
pub fn par_keyswitch_lwe_ciphertext_with_thread_count_native_mod_compatible<
    Scalar,
    KSKCont,
    InputCont,
    OutputCont,
>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
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

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let output_lwe_size = output_lwe_ciphertext.lwe_size();

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // If the moduli are not the same, we need to round the body in the output ciphertext
    if output_ciphertext_modulus != input_ciphertext_modulus
        && !output_ciphertext_modulus.is_native_modulus()
    {
        let modulus_bits = output_ciphertext_modulus.get_custom_modulus().ilog2() as usize;
        let output_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(modulus_bits),
            DecompositionLevelCount(1),
        );

        *output_lwe_ciphertext.get_mut_body().data =
            output_decomposer.closest_representable(*output_lwe_ciphertext.get_mut_body().data);
    }

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
    );

    // Don't go above the current number of threads
    let thread_count = thread_count.0.min(rayon::current_num_threads());
    let mut intermediate_accumulators = Vec::with_capacity(thread_count);

    // Smallest chunk_size such that thread_count * chunk_size >= input_lwe_size
    let chunk_size = input_lwe_ciphertext.lwe_size().0.div_ceil(thread_count);

    lwe_keyswitch_key
        .par_chunks(chunk_size)
        .zip(
            input_lwe_ciphertext
                .get_mask()
                .as_ref()
                .par_chunks(chunk_size),
        )
        .map(|(keyswitch_key_block_chunk, input_mask_element_chunk)| {
            let mut buffer =
                LweCiphertext::new(Scalar::ZERO, output_lwe_size, output_ciphertext_modulus);

            for (keyswitch_key_block, &input_mask_element) in keyswitch_key_block_chunk
                .iter()
                .zip(input_mask_element_chunk.iter())
            {
                let decomposition_iter = decomposer.decompose(input_mask_element);
                // Loop over the levels
                for (level_key_ciphertext, decomposed) in
                    keyswitch_key_block.iter().zip(decomposition_iter)
                {
                    slice_wrapping_sub_scalar_mul_assign(
                        buffer.as_mut(),
                        level_key_ciphertext.as_ref(),
                        decomposed.value(),
                    );
                }
            }
            buffer
        })
        .collect_into_vec(&mut intermediate_accumulators);

    let reduced = intermediate_accumulators
        .par_iter_mut()
        .reduce_with(|lhs, rhs| {
            lhs.as_mut()
                .iter_mut()
                .zip(rhs.as_ref().iter())
                .for_each(|(dst, &src)| *dst = (*dst).wrapping_add(src));

            lhs
        })
        .unwrap();

    output_lwe_ciphertext
        .get_mut_mask()
        .as_mut()
        .copy_from_slice(reduced.get_mask().as_ref());
    let reduced_ksed_body = *reduced.get_body().data;

    // Add the reduced body of the keyswitch to the output body to complete the keyswitch
    *output_lwe_ciphertext.get_mut_body().data =
        (*output_lwe_ciphertext.get_mut_body().data).wrapping_add(reduced_ksed_body);
}

/// Specialized implementation of a parallel LWE keyswitch when inputs have non power of two moduli.
///
/// # Panics
///
/// Panics if the modulus of the inputs are power of twos.
/// Panics if the modulus of the inputs are not all equal.
pub fn par_keyswitch_lwe_ciphertext_with_thread_count_other_mod<
    Scalar,
    KSKCont,
    InputCont,
    OutputCont,
>(
    lwe_keyswitch_key: &LweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut LweCiphertext<OutputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
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

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, output LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        output_lwe_ciphertext.ciphertext_modulus()
    );

    assert_eq!(
        lwe_keyswitch_key.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus(),
        "Mismatched CiphertextModulus. \
        LweKeyswitchKey CiphertextModulus: {:?}, input LweCiphertext CiphertextModulus {:?}.",
        lwe_keyswitch_key.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );

    let ciphertext_modulus = lwe_keyswitch_key.ciphertext_modulus();

    assert!(
        !ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports non power of 2 moduli"
    );

    let ciphertext_modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let output_lwe_size = output_lwe_ciphertext.lwe_size();

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().data = *input_lwe_ciphertext.get_body().data;

    // We instantiate a decomposer
    let decomposer = SignedDecomposerNonNative::new(
        lwe_keyswitch_key.decomposition_base_log(),
        lwe_keyswitch_key.decomposition_level_count(),
        ciphertext_modulus,
    );

    // Don't go above the current number of threads
    let thread_count = thread_count.0.min(rayon::current_num_threads());
    let mut intermediate_accumulators = Vec::with_capacity(thread_count);

    // Smallest chunk_size such that thread_count * chunk_size >= input_lwe_size
    let chunk_size = input_lwe_ciphertext.lwe_size().0.div_ceil(thread_count);

    lwe_keyswitch_key
        .par_chunks(chunk_size)
        .zip(
            input_lwe_ciphertext
                .get_mask()
                .as_ref()
                .par_chunks(chunk_size),
        )
        .map(|(keyswitch_key_block_chunk, input_mask_element_chunk)| {
            let mut buffer = LweCiphertext::new(Scalar::ZERO, output_lwe_size, ciphertext_modulus);

            for (keyswitch_key_block, &input_mask_element) in keyswitch_key_block_chunk
                .iter()
                .zip(input_mask_element_chunk.iter())
            {
                let decomposition_iter = decomposer.decompose(input_mask_element);
                // Loop over the levels
                for (level_key_ciphertext, decomposed) in
                    keyswitch_key_block.iter().zip(decomposition_iter)
                {
                    slice_wrapping_sub_scalar_mul_assign_custom_modulus(
                        buffer.as_mut(),
                        level_key_ciphertext.as_ref(),
                        decomposed.modular_value(),
                        ciphertext_modulus_as_scalar,
                    );
                }
            }
            buffer
        })
        .collect_into_vec(&mut intermediate_accumulators);

    let reduced = intermediate_accumulators
        .par_iter_mut()
        .reduce_with(|lhs, rhs| {
            lhs.as_mut()
                .iter_mut()
                .zip(rhs.as_ref().iter())
                .for_each(|(dst, &src)| {
                    *dst = (*dst).wrapping_add_custom_mod(src, ciphertext_modulus_as_scalar)
                });

            lhs
        })
        .unwrap();

    output_lwe_ciphertext
        .get_mut_mask()
        .as_mut()
        .copy_from_slice(reduced.get_mask().as_ref());
    let reduced_ksed_body = *reduced.get_body().data;

    // Add the reduced body of the keyswitch to the output body to complete the keyswitch
    *output_lwe_ciphertext.get_mut_body().data = (*output_lwe_ciphertext.get_mut_body().data)
        .wrapping_add_custom_mod(reduced_ksed_body, ciphertext_modulus_as_scalar);
}
