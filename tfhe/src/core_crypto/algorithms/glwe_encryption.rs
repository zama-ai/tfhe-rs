//! Module containing primitives pertaining to [`GLWE ciphertext
//! encryption`](`GlweCiphertext#glwe-encryption`).

use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::{
    slice_wrapping_scalar_div_assign, slice_wrapping_scalar_mul_assign,
};
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Distribution, Uniform};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the GLWE assign encryption between all functions
/// needing it.
pub fn fill_glwe_mask_and_body_for_encryption_assign<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = output_body.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        fill_glwe_mask_and_body_for_encryption_assign_native_mod_compatible(
            glwe_secret_key,
            output_mask,
            output_body,
            noise_distribution,
            generator,
        )
    } else {
        fill_glwe_mask_and_body_for_encryption_assign_non_native_mod(
            glwe_secret_key,
            output_mask,
            output_body,
            noise_distribution,
            generator,
        )
    }
}

pub fn fill_glwe_mask_and_body_for_encryption_assign_native_mod_compatible<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between output_mask ({:?}) and output_body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );
    assert_eq!(
        output_mask.glwe_dimension(),
        glwe_secret_key.glwe_dimension(),
        "Mismatched GlweDimension between output_mask ({:?}) and glwe_secret_key ({:?})",
        output_mask.glwe_dimension(),
        glwe_secret_key.glwe_dimension(),
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
        output_body.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
    }

    polynomial_wrapping_add_multisum_assign(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
}

pub fn fill_glwe_mask_and_body_for_encryption_assign_non_native_mod<
    Scalar,
    NoiseDistribution,
    KeyCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between output_mask ({:?}) and output_body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    generator.unsigned_integer_slice_wrapping_add_random_noise_from_distribution_custom_mod_assign(
        output_body.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    polynomial_wrapping_add_multisum_assign_custom_mod(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
        ciphertext_modulus.get_custom_modulus().cast_into(),
    );
}

/// Variant of [`encrypt_glwe_ciphertext`] which assumes that the plaintexts to encrypt are already
/// loaded in the body of the output [`GLWE ciphertext`](`GlweCiphertext`), this is sometimes useful
/// to avoid allocating a [`PlaintextList`] in situ.
///
/// See this [`formal definition`](`GlweCiphertext#glwe-encryption`) for the definition
/// of the GLWE encryption algorithm.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// // Manually fill the body with the encoded message
/// glwe.get_mut_body().as_mut().fill(encoded_msg);
///
/// encrypt_glwe_ciphertext_assign(
///     &glwe_secret_key,
///     &mut glwe,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_glwe_ciphertext_assign<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut GlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    fill_glwe_mask_and_body_for_encryption_assign(
        glwe_secret_key,
        &mut mask,
        &mut body,
        noise_distribution,
        generator,
    );
}

/// Convenience function to share the core logic of the seeded GLWE assign encryption between all
/// functions needing it.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_seeded_glwe_ciphertext_assign_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGlweCiphertext<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let mut mask = GlweMask::from_container(
        vec![
            Scalar::ZERO;
            glwe_ciphertext_mask_size(
                output.glwe_size().to_glwe_dimension(),
                output.polynomial_size()
            )
        ],
        output.polynomial_size(),
        output.ciphertext_modulus(),
    );
    let mut body = output.get_mut_body();

    fill_glwe_mask_and_body_for_encryption_assign(
        glwe_secret_key,
        &mut mask,
        &mut body,
        noise_distribution,
        generator,
    );
}

/// Convenience function to share the core logic of the GLWE encryption between all functions
/// needing it.
pub fn fill_glwe_mask_and_body_for_encryption<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let ciphertext_modulus = output_body.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        fill_glwe_mask_and_body_for_encryption_native_mod_compatible(
            glwe_secret_key,
            output_mask,
            output_body,
            encoded,
            noise_distribution,
            generator,
        )
    } else {
        fill_glwe_mask_and_body_for_encryption_other_mod(
            glwe_secret_key,
            output_mask,
            output_body,
            encoded,
            noise_distribution,
            generator,
        )
    }
}

pub fn fill_glwe_mask_and_body_for_encryption_native_mod_compatible<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    generator.fill_slice_with_random_noise_from_distribution_custom_mod(
        output_body.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    polynomial_wrapping_add_assign(
        &mut output_body.as_mut_polynomial(),
        &encoded.as_polynomial(),
    );

    if !ciphertext_modulus.is_native_modulus() {
        let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
        slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
        slice_wrapping_scalar_mul_assign(output_body.as_mut(), torus_scaling);
    }

    polynomial_wrapping_add_multisum_assign(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );
}

pub fn fill_glwe_mask_and_body_for_encryption_other_mod<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    BodyCont,
    MaskCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_mask: &mut GlweMask<MaskCont>,
    output_body: &mut GlweBody<BodyCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    BodyCont: ContainerMut<Element = Scalar>,
    MaskCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_body.ciphertext_modulus();

    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);
    generator.fill_slice_with_random_noise_from_distribution_custom_mod(
        output_body.as_mut(),
        noise_distribution,
        ciphertext_modulus,
    );

    let ciphertext_modulus = ciphertext_modulus.get_custom_modulus().cast_into();

    polynomial_wrapping_add_assign_custom_mod(
        &mut output_body.as_mut_polynomial(),
        &encoded.as_polynomial(),
        ciphertext_modulus,
    );

    polynomial_wrapping_add_multisum_assign_custom_mod(
        &mut output_body.as_mut_polynomial(),
        &output_mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
        ciphertext_modulus,
    );
}

/// Encrypt a (scalar) plaintext list in a [`GLWE ciphertext`](`GlweCiphertext`).
///
/// # Formal Definition
///
/// See this [`formal definition`](`GlweCiphertext#glwe-encryption`) for the definition
/// of the GLWE encryption algorithm.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_glwe_ciphertext<Scalar, NoiseDistribution, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext.polynomial_size().0 == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output ciphertext PlaintextCount of input. \
    Got {:?} in output, and {:?} in input.",
        output_glwe_ciphertext.polynomial_size(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let (mut mask, mut body) = output_glwe_ciphertext.get_mut_mask_and_body();

    fill_glwe_mask_and_body_for_encryption(
        glwe_secret_key,
        &mut mask,
        &mut body,
        input_plaintext_list,
        noise_distribution,
        generator,
    );
}

/// Encrypt a (scalar) plaintext list in [`GLWE ciphertexts`](`GlweCiphertext`) of the output
/// [`GLWE ciphertext list`](`GlweCiphertextList`).
///
/// See this [`formal definition`](`GlweCiphertext#glwe-encryption`) for the definition
/// of the GLWE encryption algorithm.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let glwe_count = GlweCiphertextCount(2);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(
///     encoded_msg,
///     PlaintextCount(polynomial_size.0 * glwe_count.0),
/// );
///
/// // Create a new GlweCiphertextList
/// let mut glwe_list = GlweCiphertextList::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     glwe_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_glwe_ciphertext_list(
///     &glwe_secret_key,
///     &mut glwe_list,
///     &plaintext_list,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext_list(&glwe_secret_key, &glwe_list, &mut output_plaintext_list);
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_glwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    OutputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_glwe_ciphertext_list: &mut GlweCiphertextList<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext_list
            .polynomial_size()
            .0
            .checked_mul(output_glwe_ciphertext_list.glwe_ciphertext_count().0)
            .unwrap()
            == input_plaintext_list.plaintext_count().0,
        "Mismatch between required number of plaintexts: {} ({:?} * {:?}) and input \
        PlaintextCount: {:?}",
        output_glwe_ciphertext_list.polynomial_size().0
            * output_glwe_ciphertext_list.glwe_ciphertext_count().0,
        output_glwe_ciphertext_list.polynomial_size(),
        output_glwe_ciphertext_list.glwe_ciphertext_count(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext_list.glwe_size().to_glwe_dimension()
            == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext_list.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext_list.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext_list.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let polynomial_size = output_glwe_ciphertext_list.polynomial_size();
    for (mut ciphertext, encoded) in output_glwe_ciphertext_list
        .iter_mut()
        .zip(input_plaintext_list.chunks_exact(polynomial_size.0))
    {
        encrypt_glwe_ciphertext(
            glwe_secret_key,
            &mut ciphertext,
            &encoded,
            noise_distribution,
            generator,
        );
    }
}

/// Decrypt a [`GLWE ciphertext`](`GlweCiphertext`) in a (scalar) plaintext list.
///
/// See [`encrypt_glwe_ciphertext`] for usage.
///
/// # Formal Definition
///
/// See this [`formal definition`](`GlweCiphertext#glwe-decryption`) for the definition
/// of the GLWE decryption algorithm.
pub fn decrypt_glwe_ciphertext<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        decrypt_glwe_ciphertext_native_mod_compatible(
            glwe_secret_key,
            input_glwe_ciphertext,
            output_plaintext_list,
        );
    } else {
        decrypt_glwe_ciphertext_other_mod(
            glwe_secret_key,
            input_glwe_ciphertext,
            output_plaintext_list,
        );
    }
}

pub fn decrypt_glwe_ciphertext_native_mod_compatible<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0 == input_glwe_ciphertext.polynomial_size().0,
        "Mismatched output PlaintextCount {:?} and input PolynomialSize {:?}",
        output_plaintext_list.plaintext_count(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert!(
        glwe_secret_key.glwe_dimension() == input_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        "Mismatched GlweDimension between glwe_secret_key {:?} and input_glwe_ciphertext {:?}",
        glwe_secret_key.glwe_dimension(),
        input_glwe_ciphertext.glwe_size().to_glwe_dimension()
    );
    assert!(
        glwe_secret_key.polynomial_size() == input_glwe_ciphertext.polynomial_size(),
        "Mismatched PolynomialSize between glwe_secret_key {:?} and input_glwe_ciphertext {:?}",
        glwe_secret_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );

    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let (mask, body) = input_glwe_ciphertext.get_mask_and_body();
    output_plaintext_list
        .as_mut()
        .copy_from_slice(body.as_ref());
    polynomial_wrapping_sub_multisum_assign(
        &mut output_plaintext_list.as_mut_polynomial(),
        &mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
    );

    if !ciphertext_modulus.is_native_modulus() {
        slice_wrapping_scalar_div_assign(
            output_plaintext_list.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );
    }
}

pub fn decrypt_glwe_ciphertext_other_mod<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    input_glwe_ciphertext: &GlweCiphertext<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0 == input_glwe_ciphertext.polynomial_size().0,
        "Mismatched output PlaintextCount {:?} and input PolynomialSize {:?}",
        output_plaintext_list.plaintext_count(),
        input_glwe_ciphertext.polynomial_size()
    );
    assert!(
        glwe_secret_key.glwe_dimension() == input_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        "Mismatched GlweDimension between glwe_secret_key {:?} and input_glwe_ciphertext {:?}",
        glwe_secret_key.glwe_dimension(),
        input_glwe_ciphertext.glwe_size().to_glwe_dimension()
    );
    assert!(
        glwe_secret_key.polynomial_size() == input_glwe_ciphertext.polynomial_size(),
        "Mismatched PolynomialSize between glwe_secret_key {:?} and input_glwe_ciphertext {:?}",
        glwe_secret_key.polynomial_size(),
        input_glwe_ciphertext.polynomial_size()
    );

    let ciphertext_modulus = input_glwe_ciphertext.ciphertext_modulus();

    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    let ciphertext_modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();

    let (mask, body) = input_glwe_ciphertext.get_mask_and_body();
    output_plaintext_list
        .as_mut()
        .copy_from_slice(body.as_ref());
    polynomial_wrapping_sub_multisum_assign_custom_mod(
        &mut output_plaintext_list.as_mut_polynomial(),
        &mask.as_polynomial_list(),
        &glwe_secret_key.as_polynomial_list(),
        ciphertext_modulus_as_scalar,
    );
}

/// Decrypt a [`GLWE ciphertext list`](`GlweCiphertextList`) in a (scalar) plaintext list.
///
/// See [`encrypt_glwe_ciphertext_list`] for usage.
pub fn decrypt_glwe_ciphertext_list<Scalar, KeyCont, InputCont, OutputCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    input_glwe_ciphertext_list: &GlweCiphertextList<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0
            == input_glwe_ciphertext_list.polynomial_size().0
                * input_glwe_ciphertext_list.glwe_ciphertext_count().0,
        "Mismatched output PlaintextCount {:?} and input PolynomialSize ({:?}) * \
        GlweCiphertextCount ({:?}) = {:?}",
        output_plaintext_list.plaintext_count(),
        input_glwe_ciphertext_list.polynomial_size(),
        input_glwe_ciphertext_list.glwe_ciphertext_count(),
        input_glwe_ciphertext_list.polynomial_size().0
            * input_glwe_ciphertext_list.glwe_ciphertext_count().0
    );
    assert!(
        glwe_secret_key.glwe_dimension()
            == input_glwe_ciphertext_list.glwe_size().to_glwe_dimension(),
        "Mismatched GlweDimension between glwe_secret_key {:?} and input_glwe_ciphertext_list {:?}",
        glwe_secret_key.glwe_dimension(),
        input_glwe_ciphertext_list.glwe_size().to_glwe_dimension()
    );
    assert!(
        glwe_secret_key.polynomial_size() == input_glwe_ciphertext_list.polynomial_size(),
        "Mismatched PolynomialSize between glwe_secret_key {:?} and input_glwe_ciphertext_list {:?}",
        glwe_secret_key.polynomial_size(),
        input_glwe_ciphertext_list.polynomial_size()
    );

    for (ciphertext, mut output_sublist) in input_glwe_ciphertext_list
        .iter()
        .zip(output_plaintext_list.chunks_exact_mut(input_glwe_ciphertext_list.polynomial_size().0))
    {
        decrypt_glwe_ciphertext(glwe_secret_key, &ciphertext, &mut output_sublist);
    }
}

/// A trivial encryption uses a zero mask and no noise.
///
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the programmable
/// bootstrap.
///
/// By definition a trivial encryption can be decrypted by any [`GLWE secret key`](`GlweSecretKey`).
///
/// Trivially encrypt an input (scalar) plaintext list in a [`GLWE ciphertext`](`GlweCiphertext`).
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// trivially_encrypt_glwe_ciphertext(&mut glwe, &plaintext_list);
///
/// // Here we show the content of the trivial encryption is actually the input data in clear and
/// // that the mask is full of 0s
/// assert_eq!(glwe.get_body().as_ref(), plaintext_list.as_ref());
/// glwe.get_mask()
///     .as_ref()
///     .iter()
///     .for_each(|&elt| assert_eq!(elt, 0));
///
/// // Now we demonstrate that any random GlweSecretKey can be used to decrypt it.
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Again the trivial encryption encrypts _nothing_
/// assert_eq!(output_plaintext_list.as_ref(), glwe.get_body().as_ref());
/// ```
pub fn trivially_encrypt_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    output: &mut GlweCiphertext<OutputCont>,
    encoded: &PlaintextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        encoded.plaintext_count().0 == output.polynomial_size().0,
        "Mismatched input PlaintextCount {:?} and output PolynomialSize {:?}",
        encoded.plaintext_count(),
        output.polynomial_size()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    mask.as_mut().fill(Scalar::ZERO);
    body.as_mut().copy_from_slice(encoded.as_ref());

    let ciphertext_modulus = body.ciphertext_modulus();

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native | CiphertextModulusKind::Other => (),
        CiphertextModulusKind::NonNativePowerOfTwo => {
            slice_wrapping_scalar_mul_assign(
                body.as_mut(),
                ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            );
        }
    }
}

/// A trivial encryption uses a zero mask and no noise.
///
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input. For
/// example, a trivial GLWE encryption of a public lookup table is used in the programmable
/// bootstrap.
///
/// By definition a trivial encryption can be decrypted by any [`GLWE secret key`](`GlweSecretKey`).
///
/// Allocate a new [`GLWE ciphertext`](`GlweCiphertext`) and trivially encrypt an input (scalar)
/// plaintext list in it.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let glwe = allocate_and_trivially_encrypt_new_glwe_ciphertext(
///     glwe_size,
///     &plaintext_list,
///     ciphertext_modulus,
/// );
///
/// // Here we show the content of the trivial encryption is actually the input data in clear and
/// // that the mask is full of 0s
/// assert_eq!(glwe.get_body().as_ref(), plaintext_list.as_ref());
/// glwe.get_mask()
///     .as_ref()
///     .iter()
///     .for_each(|&elt| assert_eq!(elt, 0));
///
/// // Now we demonstrate that any random GlweSecretKey can be used to decrypt it.
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// // Again the trivial encryption encrypts _nothing_
/// assert_eq!(output_plaintext_list.as_ref(), glwe.get_body().as_ref());
/// ```
pub fn allocate_and_trivially_encrypt_new_glwe_ciphertext<Scalar, InputCont>(
    glwe_size: GlweSize,
    encoded: &PlaintextList<InputCont>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> GlweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
{
    let polynomial_size = PolynomialSize(encoded.plaintext_count().0);

    let mut new_ct =
        GlweCiphertextOwned::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    let mut body = new_ct.get_mut_body();
    body.as_mut().copy_from_slice(encoded.as_ref());

    // Manage the non native power of 2 encoding
    if ciphertext_modulus.kind() == CiphertextModulusKind::NonNativePowerOfTwo {
        slice_wrapping_scalar_mul_assign(
            body.as_mut(),
            ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
        );
    }

    new_ct
}

/// Convenience function to share the core logic of the seeded GLWE encryption between all
/// functions needing it.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_seeded_glwe_ciphertext_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_glwe_ciphertext: &mut SeededGlweCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output_glwe_ciphertext.polynomial_size().0 == input_plaintext_list.plaintext_count().0,
        "Mismatch between PolynomialSize of output ciphertext PlaintextCount of input. \
    Got {:?} in output, and {:?} in input.",
        output_glwe_ciphertext.polynomial_size(),
        input_plaintext_list.plaintext_count()
    );
    assert!(
        output_glwe_ciphertext.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );
    assert!(
        output_glwe_ciphertext.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between PolynomialSize of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output_glwe_ciphertext.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    let glwe_dimension = output_glwe_ciphertext.glwe_size().to_glwe_dimension();
    let polynomial_size = output_glwe_ciphertext.polynomial_size();
    let ciphertext_modulus = output_glwe_ciphertext.ciphertext_modulus();

    let mut body = output_glwe_ciphertext.get_mut_body();

    let mut tmp_mask = GlweMask::from_container(
        vec![Scalar::ZERO; glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)],
        polynomial_size,
        ciphertext_modulus,
    );

    fill_glwe_mask_and_body_for_encryption(
        glwe_secret_key,
        &mut tmp_mask,
        &mut body,
        input_plaintext_list,
        noise_distribution,
        generator,
    );
}

/// Encrypt a [`PlaintextList`] in a
/// [`compressed/seeded GLWE ciphertext`](`SeededGlweCiphertext`).
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// // Create a new GlweCiphertext
/// let mut glwe = SeededGlweCiphertext::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// encrypt_seeded_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_noise_distribution,
///     seeder,
/// );
///
/// let glwe = glwe.decompress_into_glwe_ciphertext();
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_seeded_glwe_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    InputCont,
    OutputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output_glwe_ciphertext: &mut SeededGlweCiphertext<OutputCont>,
    input_plaintext_list: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output_glwe_ciphertext.compression_seed(),
        noise_seeder,
    );

    encrypt_seeded_glwe_ciphertext_with_pre_seeded_generator(
        glwe_secret_key,
        output_glwe_ciphertext,
        input_plaintext_list,
        noise_distribution,
        &mut generator,
    );
}

/// Convenience function to share the core logic of the seeded GLWE list encryption between all
/// functions needing it.
///
/// Allows to efficiently encrypt lists of seeded GLWE.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_seeded_glwe_ciphertext_list_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGlweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatched GlweDimension between input GlweSecretKey {:?} and output \
        SeededGlweCiphertextList {:?}.",
        glwe_secret_key.glwe_dimension(),
        output.glwe_size().to_glwe_dimension(),
    );
    assert!(
        output
            .glwe_ciphertext_count()
            .0
            .checked_mul(output.polynomial_size().0)
            .unwrap()
            == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts while {:?} plaintexts are required to encrypt {:?} ciphertexts.",
        encoded.plaintext_count(),
        output.glwe_ciphertext_count().0 * output.polynomial_size().0,
        output.glwe_ciphertext_count()
    );

    let mut output_mask = GlweMask::from_container(
        vec![
            Scalar::ZERO;
            glwe_ciphertext_mask_size(
                output.glwe_size().to_glwe_dimension(),
                output.polynomial_size(),
            )
        ],
        output.polynomial_size(),
        output.ciphertext_modulus(),
    );

    // TODO: use forking generators (for later parallel implementation).

    let polynomial_size = output.polynomial_size();

    for (mut output_glwe, plaintext_list) in output
        .iter_mut()
        .zip(encoded.chunks_exact(polynomial_size.0))
    {
        fill_glwe_mask_and_body_for_encryption(
            glwe_secret_key,
            &mut output_mask,
            &mut output_glwe.get_mut_body(),
            &plaintext_list,
            noise_distribution,
            generator,
        );
    }
}

/// Encrypt a [`PlaintextList`] in a
/// [`compressed/seeded LWE ciphertext list`](`SeededLweCiphertextList`).
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let glwe_count = GlweCiphertextCount(2);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(
///     encoded_msg,
///     PlaintextCount(polynomial_size.0 * glwe_count.0),
/// );
///
/// // Create a new GlweCiphertextList
/// let mut glwe_list = SeededGlweCiphertextList::new(
///     0u64,
///     glwe_size,
///     polynomial_size,
///     glwe_count,
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// encrypt_seeded_glwe_ciphertext_list(
///     &glwe_secret_key,
///     &mut glwe_list,
///     &plaintext_list,
///     glwe_noise_distribution,
///     seeder,
/// );
///
/// let glwe_list = glwe_list.decompress_into_glwe_ciphertext_list();
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, plaintext_list.plaintext_count());
///
/// decrypt_glwe_ciphertext_list(&glwe_secret_key, &glwe_list, &mut output_plaintext_list);
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_seeded_glwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    NoiseSeeder,
>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    output: &mut SeededGlweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed(),
        noise_seeder,
    );

    encrypt_seeded_glwe_ciphertext_list_with_pre_seeded_generator(
        glwe_secret_key,
        output,
        encoded,
        noise_distribution,
        &mut generator,
    );
}
