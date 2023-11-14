//! Module containing primitives pertaining to [`LWE ciphertext encryption and
//! decryption`](`LweCiphertext#lwe-encryption`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, RandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Convenience function to share the core logic of the LWE encryption between all functions needing
/// it.
pub fn fill_lwe_mask_and_body_for_encryption<Scalar, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        fill_lwe_mask_and_body_for_encryption_native_mod_compatible(
            lwe_secret_key,
            output_mask,
            output_body,
            encoded,
            noise_parameters,
            generator,
        );
    } else {
        fill_lwe_mask_and_body_for_encryption_other_mod(
            lwe_secret_key,
            output_mask,
            output_body,
            encoded,
            noise_parameters,
            generator,
        );
    }
}

pub fn fill_lwe_mask_and_body_for_encryption_native_mod_compatible<
    Scalar,
    KeyCont,
    OutputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // generate a randomly uniform mask
    generator.fill_slice_with_random_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    // generate an error from the normal distribution described by std_dev
    let noise = generator.random_noise_custom_mod(noise_parameters, ciphertext_modulus);
    // compute the multisum between the secret key and the mask
    let mask_key_dot_product = (*output_body.data).wrapping_add(slice_wrapping_dot_product(
        output_mask.as_ref(),
        lwe_secret_key.as_ref(),
    ));

    // Store sum(ai * si) + delta * m + e in the body
    *output_body.data = mask_key_dot_product
        .wrapping_add(encoded.0)
        .wrapping_add(noise);

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => (),
        CiphertextModulusKind::NonNativePowerOfTwo => {
            // Manage power of 2 encoding to map to the native case
            let torus_scaling = ciphertext_modulus.get_power_of_two_scaling_to_native_torus();
            slice_wrapping_scalar_mul_assign(output_mask.as_mut(), torus_scaling);
            *output_body.data = (*output_body.data).wrapping_mul(torus_scaling);
        }
        CiphertextModulusKind::Other => unreachable!(),
    };
}

pub fn fill_lwe_mask_and_body_for_encryption_other_mod<Scalar, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_body.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    // generate a randomly uniform mask
    generator.fill_slice_with_random_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    // generate an error from the normal distribution described by std_dev
    let noise = generator.random_noise_custom_mod(noise_parameters, ciphertext_modulus);

    let ciphertext_modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();

    // compute the multisum between the secret key and the mask
    let mask_key_dot_product = slice_wrapping_dot_product_custom_mod(
        output_mask.as_ref(),
        lwe_secret_key.as_ref(),
        ciphertext_modulus_as_scalar,
    );

    // Store sum(ai * si) + delta * m + e in the body
    *output_body.data = mask_key_dot_product
        .wrapping_add_custom_mod(encoded.0, ciphertext_modulus_as_scalar)
        .wrapping_add_custom_mod(noise, ciphertext_modulus_as_scalar);
}

/// Encrypt an input plaintext in an output [`LWE ciphertext`](`LweCiphertext`).
///
/// See the [`LWE ciphertext formal definition`](`LweCiphertext#lwe-encryption`) for the definition
/// of the encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// encrypt_lwe_ciphertext(
///     &lwe_secret_key,
///     &mut lwe,
///     plaintext,
///     lwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn encrypt_lwe_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mut mask, mut body) = output.get_mut_mask_and_body();

    fill_lwe_mask_and_body_for_encryption(
        lwe_secret_key,
        &mut mask,
        &mut body,
        encoded,
        noise_parameters,
        generator,
    );
}

/// Allocate a new [`LWE ciphertext`](`LweCiphertext`) and encrypt an input plaintext in it.
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let lwe = allocate_and_encrypt_new_lwe_ciphertext(
///     &lwe_secret_key,
///     plaintext,
///     lwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn allocate_and_encrypt_new_lwe_ciphertext<Scalar, KeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct = LweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );

    encrypt_lwe_ciphertext(
        lwe_secret_key,
        &mut new_ct,
        encoded,
        noise_parameters,
        generator,
    );

    new_ct
}

/// A trivial encryption uses a zero mask and no noise.
///
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input.
///
/// By definition a trivial encryption can be decrypted by any [`LWE secret key`](`LweSecretKey`).
///
/// Trivially encrypt an input plaintext in an [`LWE ciphertext`](`LweCiphertext`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// trivially_encrypt_lwe_ciphertext(&mut lwe, plaintext);
///
/// // Here we show the content of the trivial encryption is actually the input data in clear and
/// // that the mask is full of 0s
/// assert_eq!(*lwe.get_body().data, plaintext.0);
/// lwe.get_mask()
///     .as_ref()
///     .iter()
///     .for_each(|&elt| assert_eq!(elt, 0));
///
/// // Now we demonstrate that any random LweSecretKey can be used to decrypt it.
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
///
/// // Again the trivial encryption encrypts _nothing_
/// assert_eq!(decrypted_plaintext.0, *lwe.get_body().data);
/// ```
pub fn trivially_encrypt_lwe_ciphertext<Scalar, OutputCont>(
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
{
    output.get_mut_mask().as_mut().fill(Scalar::ZERO);

    let output_body = output.get_mut_body();
    let ciphertext_modulus = output_body.ciphertext_modulus();

    *output_body.data = match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native | CiphertextModulusKind::Other => encoded.0,
        CiphertextModulusKind::NonNativePowerOfTwo => {
            // Manage non native power of 2 encoding
            encoded.0 * ciphertext_modulus.get_power_of_two_scaling_to_native_torus()
        }
    };
}

/// A trivial encryption uses a zero mask and no noise.
///
/// It is absolutely not secure, as the body contains a direct copy of the plaintext.
/// However, it is useful for some FHE algorithms taking public information as input.
///
/// By definition a trivial encryption can be decrypted by any [`LWE secret key`](`LweSecretKey`).
///
/// Allocate a new [`LWE ciphertext`](`LweCiphertext`) and trivially encrypt an input plaintext in
/// it.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(
///     lwe_dimension.to_lwe_size(),
///     plaintext,
///     ciphertext_modulus,
/// );
///
/// // Here we show the content of the trivial encryption is actually the input data in clear and
/// // that the mask is full of 0s
/// assert_eq!(*lwe.get_body().data, plaintext.0);
/// lwe.get_mask()
///     .as_ref()
///     .iter()
///     .for_each(|&elt| assert_eq!(elt, 0));
///
/// // Now we demonstrate that any random LweSecretKey can be used to decrypt it.
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
///
/// // Again the trivial encryption encrypts _nothing_
/// assert_eq!(decrypted_plaintext.0, *lwe.get_body().data);
/// ```
pub fn allocate_and_trivially_encrypt_new_lwe_ciphertext<Scalar>(
    lwe_size: LweSize,
    encoded: Plaintext<Scalar>,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
{
    let mut new_ct = LweCiphertextOwned::new(Scalar::ZERO, lwe_size, ciphertext_modulus);

    *new_ct.get_mut_body().data = encoded.0;

    let output_body = new_ct.get_mut_body();
    let ciphertext_modulus = output_body.ciphertext_modulus();

    *output_body.data = match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native | CiphertextModulusKind::Other => encoded.0,
        CiphertextModulusKind::NonNativePowerOfTwo => {
            // Manage non native power of 2 encoding
            encoded.0 * ciphertext_modulus.get_power_of_two_scaling_to_native_torus()
        }
    };

    new_ct
}

/// Decrypt an [`LWE ciphertext`](`LweCiphertext`) and return a noisy plaintext.
///
/// See [`encrypt_lwe_ciphertext`] for usage.
///
/// # Formal Definition
///
/// See the [`LWE ciphertext formal definition`](`LweCiphertext#lwe-decryption`) for the definition
/// of the encryption algorithm.
pub fn decrypt_lwe_ciphertext<Scalar, KeyCont, InputCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    lwe_ciphertext: &LweCiphertext<InputCont>,
) -> Plaintext<Scalar>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    let ciphertext_modulus = lwe_ciphertext.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        decrypt_lwe_ciphertext_native_mod_compatible(lwe_secret_key, lwe_ciphertext)
    } else {
        decrypt_lwe_ciphertext_other_mod(lwe_secret_key, lwe_ciphertext)
    }
}

pub fn decrypt_lwe_ciphertext_native_mod_compatible<Scalar, KeyCont, InputCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    lwe_ciphertext: &LweCiphertext<InputCont>,
) -> Plaintext<Scalar>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        lwe_ciphertext.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        lwe_ciphertext.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let ciphertext_modulus = lwe_ciphertext.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let (mask, body) = lwe_ciphertext.get_mask_and_body();

    let mask_key_dot_product = slice_wrapping_dot_product(mask.as_ref(), lwe_secret_key.as_ref());
    let plaintext = (*body.data).wrapping_sub(mask_key_dot_product);

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => Plaintext(plaintext),
        CiphertextModulusKind::NonNativePowerOfTwo => {
            // Manage power of 2 encoding
            Plaintext(
                plaintext
                    .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus()),
            )
        }
        CiphertextModulusKind::Other => unreachable!(),
    }
}

pub fn decrypt_lwe_ciphertext_other_mod<Scalar, KeyCont, InputCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    lwe_ciphertext: &LweCiphertext<InputCont>,
) -> Plaintext<Scalar>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        lwe_ciphertext.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        lwe_ciphertext.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let ciphertext_modulus = lwe_ciphertext.ciphertext_modulus();

    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    let (mask, body) = lwe_ciphertext.get_mask_and_body();

    let ciphertext_modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();

    Plaintext((*body.data).wrapping_sub_custom_mod(
        slice_wrapping_dot_product_custom_mod(
            mask.as_ref(),
            lwe_secret_key.as_ref(),
            ciphertext_modulus_as_scalar,
        ),
        ciphertext_modulus_as_scalar,
    ))
}

/// Encrypt an input plaintext list in an output [`LWE ciphertext list`](`LweCiphertextList`).
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(lwe_ciphertext_count.0));
///
/// // Create a new LweCiphertextList
/// let mut lwe_list = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_list,
///     &plaintext_list,
///     lwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(lwe_list.lwe_ciphertext_count().0));
/// decrypt_lwe_ciphertext_list(&lwe_secret_key, &lwe_list, &mut output_plaintext_list);
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
pub fn encrypt_lwe_ciphertext_list<Scalar, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .fork_lwe_list_to_lwe::<Scalar>(output.lwe_ciphertext_count(), output.lwe_size())
        .unwrap();

    for ((encoded_plaintext_ref, mut ciphertext), mut loop_generator) in
        encoded.iter().zip(output.iter_mut()).zip(gen_iter)
    {
        encrypt_lwe_ciphertext(
            lwe_secret_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            noise_parameters,
            &mut loop_generator,
        );
    }
}

/// Parallel variant of [`encrypt_lwe_ciphertext_list`].
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(lwe_ciphertext_count.0));
///
/// // Create a new LweCiphertextList
/// let mut lwe_list = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
///
/// par_encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_list,
///     &plaintext_list,
///     lwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(lwe_list.lwe_ciphertext_count().0));
/// decrypt_lwe_ciphertext_list(&lwe_secret_key, &lwe_list, &mut output_plaintext_list);
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
pub fn par_encrypt_lwe_ciphertext_list<Scalar, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .par_fork_lwe_list_to_lwe::<Scalar>(output.lwe_ciphertext_count(), output.lwe_size())
        .unwrap();

    encoded
        .par_iter()
        .zip(output.par_iter_mut())
        .zip(gen_iter)
        .for_each(|((encoded_plaintext_ref, mut ciphertext), mut generator)| {
            encrypt_lwe_ciphertext(
                lwe_secret_key,
                &mut ciphertext,
                encoded_plaintext_ref.into(),
                noise_parameters,
                &mut generator,
            );
        });
}

/// Decrypt an [`LWE ciphertext list`](`LweCiphertextList`) in a plaintext list.
///
/// See [`encrypt_lwe_ciphertext_list`] for usage.
///
/// See this [`formal definition`](`decrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE decryption algorithm.
pub fn decrypt_lwe_ciphertext_list<Scalar, KeyCont, InputCont, OutputCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    output_plaintext_list: &mut PlaintextList<OutputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        output_plaintext_list.plaintext_count().0
            == input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        "Mismatched output PlaintextCount {:?} and input LweCiphertextCount ({:?}).",
        output_plaintext_list.plaintext_count(),
        input_lwe_ciphertext_list.lwe_ciphertext_count(),
    );

    for (ciphertext, output_plaintext) in input_lwe_ciphertext_list
        .iter()
        .zip(output_plaintext_list.iter_mut())
    {
        *output_plaintext.0 = decrypt_lwe_ciphertext(lwe_secret_key, &ciphertext).0;
    }
}

/// Encrypt an input plaintext in an output [`LWE ciphertext`](`LweCiphertext`) using an
/// [`LWE public key`](`LwePublicKey`). The ciphertext can be decrypted using the
/// [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let zero_encryption_count =
///     LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_public_key = allocate_and_generate_new_lwe_public_key(
///     &lwe_secret_key,
///     zero_encryption_count,
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
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// encrypt_lwe_ciphertext_with_public_key(
///     &lwe_public_key,
///     &mut lwe,
///     plaintext,
///     &mut secret_generator,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn encrypt_lwe_ciphertext_with_public_key<Scalar, KeyCont, OutputCont, Gen>(
    lwe_public_key: &LwePublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between lwe_public_key ({:?}) and output ({:?})",
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    output.as_mut().fill(Scalar::ZERO);

    let mut tmp_zero_encryption =
        LweCiphertext::new(Scalar::ZERO, output.lwe_size(), output.ciphertext_modulus());

    let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];

    generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero) in ct_choice.iter().zip(lwe_public_key.iter()) {
        // chosen is 1 if chosen, 0 otherwise, so use a multiplication to avoid having a branch
        // depending on a value that's supposed to remain secret
        lwe_ciphertext_cleartext_mul(
            &mut tmp_zero_encryption,
            &public_encryption_of_zero,
            Cleartext(chosen),
        );
        lwe_ciphertext_add_assign(output, &tmp_zero_encryption);
    }

    lwe_ciphertext_plaintext_add_assign(output, encoded);
}

/// Encrypt an input plaintext in an output [`LWE ciphertext`](`LweCiphertext`) using a
/// [`seeded LWE public key`](`SeededLwePublicKey`). The ciphertext can be decrypted using the
/// [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let zero_encryption_count =
///     LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_public_key = allocate_and_generate_new_seeded_lwe_public_key(
///     &lwe_secret_key,
///     zero_encryption_count,
///     lwe_modular_std_dev,
///     ciphertext_modulus,
///     seeder,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// encrypt_lwe_ciphertext_with_seeded_public_key(
///     &lwe_public_key,
///     &mut lwe,
///     plaintext,
///     &mut secret_generator,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn encrypt_lwe_ciphertext_with_seeded_public_key<Scalar, KeyCont, OutputCont, Gen>(
    lwe_public_key: &SeededLwePublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus(),
        "Mismatched moduli between lwe_public_key ({:?}) and output ({:?})",
        lwe_public_key.ciphertext_modulus(),
        output.ciphertext_modulus()
    );

    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    output.as_mut().fill(Scalar::ZERO);

    let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];

    generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    let ciphertext_modulus = output.ciphertext_modulus();

    let mut tmp_zero_encryption =
        LweCiphertext::new(Scalar::ZERO, lwe_public_key.lwe_size(), ciphertext_modulus);

    let mut random_generator =
        RandomGenerator::<ActivatedRandomGenerator>::new(lwe_public_key.compression_seed().seed);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero_body) in ct_choice.iter().zip(lwe_public_key.iter()) {
        let (mut mask, body) = tmp_zero_encryption.get_mut_mask_and_body();
        random_generator
            .fill_slice_with_random_uniform_custom_mod(mask.as_mut(), ciphertext_modulus);
        if ciphertext_modulus.is_non_native_power_of_two() {
            slice_wrapping_scalar_mul_assign(
                mask.as_mut(),
                ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            );
        }
        *body.data = *public_encryption_of_zero_body.data;

        // chosen is 1 if chosen, 0 otherwise, so use a multiplication to avoid having a branch
        // depending on a value that's supposed to remain secret
        lwe_ciphertext_cleartext_mul_assign(&mut tmp_zero_encryption, Cleartext(chosen));
        lwe_ciphertext_add_assign(output, &tmp_zero_encryption);
    }

    lwe_ciphertext_plaintext_add_assign(output, encoded);
}

/// Convenience function to share the core logic of the seeded LWE encryption between all functions
/// needing it.
pub fn encrypt_seeded_lwe_ciphertext_list_with_existing_generator<
    Scalar,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LweSecretKey {:?} and output \
        SeededLweCiphertextList {:?}.",
        lwe_secret_key.lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
    );
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let mut output_mask = LweMask::from_container(
        vec![Scalar::ZERO; output.lwe_size().to_lwe_dimension().0],
        output.ciphertext_modulus(),
    );

    let gen_iter = generator
        .fork_lwe_list_to_lwe::<Scalar>(output.lwe_ciphertext_count(), output.lwe_size())
        .unwrap();

    for ((mut output_body, plaintext), mut loop_generator) in
        output.iter_mut().zip(encoded.iter()).zip(gen_iter)
    {
        fill_lwe_mask_and_body_for_encryption(
            lwe_secret_key,
            &mut output_mask,
            &mut output_body,
            plaintext.into(),
            noise_parameters,
            &mut loop_generator,
        );
    }
}

/// Encrypt a [`PlaintextList`] in a
/// [`compressed/seeded LWE ciphertext list`](`SeededLweCiphertextList`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(lwe_ciphertext_count.0));
///
/// // Create a new SeededLweCiphertextList
/// let mut lwe_list = SeededLweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// encrypt_seeded_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_list,
///     &plaintext_list,
///     lwe_modular_std_dev,
///     seeder,
/// );
///
/// let lwe_list = lwe_list.decompress_into_lwe_ciphertext_list();
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(lwe_list.lwe_ciphertext_count().0));
/// decrypt_lwe_ciphertext_list(&lwe_secret_key, &lwe_list, &mut output_plaintext_list);
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
pub fn encrypt_seeded_lwe_ciphertext_list<Scalar, KeyCont, OutputCont, InputCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_seeded_lwe_ciphertext_list_with_existing_generator(
        lwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut generator,
    );
}

/// Convenience function to share the core logic of the seeded LWE encryption between all functions
/// needing it.
pub fn par_encrypt_seeded_lwe_ciphertext_list_with_existing_generator<
    Scalar,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar> + Sync,
    InputCont: Container<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LweSecretKey {:?} and output \
        SeededLweCiphertextList {:?}.",
        lwe_secret_key.lwe_dimension(),
        output.lwe_size().to_lwe_dimension(),
    );
    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .par_fork_lwe_list_to_lwe::<Scalar>(output.lwe_ciphertext_count(), output.lwe_size())
        .unwrap();

    let lwe_dimension = output.lwe_size().to_lwe_dimension();
    let ciphertext_modulus = output.ciphertext_modulus();

    output
        .par_iter_mut()
        .zip(encoded.par_iter())
        .zip(gen_iter)
        .for_each(|((mut output_body, plaintext), mut loop_generator)| {
            let mut output_mask =
                LweMask::from_container(vec![Scalar::ZERO; lwe_dimension.0], ciphertext_modulus);
            fill_lwe_mask_and_body_for_encryption(
                lwe_secret_key,
                &mut output_mask,
                &mut output_body,
                plaintext.into(),
                noise_parameters,
                &mut loop_generator,
            );
        });
}

/// Parallel variant of [`encrypt_seeded_lwe_ciphertext_list`].
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(lwe_ciphertext_count.0));
///
/// // Create a new SeededLweCiphertextList
/// let mut lwe_list = SeededLweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// par_encrypt_seeded_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_list,
///     &plaintext_list,
///     lwe_modular_std_dev,
///     seeder,
/// );
///
/// let lwe_list = lwe_list.decompress_into_lwe_ciphertext_list();
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(lwe_list.lwe_ciphertext_count().0));
/// decrypt_lwe_ciphertext_list(&lwe_secret_key, &lwe_list, &mut output_plaintext_list);
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
pub fn par_encrypt_seeded_lwe_ciphertext_list<Scalar, KeyCont, OutputCont, InputCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar> + Sync,
    InputCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    par_encrypt_seeded_lwe_ciphertext_list_with_existing_generator(
        lwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut generator,
    );
}

/// Convenience function to share the core logic of the seeded LWE encryption between all functions
/// needing it.
pub fn encrypt_seeded_lwe_ciphertext_with_existing_generator<Scalar, KeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertext<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut mask = LweMask::from_container(
        vec![Scalar::ZERO; lwe_secret_key.lwe_dimension().0],
        output.ciphertext_modulus(),
    );

    fill_lwe_mask_and_body_for_encryption(
        lwe_secret_key,
        &mut mask,
        &mut output.get_mut_body(),
        encoded,
        noise_parameters,
        generator,
    );
}

/// Encrypt an input plaintext in an output [`seeded LWE ciphertext`](`SeededLweCiphertext`).
///
/// See the [`LWE ciphertext formal definition`](`LweCiphertext#lwe-encryption`) for the definition
/// of the encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new SeededLweCiphertext
/// let mut lwe = SeededLweCiphertext::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     seeder.seed().into(),
///     ciphertext_modulus,
/// );
///
/// encrypt_seeded_lwe_ciphertext(
///     &lwe_secret_key,
///     &mut lwe,
///     plaintext,
///     lwe_modular_std_dev,
///     seeder,
/// );
///
/// let lwe = lwe.decompress_into_lwe_ciphertext();
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn encrypt_seeded_lwe_ciphertext<Scalar, KeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertext<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_seeded_lwe_ciphertext_with_existing_generator(
        lwe_secret_key,
        output,
        encoded,
        noise_parameters,
        &mut encryption_generator,
    );
}

/// Allocate a new [`seeded LWE ciphertext`](`SeededLweCiphertext`) and encrypt an input plaintext
/// in it.
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new SeededLweCiphertext
/// let mut lwe = allocate_and_encrypt_new_seeded_lwe_ciphertext(
///     &lwe_secret_key,
///     plaintext,
///     lwe_modular_std_dev,
///     ciphertext_modulus,
///     seeder,
/// );
///
/// let lwe = lwe.decompress_into_lwe_ciphertext();
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn allocate_and_encrypt_new_seeded_lwe_ciphertext<Scalar, KeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweCiphertext<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut seeded_ct = SeededLweCiphertext::new(
        Scalar::ZERO,
        lwe_secret_key.lwe_dimension().to_lwe_size(),
        noise_seeder.seed().into(),
        ciphertext_modulus,
    );

    encrypt_seeded_lwe_ciphertext(
        lwe_secret_key,
        &mut seeded_ct,
        encoded,
        noise_parameters,
        noise_seeder,
    );

    seeded_ct
}

/// Encrypt an input plaintext in an output [`LWE ciphertext`](`LweCiphertext`) using an
/// [`LWE compact public key`](`LweCompactPublicKey`). The ciphertext can be decrypted using the
/// [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
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
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// encrypt_lwe_ciphertext_with_compact_public_key(
///     &lwe_compact_public_key,
///     &mut lwe,
///     plaintext,
///     glwe_modular_std_dev,
///     glwe_modular_std_dev,
///     &mut secret_generator,
///     &mut encryption_generator,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
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
pub fn encrypt_lwe_ciphertext_with_compact_public_key<
    Scalar,
    KeyCont,
    OutputCont,
    SecretGen,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    mask_noise_parameters: impl DispersionParameter,
    body_noise_parameters: impl DispersionParameter,
    secret_generator: &mut SecretRandomGenerator<SecretGen>,
    encryption_generator: &mut EncryptionRandomGenerator<EncryptionGen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    SecretGen: ByteRandomGenerator,
    EncryptionGen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_compact_public_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_compact_public_key.lwe_dimension()
    );

    assert!(
        lwe_compact_public_key.ciphertext_modulus() == output.ciphertext_modulus(),
        "Mismatch between CiphertextModulus of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.ciphertext_modulus(),
        lwe_compact_public_key.ciphertext_modulus()
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let mut binary_random_vector = vec![Scalar::ZERO; lwe_compact_public_key.lwe_dimension().0];

    secret_generator.fill_slice_with_random_uniform_binary(&mut binary_random_vector);

    let (mut ct_mask, ct_body) = output.get_mut_mask_and_body();
    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();

    slice_semi_reverse_negacyclic_convolution(
        ct_mask.as_mut(),
        pk_mask.as_ref(),
        &binary_random_vector,
    );

    // Noise from Chi_1 for the mask part of the encryption
    encryption_generator.unsigned_torus_slice_wrapping_add_random_noise_assign(
        ct_mask.as_mut(),
        mask_noise_parameters,
    );

    *ct_body.data = slice_wrapping_dot_product(pk_body.as_ref(), &binary_random_vector);
    // Noise from Chi_2 for the body part of the encryption
    *ct_body.data =
        (*ct_body.data).wrapping_add(encryption_generator.random_noise(body_noise_parameters));
    *ct_body.data = (*ct_body.data).wrapping_add(encoded.0);
}

/// Encrypt an input plaintext list in an output [`LWE compact ciphertext
/// list`](`LweCompactCiphertextList`) using an [`LWE compact public key`](`LweCompactPublicKey`).
/// The expanded ciphertext list can be decrypted using the [`LWE secret key`](`LweSecretKey`) that
/// was used to generate the public key.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_ciphertext_count = LweCiphertextCount(lwe_dimension.0 * 4);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut input_plaintext_list = PlaintextList::new(0u64, PlaintextCount(lwe_ciphertext_count.0));
/// input_plaintext_list
///     .iter_mut()
///     .enumerate()
///     .for_each(|(idx, x)| {
///         *x.0 = (idx as u64 % 16) << 60;
///     });
///
/// // Create a new LweCompactCiphertextList
/// let mut output_compact_ct_list = LweCompactCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
///     &lwe_compact_public_key,
///     &mut output_compact_ct_list,
///     &input_plaintext_list,
///     glwe_modular_std_dev,
///     glwe_modular_std_dev,
///     &mut secret_generator,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = input_plaintext_list.clone();
/// output_plaintext_list.as_mut().fill(0u64);
///
/// let lwe_ciphertext_list = output_compact_ct_list.expand_into_lwe_ciphertext_list();
///
/// decrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &lwe_ciphertext_list,
///     &mut output_plaintext_list,
/// );
///
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round the plaintexts
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// // Check we recovered the original messages
/// assert_eq!(input_plaintext_list, output_plaintext_list);
/// ```
pub fn encrypt_lwe_compact_ciphertext_list_with_compact_public_key<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
    SecretGen,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    mask_noise_parameters: impl DispersionParameter,
    body_noise_parameters: impl DispersionParameter,
    secret_generator: &mut SecretRandomGenerator<SecretGen>,
    encryption_generator: &mut EncryptionRandomGenerator<EncryptionGen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    SecretGen: ByteRandomGenerator,
    EncryptionGen: ByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_compact_public_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_compact_public_key.lwe_dimension()
    );

    assert!(
        lwe_compact_public_key.ciphertext_modulus() == output.ciphertext_modulus(),
        "Mismatch between CiphertextModulus of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.ciphertext_modulus(),
        lwe_compact_public_key.ciphertext_modulus()
    );

    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between LweCiphertextCount of output ciphertext and \
        PlaintextCount of input list. Got {:?} in output, and {:?} in input plaintext list.",
        output.lwe_ciphertext_count(),
        encoded.plaintext_count()
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let (mut output_mask_list, mut output_body_list) = output.get_mut_mask_and_body_list();
    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();

    let lwe_mask_count = output_mask_list.lwe_mask_count();
    let lwe_dimension = output_mask_list.lwe_dimension();

    let mut binary_random_vector = vec![Scalar::ZERO; output_mask_list.lwe_mask_list_size()];
    secret_generator.fill_slice_with_random_uniform_binary(&mut binary_random_vector);

    let max_ciphertext_per_bin = lwe_dimension.0;

    let gen_iter = encryption_generator
        .fork_lwe_compact_ciphertext_list_to_bin::<Scalar>(lwe_mask_count, lwe_dimension)
        .expect("Failed to split generator into lwe compact ciphertext bins");

    // Loop over the ciphertext "bins"
    output_mask_list
        .iter_mut()
        .zip(
            output_body_list
                .chunks_mut(max_ciphertext_per_bin)
                .zip(encoded.chunks(max_ciphertext_per_bin))
                .zip(binary_random_vector.chunks(max_ciphertext_per_bin))
                .zip(gen_iter),
        )
        .for_each(
            |(
                mut output_mask,
                (
                    ((mut output_body_chunk, input_plaintext_chunk), binary_random_slice),
                    mut loop_generator,
                ),
            )| {
                // output_body_chunk may not be able to fit the full convolution result so we create
                // a temp buffer to compute the full convolution
                let mut pk_body_convolved = vec![Scalar::ZERO; lwe_dimension.0];

                slice_semi_reverse_negacyclic_convolution(
                    output_mask.as_mut(),
                    pk_mask.as_ref(),
                    binary_random_slice,
                );

                // Fill the temp buffer with b convolved with r
                slice_semi_reverse_negacyclic_convolution(
                    pk_body_convolved.as_mut_slice(),
                    pk_body.as_ref(),
                    binary_random_slice,
                );

                // Noise from Chi_1 for the mask part of the encryption
                loop_generator.unsigned_torus_slice_wrapping_add_random_noise_assign(
                    output_mask.as_mut(),
                    mask_noise_parameters,
                );

                // Fill the body chunk afterwards manually as it most likely will be smaller than
                // the full convolution result. b convolved r + Delta * m + e2
                // taking noise from Chi_2 for the body part of the encryption
                output_body_chunk
                    .iter_mut()
                    .zip(pk_body_convolved.iter().zip(input_plaintext_chunk.iter()))
                    .for_each(|(dst, (&src, plaintext))| {
                        *dst.data = src
                            .wrapping_add(loop_generator.random_noise(body_noise_parameters))
                            .wrapping_add(*plaintext.0);
                    });
            },
        );
}

/// Parallel variant of [`encrypt_lwe_compact_ciphertext_list_with_compact_public_key`]. Encrypt an
/// input plaintext list in an output [`LWE compact ciphertext list`](`LweCompactCiphertextList`)
/// using an [`LWE compact public key`](`LweCompactPublicKey`). The expanded ciphertext list can be
/// decrypted using the [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_ciphertext_count = LweCiphertextCount(lwe_dimension.0 * 4);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_modular_std_dev,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let mut input_plaintext_list = PlaintextList::new(0u64, PlaintextCount(lwe_ciphertext_count.0));
/// input_plaintext_list
///     .iter_mut()
///     .enumerate()
///     .for_each(|(idx, x)| {
///         *x.0 = (idx as u64 % 16) << 60;
///     });
///
/// // Create a new LweCompactCiphertextList
/// let mut output_compact_ct_list = LweCompactCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
///
/// par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
///     &lwe_compact_public_key,
///     &mut output_compact_ct_list,
///     &input_plaintext_list,
///     glwe_modular_std_dev,
///     glwe_modular_std_dev,
///     &mut secret_generator,
///     &mut encryption_generator,
/// );
///
/// let mut output_plaintext_list = input_plaintext_list.clone();
/// output_plaintext_list.as_mut().fill(0u64);
///
/// let lwe_ciphertext_list = output_compact_ct_list.par_expand_into_lwe_ciphertext_list();
///
/// decrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &lwe_ciphertext_list,
///     &mut output_plaintext_list,
/// );
///
/// let signed_decomposer =
///     SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// // Round the plaintexts
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));
///
/// // Check we recovered the original messages
/// assert_eq!(input_plaintext_list, output_plaintext_list);
/// ```
pub fn par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
    SecretGen,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    mask_noise_parameters: impl DispersionParameter + Sync,
    body_noise_parameters: impl DispersionParameter + Sync,
    secret_generator: &mut SecretRandomGenerator<SecretGen>,
    encryption_generator: &mut EncryptionRandomGenerator<EncryptionGen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    SecretGen: ByteRandomGenerator,
    EncryptionGen: ParallelByteRandomGenerator,
{
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_compact_public_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_compact_public_key.lwe_dimension()
    );

    assert!(
        lwe_compact_public_key.ciphertext_modulus() == output.ciphertext_modulus(),
        "Mismatch between CiphertextModulus of output ciphertext and input public key. \
    Got {:?} in output, and {:?} in public key.",
        output.ciphertext_modulus(),
        lwe_compact_public_key.ciphertext_modulus()
    );

    assert!(
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between LweCiphertextCount of output ciphertext and \
        PlaintextCount of input list. Got {:?} in output, and {:?} in input plaintext list.",
        output.lwe_ciphertext_count(),
        encoded.plaintext_count()
    );

    assert!(
        output.ciphertext_modulus().is_native_modulus(),
        "This operation only supports native moduli"
    );

    let (mut output_mask_list, mut output_body_list) = output.get_mut_mask_and_body_list();
    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();

    let lwe_mask_count = output_mask_list.lwe_mask_count();
    let lwe_dimension = output_mask_list.lwe_dimension();

    let mut binary_random_vector = vec![Scalar::ZERO; output_mask_list.lwe_mask_list_size()];
    secret_generator.fill_slice_with_random_uniform_binary(&mut binary_random_vector);

    let max_ciphertext_per_bin = lwe_dimension.0;

    let gen_iter = encryption_generator
        .par_fork_lwe_compact_ciphertext_list_to_bin::<Scalar>(lwe_mask_count, lwe_dimension)
        .expect("Failed to split generator into lwe compact ciphertext bins");

    // Loop over the ciphertext "bins"
    output_mask_list
        .par_iter_mut()
        .zip(
            output_body_list
                .par_chunks_mut(max_ciphertext_per_bin)
                .zip(encoded.par_chunks(max_ciphertext_per_bin))
                .zip(binary_random_vector.par_chunks(max_ciphertext_per_bin))
                .zip(gen_iter),
        )
        .for_each(
            |(
                mut output_mask,
                (
                    ((mut output_body_chunk, input_plaintext_chunk), binary_random_slice),
                    mut loop_generator,
                ),
            )| {
                // output_body_chunk may not be able to fit the full convolution result so we create
                // a temp buffer to compute the full convolution
                let mut pk_body_convolved = vec![Scalar::ZERO; lwe_dimension.0];

                rayon::join(
                    || {
                        slice_semi_reverse_negacyclic_convolution(
                            output_mask.as_mut(),
                            pk_mask.as_ref(),
                            binary_random_slice,
                        );
                    },
                    || {
                        // Fill the temp buffer with b convolved with r
                        slice_semi_reverse_negacyclic_convolution(
                            pk_body_convolved.as_mut_slice(),
                            pk_body.as_ref(),
                            binary_random_slice,
                        );
                    },
                );

                // Noise from Chi_1 for the mask part of the encryption
                loop_generator.unsigned_torus_slice_wrapping_add_random_noise_assign(
                    output_mask.as_mut(),
                    mask_noise_parameters,
                );

                // Fill the body chunk afterwards manually as it most likely will be smaller than
                // the full convolution result. b convolved r + Delta * m + e2
                // taking noise from Chi_2 for the body part of the encryption
                output_body_chunk
                    .iter_mut()
                    .zip(pk_body_convolved.iter().zip(input_plaintext_chunk.iter()))
                    .for_each(|(dst, (&src, plaintext))| {
                        *dst.data = src
                            .wrapping_add(loop_generator.random_noise(body_noise_parameters))
                            .wrapping_add(*plaintext.0);
                    });
            },
        );
}

#[cfg(test)]
mod test {
    use crate::core_crypto::commons::test_tools;
    use crate::core_crypto::prelude::*;

    use crate::core_crypto::commons::generators::{
        DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
    };
    use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;

    #[test]
    fn test_compact_public_key_encryption() {
        use rand::Rng;

        let lwe_dimension = LweDimension(2048);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut secret_random_generator = test_tools::new_secret_random_generator();
        let mut encryption_random_generator = test_tools::new_encryption_random_generator();

        let mut thread_rng = rand::thread_rng();

        for _ in 0..10_000 {
            let lwe_sk =
                LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

            let mut compact_lwe_pk =
                LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

            generate_lwe_compact_public_key(
                &lwe_sk,
                &mut compact_lwe_pk,
                glwe_modular_std_dev,
                &mut encryption_random_generator,
            );

            let msg: u64 = thread_rng.gen();
            let msg = msg % 16;

            let plaintext = Plaintext(msg << 60);

            let mut output_ct = LweCiphertext::new(
                0u64,
                lwe_dimension.to_lwe_size(),
                CiphertextModulus::new_native(),
            );

            encrypt_lwe_ciphertext_with_compact_public_key(
                &compact_lwe_pk,
                &mut output_ct,
                plaintext,
                glwe_modular_std_dev,
                glwe_modular_std_dev,
                &mut secret_random_generator,
                &mut encryption_random_generator,
            );

            let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_sk, &output_ct);

            let signed_decomposer =
                SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

            let cleartext = signed_decomposer.closest_representable(decrypted_plaintext.0) >> 60;

            assert_eq!(cleartext, msg);
        }
    }

    #[test]
    fn test_par_compact_lwe_list_public_key_encryption_equivalence() {
        use rand::Rng;

        let lwe_dimension = LweDimension(2048);
        let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut thread_rng = rand::thread_rng();

        for _ in 0..100 {
            // We'll encrypt between 1 and 4 * lwe_dimension ciphertexts
            let ct_count: usize = thread_rng.gen();
            let ct_count = ct_count % (lwe_dimension.0 * 4) + 1;
            let lwe_ciphertext_count = LweCiphertextCount(ct_count);

            println!("{lwe_dimension:?} {ct_count:?}");

            let seed = test_tools::random_seed();
            let mut input_plaintext_list =
                PlaintextList::new(0u64, PlaintextCount(lwe_ciphertext_count.0));
            input_plaintext_list.iter_mut().for_each(|x| {
                let msg: u64 = thread_rng.gen();
                *x.0 = (msg % 16) << 60;
            });

            let par_lwe_ct_list = {
                let mut deterministic_seeder =
                    DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
                let mut secret_random_generator =
                    SecretRandomGenerator::<ActivatedRandomGenerator>::new(
                        deterministic_seeder.seed(),
                    );
                let mut encryption_random_generator =
                    EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                        deterministic_seeder.seed(),
                        &mut deterministic_seeder,
                    );

                let lwe_sk =
                    LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

                let mut compact_lwe_pk =
                    LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

                generate_lwe_compact_public_key(
                    &lwe_sk,
                    &mut compact_lwe_pk,
                    glwe_modular_std_dev,
                    &mut encryption_random_generator,
                );

                let mut output_compact_ct_list = LweCompactCiphertextList::new(
                    0u64,
                    lwe_dimension.to_lwe_size(),
                    lwe_ciphertext_count,
                    ciphertext_modulus,
                );

                par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
                    &compact_lwe_pk,
                    &mut output_compact_ct_list,
                    &input_plaintext_list,
                    glwe_modular_std_dev,
                    glwe_modular_std_dev,
                    &mut secret_random_generator,
                    &mut encryption_random_generator,
                );

                let mut output_plaintext_list = input_plaintext_list.clone();
                output_plaintext_list.as_mut().fill(0u64);

                let lwe_ciphertext_list =
                    output_compact_ct_list.par_expand_into_lwe_ciphertext_list();

                decrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &lwe_ciphertext_list,
                    &mut output_plaintext_list,
                );

                let signed_decomposer =
                    SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

                output_plaintext_list
                    .iter_mut()
                    .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

                assert_eq!(input_plaintext_list, output_plaintext_list);

                lwe_ciphertext_list
            };

            let ser_lwe_ct_list = {
                let mut deterministic_seeder =
                    DeterministicSeeder::<ActivatedRandomGenerator>::new(seed);
                let mut secret_random_generator =
                    SecretRandomGenerator::<ActivatedRandomGenerator>::new(
                        deterministic_seeder.seed(),
                    );
                let mut encryption_random_generator =
                    EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                        deterministic_seeder.seed(),
                        &mut deterministic_seeder,
                    );

                let lwe_sk =
                    LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

                let mut compact_lwe_pk =
                    LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

                generate_lwe_compact_public_key(
                    &lwe_sk,
                    &mut compact_lwe_pk,
                    glwe_modular_std_dev,
                    &mut encryption_random_generator,
                );

                let mut output_compact_ct_list = LweCompactCiphertextList::new(
                    0u64,
                    lwe_dimension.to_lwe_size(),
                    lwe_ciphertext_count,
                    ciphertext_modulus,
                );

                encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
                    &compact_lwe_pk,
                    &mut output_compact_ct_list,
                    &input_plaintext_list,
                    glwe_modular_std_dev,
                    glwe_modular_std_dev,
                    &mut secret_random_generator,
                    &mut encryption_random_generator,
                );

                let mut output_plaintext_list = input_plaintext_list.clone();
                output_plaintext_list.as_mut().fill(0u64);

                let lwe_ciphertext_list = output_compact_ct_list.expand_into_lwe_ciphertext_list();

                decrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &lwe_ciphertext_list,
                    &mut output_plaintext_list,
                );

                let signed_decomposer =
                    SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

                output_plaintext_list
                    .iter_mut()
                    .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

                assert_eq!(input_plaintext_list, output_plaintext_list);

                lwe_ciphertext_list
            };

            assert_eq!(ser_lwe_ct_list, par_lwe_ct_list);
        }
    }
}
