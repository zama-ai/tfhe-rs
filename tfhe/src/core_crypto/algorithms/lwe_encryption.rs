//! Module containing primitives pertaining to [`LWE ciphertext encryption and
//! decryption`](`LweCiphertext#lwe-encryption`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::generators::{
    EncryptionRandomGenerator, NoiseRandomGenerator, SecretRandomGenerator,
};
#[cfg(feature = "zk-pok")]
use crate::core_crypto::commons::math::random::BoundedDistribution;
use crate::core_crypto::commons::math::random::{
    DefaultRandomGenerator, Distribution, RandomGenerable, RandomGenerator, Uniform, UniformBinary,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Convenience function to share the core logic of the LWE encryption between all functions needing
/// it.
pub fn fill_lwe_mask_and_body_for_encryption<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
            noise_distribution,
            generator,
        );
    } else {
        fill_lwe_mask_and_body_for_encryption_other_mod(
            lwe_secret_key,
            output_mask,
            output_body,
            encoded,
            noise_distribution,
            generator,
        );
    }
}

pub fn fill_lwe_mask_and_body_for_encryption_native_mod_compatible<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    // generate an error from the given noise_distribution
    let noise =
        generator.random_noise_from_distribution_custom_mod(noise_distribution, ciphertext_modulus);
    // compute the multisum between the secret key and the mask
    let mask_key_dot_product =
        slice_wrapping_dot_product(output_mask.as_ref(), lwe_secret_key.as_ref());

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
    }
}

pub fn fill_lwe_mask_and_body_for_encryption_other_mod<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output_mask: &mut LweMask<OutputCont>,
    output_body: &mut LweBodyRefMut<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    // generate an error from the given noise_distribution
    let noise =
        generator.random_noise_from_distribution_custom_mod(noise_distribution, ciphertext_modulus);

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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
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
///     lwe_noise_distribution,
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
pub fn encrypt_lwe_ciphertext<Scalar, NoiseDistribution, KeyCont, OutputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
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
        noise_distribution,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
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
///     lwe_noise_distribution,
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
pub fn allocate_and_encrypt_new_lwe_ciphertext<Scalar, NoiseDistribution, KeyCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
        noise_distribution,
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
/// ```rust
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
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
/// ```rust
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
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let lwe = allocate_and_trivially_encrypt_new_lwe_ciphertext(
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
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
///     lwe_noise_distribution,
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_lwe_ciphertext_list<Scalar, NoiseDistribution, KeyCont, OutputCont, InputCont, Gen>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
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
        output.lwe_ciphertext_count().0 == encoded.plaintext_count().0,
        "Mismatch between number of output ciphertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    let gen_iter = generator
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((encoded_plaintext_ref, mut ciphertext), mut loop_generator) in
        encoded.iter().zip(output.iter_mut()).zip(gen_iter)
    {
        encrypt_lwe_ciphertext(
            lwe_secret_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            noise_distribution,
            &mut loop_generator,
        );
    }
}

/// Parallel variant of [`encrypt_lwe_ciphertext_list`].
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
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
///     lwe_noise_distribution,
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn par_encrypt_lwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut LweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
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
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
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
                noise_distribution,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let zero_encryption_count =
///     LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
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
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_public_key = allocate_and_generate_new_lwe_public_key(
///     &lwe_secret_key,
///     zero_encryption_count,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let zero_encryption_count =
///     LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_public_key = allocate_and_generate_new_seeded_lwe_public_key(
///     &lwe_secret_key,
///     zero_encryption_count,
///     lwe_noise_distribution,
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
    encrypt_lwe_ciphertext_iterator_with_seeded_public_key(
        lwe_public_key,
        std::iter::once(output.as_mut_view()),
        std::iter::once(encoded),
        generator,
    );
}

/// Encrypt several input plaintext in output [`LWE ciphertexts`](`LweCiphertext`) using a
/// [`seeded LWE public key`](`SeededLwePublicKey`). The ciphertext can be decrypted using the
/// [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let zero_encryption_count =
///     LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_public_key = allocate_and_generate_new_seeded_lwe_public_key(
///     &lwe_secret_key,
///     zero_encryption_count,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     seeder,
/// );
///
/// // Create the plaintext
/// let msg_1 = 3u64;
/// let plaintext_1 = Plaintext(msg_1 << 60);
/// let msg_2 = 2u64;
/// let plaintext_2 = Plaintext(msg_2 << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe_1 = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
/// let mut lwe_2 = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// encrypt_lwe_ciphertext_iterator_with_seeded_public_key(
///     &lwe_public_key,
///     [lwe_1.as_mut_view(), lwe_2.as_mut_view()],
///     [plaintext_1, plaintext_2],
///     &mut secret_generator,
/// );
///
/// let decrypted_plaintext_1 = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_1);
/// let decrypted_plaintext_2 = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe_2);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let rounded_1 = decomposer.closest_representable(decrypted_plaintext_1.0);
/// let rounded_2 = decomposer.closest_representable(decrypted_plaintext_2.0);
///
/// // Remove the encoding
/// let cleartext_1 = rounded_1 >> 60;
/// let cleartext_2 = rounded_2 >> 60;
///
/// // Check we recovered the original message
/// assert_eq!(cleartext_1, msg_1);
/// assert_eq!(cleartext_2, msg_2);
/// ```
pub fn encrypt_lwe_ciphertext_iterator_with_seeded_public_key<Scalar, KeyCont, OutputCont, Gen>(
    lwe_public_key: &SeededLwePublicKey<KeyCont>,
    output: impl IntoIterator<Item = LweCiphertext<OutputCont>>,
    encoded: impl IntoIterator<Item = Plaintext<Scalar>>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut output: Vec<_> = output.into_iter().collect();
    let output = output.as_mut_slice();
    if output.is_empty() {
        return;
    }

    let encoded: Vec<_> = encoded.into_iter().collect();
    assert_eq!(
        output.len(),
        encoded.len(),
        "Mismatched Plaintext Iterator and LweCiphertext Iterator lengths."
    );

    let output_ciphertext_modulus = output[0].ciphertext_modulus();

    assert!(
        output
            .iter()
            .all(|lwe| lwe.ciphertext_modulus() == output_ciphertext_modulus),
        "The input LweCiphertext Iterator must have homogeneous CiphertextModulus"
    );

    assert_eq!(
        lwe_public_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched moduli between lwe_public_key ({:?}) and output ({:?})",
        lwe_public_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );

    let output_lwe_size = output[0].lwe_size();

    assert!(
        output.iter().all(|lwe| lwe.lwe_size() == output_lwe_size),
        "The input LweCiphertext Iterator must have homogeneous LweSize"
    );

    assert!(
        output_lwe_size.to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output_lwe_size.to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    for output_ct in output.iter_mut() {
        output_ct.as_mut().fill(Scalar::ZERO);
    }

    let mut tmp_zero_encryption = LweCiphertext::new(
        Scalar::ZERO,
        lwe_public_key.lwe_size(),
        output_ciphertext_modulus,
    );

    let mut random_generator =
        RandomGenerator::<DefaultRandomGenerator>::new(lwe_public_key.compression_seed().seed);

    // Add the public encryption of zeros to get the zero encryption
    for public_encryption_of_zero_body in lwe_public_key.iter() {
        let (mut mask, body) = tmp_zero_encryption.get_mut_mask_and_body();
        random_generator
            .fill_slice_with_random_uniform_custom_mod(mask.as_mut(), output_ciphertext_modulus);
        if output_ciphertext_modulus.is_non_native_power_of_two() {
            slice_wrapping_scalar_mul_assign(
                mask.as_mut(),
                output_ciphertext_modulus.get_power_of_two_scaling_to_native_torus(),
            );
        }
        *body.data = *public_encryption_of_zero_body.data;

        for output_ct in output.iter_mut() {
            let chosen = generator.generate_random_uniform_binary();
            // chosen is 1 if chosen, 0 otherwise, so use a multiplication to avoid having a branch
            // depending on a value that's supposed to remain secret
            slice_wrapping_add_scalar_mul_assign(
                output_ct.as_mut(),
                tmp_zero_encryption.as_ref(),
                chosen,
            );
        }
    }

    for (output_ct, plaintext) in output.iter_mut().zip(encoded.into_iter()) {
        lwe_ciphertext_plaintext_add_assign(output_ct, plaintext);
    }
}

/// Convenience function to share the core logic of the seeded LWE encryption between all functions
/// needing it.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((mut output_body, plaintext), mut loop_generator) in
        output.iter_mut().zip(encoded.iter()).zip(gen_iter)
    {
        fill_lwe_mask_and_body_for_encryption(
            lwe_secret_key,
            &mut output_mask,
            &mut output_body,
            plaintext.into(),
            noise_distribution,
            &mut loop_generator,
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
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
///     lwe_noise_distribution,
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn encrypt_seeded_lwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
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
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
        lwe_secret_key,
        output,
        encoded,
        noise_distribution,
        &mut generator,
    );
}

/// Convenience function to share the core logic of the seeded LWE encryption between all functions
/// needing it.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn par_encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
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
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
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
                noise_distribution,
                &mut loop_generator,
            );
        });
}

/// Parallel variant of [`encrypt_seeded_lwe_ciphertext_list`].
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_ciphertext_count = LweCiphertextCount(2);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
///     lwe_noise_distribution,
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
/// cleartext_list.iter_mut().for_each(|elt| *elt >>= 60);
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// cleartext_list.iter().for_each(|&elt| assert_eq!(elt, msg));
/// ```
pub fn par_encrypt_seeded_lwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar> + Sync,
    InputCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    par_encrypt_seeded_lwe_ciphertext_list_with_pre_seeded_generator(
        lwe_secret_key,
        output,
        encoded,
        noise_distribution,
        &mut generator,
    );
}

/// Convenience function to share the core logic of the seeded LWE encryption between all functions
/// needing it.
///
/// WARNING: this assumes the caller manages the coherency of calls to the generator to make sure
/// the right bytes are generated at the right time.
pub fn encrypt_seeded_lwe_ciphertext_with_pre_seeded_generator<
    Scalar,
    NoiseDistribution,
    KeyCont,
    Gen,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertext<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
        noise_distribution,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
///     lwe_noise_distribution,
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
pub fn encrypt_seeded_lwe_ciphertext<Scalar, NoiseDistribution, KeyCont, NoiseSeeder>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    output: &mut SeededLweCiphertext<Scalar>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    noise_seeder: &mut NoiseSeeder,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    // Maybe Sized allows to pass Box<dyn Seeder>.
    NoiseSeeder: Seeder + ?Sized,
{
    let mut encryption_generator = EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
        output.compression_seed().seed,
        noise_seeder,
    );

    encrypt_seeded_lwe_ciphertext_with_pre_seeded_generator(
        lwe_secret_key,
        output,
        encoded,
        noise_distribution,
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
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
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
/// let lwe = allocate_and_encrypt_new_seeded_lwe_ciphertext(
///     &lwe_secret_key,
///     plaintext,
///     lwe_noise_distribution,
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
pub fn allocate_and_encrypt_new_seeded_lwe_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    NoiseSeeder,
>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    encoded: Plaintext<Scalar>,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    noise_seeder: &mut NoiseSeeder,
) -> SeededLweCiphertext<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
        noise_distribution,
        noise_seeder,
    );

    seeded_ct
}

/// This struct stores random vectors that were generated during
/// the encryption of a lwe ciphertext or lwe compact ciphertext list.
///
/// These are needed by the zero-knowledge proof
struct CompactPublicKeyRandomVectors<Scalar> {
    // This is 'r'
    #[cfg_attr(not(feature = "zk-pok"), allow(unused))]
    binary_random_vector: Vec<Scalar>,
    // This is e1
    #[cfg_attr(not(feature = "zk-pok"), allow(unused))]
    mask_noise: Vec<Scalar>,
    // This is e2
    #[cfg_attr(not(feature = "zk-pok"), allow(unused))]
    body_noise: Vec<Scalar>,
}

#[cfg(feature = "zk-pok")]
fn verify_zero_knowledge_preconditions<Scalar, KeyCont, MaskDistribution, BodyDistribution>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    ciphertext_count: LweCiphertextCount,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: BodyDistribution,
    crs: &CompactPkeCrs,
) -> crate::Result<()>
where
    Scalar: UnsignedInteger + CastFrom<u64>,
    Scalar::Signed: CastFrom<u64>,
    i64: CastFrom<Scalar>,
    u64: CastFrom<Scalar> + CastInto<Scalar::Signed>,
    MaskDistribution: BoundedDistribution<Scalar::Signed>,
    BodyDistribution: BoundedDistribution<Scalar::Signed>,
    KeyCont: Container<Element = Scalar>,
{
    let exclusive_max = crs.exclusive_max_noise();

    if mask_noise_distribution.contains(exclusive_max.cast_into()) {
        // The proof expect noise bound between [-b, b) (aka -b..b)
        return Err(
            "The given random distribution would create random values out \
            of the expected bounds of given to the CRS"
                .into(),
        );
    }
    if body_noise_distribution.contains(exclusive_max.cast_into()) {
        // The proof expect noise bound between [-b, b) (aka -b..b)
        return Err(
            "The given random distribution would create random values out \
            of the expected bounds of given to the CRS"
                .into(),
        );
    }

    if !ciphertext_modulus.is_native_modulus() {
        return Err("This operation only supports native modulus".into());
    }

    if Scalar::BITS > 64 {
        return Err("Zero knowledge proof do not support moduli greater than 2**64".into());
    }

    if ciphertext_modulus != crs.ciphertext_modulus() {
        return Err("Mismatched modulus between CRS and ciphertexts".into());
    }

    if ciphertext_count > crs.max_num_messages() {
        return Err(format!(
            "CRS allows at most {} ciphertexts to be proven at once, {} contained in the list",
            crs.max_num_messages().0,
            ciphertext_count.0
        )
        .into());
    }

    if lwe_compact_public_key.lwe_dimension() > crs.lwe_dimension() {
        return Err(format!(
            "CRS allows a LweDimension of at most {}, current dimension: {}",
            crs.lwe_dimension().0,
            lwe_compact_public_key.lwe_dimension().0
        )
        .into());
    }

    // 2**64 /delta == ((2**63) / delta) *2
    let plaintext_modulus = ((1u64 << (u64::BITS - 1) as usize) / u64::cast_from(delta)) * 2;
    if plaintext_modulus != crs.plaintext_modulus() {
        return Err(format!(
            "Mismatched plaintext modulus: CRS expects {}, requested modulus: {plaintext_modulus:?}",
            crs.plaintext_modulus()
        ).into());
    }

    Ok(())
}

fn encrypt_lwe_ciphertext_with_compact_public_key_impl<
    Scalar,
    KeyCont,
    OutputCont,
    MaskDistribution,
    NoiseDistribution,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
) -> CompactPublicKeyRandomVectors<Scalar>
where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution> + RandomGenerable<UniformBinary>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
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
    noise_generator.fill_slice_with_random_uniform_binary_bits(&mut binary_random_vector);

    let mut mask_noise = vec![Scalar::ZERO; lwe_compact_public_key.lwe_dimension().0];
    noise_generator
        .fill_slice_with_random_noise_from_distribution(&mut mask_noise, mask_noise_distribution);

    let body_noise = noise_generator.random_noise_from_distribution(body_noise_distribution);

    {
        let (mut ct_mask, ct_body) = output.get_mut_mask_and_body();
        let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();

        {
            slice_semi_reverse_negacyclic_convolution(
                ct_mask.as_mut(),
                pk_mask.as_ref(),
                &binary_random_vector,
            );

            // Noise from Chi_1 for the mask part of the encryption
            slice_wrapping_add_assign(ct_mask.as_mut(), mask_noise.as_slice());
        }

        {
            *ct_body.data = slice_wrapping_dot_product(pk_body.as_ref(), &binary_random_vector);
            // Noise from Chi_2 for the body part of the encryption
            *ct_body.data = (*ct_body.data).wrapping_add(body_noise);
            *ct_body.data = (*ct_body.data).wrapping_add(encoded.0);
        }
    }

    CompactPublicKeyRandomVectors {
        binary_random_vector,
        mask_noise,
        body_noise: vec![body_noise],
    }
}

/// Encrypt an input plaintext in an output [`LWE ciphertext`](`LweCiphertext`) using an
/// [`LWE compact public key`](`LweCompactPublicKey`). The ciphertext can be decrypted using the
/// [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
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
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_noise_distribution,
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
///     glwe_noise_distribution,
///     glwe_noise_distribution,
///     encryption_generator.noise_generator_mut(),
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
    MaskDistribution,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    encoded: Plaintext<Scalar>,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
) where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution> + RandomGenerable<UniformBinary>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    EncryptionGen: ByteRandomGenerator,
{
    let _ = encrypt_lwe_ciphertext_with_compact_public_key_impl(
        lwe_compact_public_key,
        output,
        encoded,
        mask_noise_distribution,
        body_noise_distribution,
        noise_generator,
    );
}

/// Encrypt and generates a zero-knowledge proof of an input cleartext
/// in an output [`LWE ciphertext`](`LweCiphertext`) using an
/// [`LWE compact public key`](`LweCompactPublicKey`). The ciphertext can be decrypted using the
/// [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
///
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::commons::math::random::RandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::zk::ZkMSBZeroPaddingBitCount;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let glwe_noise_distribution = TUniform::new(9);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let delta_log = 59;
/// let delta = 1u64 << delta_log;
/// let msb_zero_padding_bit_count = ZkMSBZeroPaddingBitCount(1);
/// let plaintext_modulus = 1u64 << (64 - delta_log - msb_zero_padding_bit_count.0);
/// // We need the padding bit in the plaintext modulus for the ZK
/// let zk_plaintext_modulus = plaintext_modulus << msb_zero_padding_bit_count.0;
///
/// // We can add custom metadata that will be required for verification, allowing to tie the proof
/// // to some arbitrary data.
/// let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let mut random_generator = RandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let crs = CompactPkeCrs::new(
///     lwe_dimension,
///     LweCiphertextCount(1),
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     zk_plaintext_modulus,
///     msb_zero_padding_bit_count,
///     &mut random_generator,
/// )
/// .unwrap();
///
/// // Create the plaintext
/// let msg = Cleartext(3u64);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// let proof = encrypt_and_prove_lwe_ciphertext_with_compact_public_key(
///     &lwe_compact_public_key,
///     &mut lwe,
///     msg,
///     delta,
///     glwe_noise_distribution,
///     glwe_noise_distribution,
///     encryption_generator.noise_generator_mut(),
///     &mut random_generator,
///     &crs,
///     &metadata,
///     ZkComputeLoad::Proof,
/// )
/// .unwrap();
///
/// // verify the ciphertext list with the proof
/// assert!(
///     verify_lwe_ciphertext(&lwe, &lwe_compact_public_key, &proof, &crs, &metadata).is_valid()
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(
///     DecompositionBaseLog((64 - delta_log) as usize),
///     DecompositionLevelCount(1),
/// );
///
/// let rounded = decomposer.closest_representable(decrypted_plaintext.0);
///
/// // Remove the encoding
/// let cleartext = rounded >> delta_log;
///
/// // Check we recovered the original message
/// assert_eq!(cleartext, msg.0);
/// ```
#[cfg(feature = "zk-pok")]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_and_prove_lwe_ciphertext_with_compact_public_key<
    Scalar,
    KeyCont,
    OutputCont,
    MaskDistribution,
    NoiseDistribution,
    EncryptionGen,
    G,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCiphertext<OutputCont>,
    message: Cleartext<Scalar>,
    delta: Scalar,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
    random_generator: &mut RandomGenerator<G>,
    crs: &CompactPkeCrs,
    metadata: &[u8],
    load: ZkComputeLoad,
) -> crate::Result<CompactPkeProof>
where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution>
        + RandomGenerable<UniformBinary>
        + CastFrom<u64>,
    Scalar::Signed: CastFrom<u64>,
    i64: CastFrom<Scalar>,
    u64: CastFrom<Scalar> + CastInto<Scalar::Signed>,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    MaskDistribution: BoundedDistribution<Scalar::Signed>,
    NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    EncryptionGen: ByteRandomGenerator,
    G: ByteRandomGenerator,
{
    verify_zero_knowledge_preconditions(
        lwe_compact_public_key,
        LweCiphertextCount(1),
        output.ciphertext_modulus(),
        delta,
        mask_noise_distribution,
        body_noise_distribution,
        crs,
    )?;

    let CompactPublicKeyRandomVectors {
        binary_random_vector,
        mask_noise,
        body_noise,
    } = encrypt_lwe_ciphertext_with_compact_public_key_impl(
        lwe_compact_public_key,
        output,
        Plaintext(message.0 * delta),
        mask_noise_distribution,
        body_noise_distribution,
        noise_generator,
    );

    Ok(crs.prove(
        lwe_compact_public_key,
        &vec![message.0],
        &LweCompactCiphertextList::from_container(
            output.as_ref(),
            output.lwe_size(),
            LweCiphertextCount(1),
            output.ciphertext_modulus(),
        ),
        &binary_random_vector,
        &mask_noise,
        &body_noise,
        metadata,
        load,
        random_generator,
    ))
}

fn encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
    MaskDistribution,
    NoiseDistribution,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
    slice_semi_reverse_negacyclic_convolution_impl: fn(&mut [Scalar], &[Scalar], &[Scalar]),
) -> CompactPublicKeyRandomVectors<Scalar>
where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution> + RandomGenerable<UniformBinary>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
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

    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();
    let (mut output_mask_list, mut output_body_list) = output.get_mut_mask_and_body_list();

    let mut binary_random_vector = vec![Scalar::ZERO; output_mask_list.lwe_mask_list_size()];
    noise_generator.fill_slice_with_random_uniform_binary_bits(&mut binary_random_vector);

    let mut mask_noise = vec![Scalar::ZERO; output_mask_list.lwe_mask_list_size()];
    noise_generator
        .fill_slice_with_random_noise_from_distribution(&mut mask_noise, mask_noise_distribution);

    let mut body_noise = vec![Scalar::ZERO; encoded.plaintext_count().0];
    noise_generator
        .fill_slice_with_random_noise_from_distribution(&mut body_noise, body_noise_distribution);

    let max_ciphertext_per_bin = lwe_compact_public_key.lwe_dimension().0;
    output_mask_list
        .iter_mut()
        .zip(
            output_body_list
                .chunks_mut(max_ciphertext_per_bin)
                .zip(encoded.chunks(max_ciphertext_per_bin))
                .zip(binary_random_vector.chunks(max_ciphertext_per_bin))
                .zip(mask_noise.as_slice().chunks(max_ciphertext_per_bin))
                .zip(body_noise.as_slice().chunks(max_ciphertext_per_bin)),
        )
        .for_each(
            |(
                mut output_mask,
                (
                    (
                        ((mut output_body_chunk, input_plaintext_chunk), binary_random_slice),
                        mask_noise,
                    ),
                    body_noise,
                ),
            )| {
                // output_body_chunk may not be able to fit the full convolution result so we
                // create a temp buffer to compute the full convolution
                let mut pk_body_convolved = vec![Scalar::ZERO; max_ciphertext_per_bin];

                slice_semi_reverse_negacyclic_convolution_impl(
                    output_mask.as_mut(),
                    pk_mask.as_ref(),
                    binary_random_slice,
                );

                // Fill the temp buffer with b convolved with r
                slice_semi_reverse_negacyclic_convolution_impl(
                    pk_body_convolved.as_mut_slice(),
                    pk_body.as_ref(),
                    binary_random_slice,
                );

                slice_wrapping_add_assign(output_mask.as_mut(), mask_noise);

                // Fill the body chunk afterward manually as it most likely will be smaller than
                // the full convolution result. rev(b convolved r) + Delta * m + e2
                // taking noise from Chi_2 for the body part of the encryption
                output_body_chunk
                    .iter_mut()
                    .zip(
                        pk_body_convolved
                            .iter()
                            .rev()
                            .zip(input_plaintext_chunk.iter()),
                    )
                    .zip(body_noise)
                    .for_each(|((dst, (&src, plaintext)), body_noise)| {
                        *dst.data = src.wrapping_add(*body_noise).wrapping_add(*plaintext.0);
                    });
            },
        );
    CompactPublicKeyRandomVectors {
        binary_random_vector,
        mask_noise,
        body_noise,
    }
}

/// Encrypt an input plaintext list in an output [`LWE compact ciphertext
/// list`](`LweCompactCiphertextList`) using an [`LWE compact public key`](`LweCompactPublicKey`).
/// The expanded ciphertext list can be decrypted using the [`LWE secret key`](`LweSecretKey`) that
/// was used to generate the public key.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_ciphertext_count = LweCiphertextCount(lwe_dimension.0 * 4);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_noise_distribution,
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
///     glwe_noise_distribution,
///     glwe_noise_distribution,
///     encryption_generator.noise_generator_mut(),
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
    MaskDistribution,
    NoiseDistribution,
    KeyCont,
    InputCont,
    OutputCont,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
) where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution> + RandomGenerable<UniformBinary>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    EncryptionGen: ByteRandomGenerator,
{
    // Conservative for now this implementation does not use the optimized implementation of the
    // negacyclic convolution
    let _ = encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl(
        lwe_compact_public_key,
        output,
        encoded,
        mask_noise_distribution,
        body_noise_distribution,
        noise_generator,
        slice_semi_reverse_negacyclic_convolution,
    );
}

/// Encrypt and generates a zero-knowledge proof of an input cleartext list in an output
/// [`LWE compact ciphertext list`](`LweCompactCiphertextList`)
/// using an [`LWE compact public key`](`LweCompactPublicKey`).
///
/// The expanded ciphertext list can be decrypted using the [`LWE secret key`](`LweSecretKey`) that
/// was used to generate the public key.
///
/// - The input cleartext list must have a length smaller or equal the maximum number of message
///   authorized by the CRS.
///
/// - The noise distributions must be bounded
///
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::commons::math::random::RandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::zk::ZkMSBZeroPaddingBitCount;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_ciphertext_count = LweCiphertextCount(4);
/// let glwe_noise_distribution = TUniform::new(9);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let delta_log = 59;
/// let delta = 1u64 << delta_log;
/// let msb_zero_padding_bit_count = ZkMSBZeroPaddingBitCount(1);
/// let plaintext_modulus = 1u64 << (64 - delta_log - msb_zero_padding_bit_count.0);
/// // We need the padding bit in the plaintext modulus for the ZK
/// let zk_plaintext_modulus = plaintext_modulus << msb_zero_padding_bit_count.0;
///
/// // We can add custom metadata that will be required for verification, allowing to tie the proof
/// // to some arbitrary data.
/// let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let mut random_generator = RandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// let crs = CompactPkeCrs::new(
///     lwe_dimension,
///     lwe_ciphertext_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     zk_plaintext_modulus,
///     msb_zero_padding_bit_count,
///     &mut random_generator,
/// )
/// .unwrap();
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let cleartexts = (0..lwe_ciphertext_count.0 as u64).collect::<Vec<_>>();
///
/// // Create a new LweCompactCiphertextList
/// let mut output_compact_ct_list = LweCompactCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
///
/// let proof = encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
///     &lwe_compact_public_key,
///     &mut output_compact_ct_list,
///     &cleartexts,
///     delta,
///     glwe_noise_distribution,
///     glwe_noise_distribution,
///     encryption_generator.noise_generator_mut(),
///     &mut random_generator,
///     &crs,
///     &metadata,
///     ZkComputeLoad::Proof,
/// )
/// .unwrap();
///
/// // verify the ciphertext list with the proof
/// assert!(verify_lwe_compact_ciphertext_list(
///     &output_compact_ct_list,
///     &lwe_compact_public_key,
///     &proof,
///     &crs,
///     &metadata,
/// )
/// .is_valid());
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(lwe_ciphertext_count.0));
///
/// let lwe_ciphertext_list = output_compact_ct_list.expand_into_lwe_ciphertext_list();
///
/// decrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &lwe_ciphertext_list,
///     &mut output_plaintext_list,
/// );
///
/// let signed_decomposer = SignedDecomposer::new(
///     DecompositionBaseLog((64 - delta_log) as usize),
///     DecompositionLevelCount(1),
/// );
///
/// // Round the plaintexts
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0) >> delta_log);
///
/// // Check we recovered the original messages
/// assert_eq!(&cleartexts, output_plaintext_list.as_ref());
/// ```
#[cfg(feature = "zk-pok")]
#[allow(clippy::too_many_arguments)]
pub fn encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
    MaskDistribution,
    NoiseDistribution,
    EncryptionGen,
    G,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    messages: &InputCont,
    delta: Scalar,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
    random_generator: &mut RandomGenerator<G>,
    crs: &CompactPkeCrs,
    metadata: &[u8],
    load: ZkComputeLoad,
) -> crate::Result<CompactPkeProof>
where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution>
        + RandomGenerable<UniformBinary>
        + CastFrom<u64>,
    Scalar::Signed: CastFrom<u64>,
    i64: CastFrom<Scalar>,
    u64: CastFrom<Scalar> + CastInto<Scalar::Signed>,
    MaskDistribution: BoundedDistribution<Scalar::Signed>,
    NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    EncryptionGen: ByteRandomGenerator,
    G: ByteRandomGenerator,
{
    verify_zero_knowledge_preconditions(
        lwe_compact_public_key,
        output.lwe_ciphertext_count(),
        output.ciphertext_modulus(),
        delta,
        mask_noise_distribution,
        body_noise_distribution,
        crs,
    )?;

    let encoded = PlaintextList::from_container(
        messages
            .as_ref()
            .iter()
            .copied()
            .map(|m| m * delta)
            .collect::<Vec<_>>(),
    );

    // Conservative for now this implementation does not use the optimized implementation of the
    // negacyclic convolution
    let CompactPublicKeyRandomVectors {
        binary_random_vector,
        mask_noise,
        body_noise,
    } = encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl(
        lwe_compact_public_key,
        output,
        &encoded,
        mask_noise_distribution,
        body_noise_distribution,
        noise_generator,
        slice_semi_reverse_negacyclic_convolution,
    );

    Ok(crs.prove(
        lwe_compact_public_key,
        messages,
        output,
        &binary_random_vector,
        &mask_noise,
        &body_noise,
        metadata,
        load,
        random_generator,
    ))
}

fn par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
    MaskDistribution,
    NoiseDistribution,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
) -> CompactPublicKeyRandomVectors<Scalar>
where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution> + RandomGenerable<UniformBinary>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
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

    let (pk_mask, pk_body) = lwe_compact_public_key.get_mask_and_body();
    let (mut output_mask_list, mut output_body_list) = output.get_mut_mask_and_body_list();

    let mut binary_random_vector = vec![Scalar::ZERO; output_mask_list.lwe_mask_list_size()];
    noise_generator.fill_slice_with_random_uniform_binary_bits(&mut binary_random_vector);

    let mut mask_noise = vec![Scalar::ZERO; output_mask_list.lwe_mask_list_size()];
    noise_generator
        .fill_slice_with_random_noise_from_distribution(&mut mask_noise, mask_noise_distribution);

    let mut body_noise = vec![Scalar::ZERO; encoded.plaintext_count().0];
    noise_generator
        .fill_slice_with_random_noise_from_distribution(&mut body_noise, body_noise_distribution);

    let max_ciphertext_per_bin = lwe_compact_public_key.lwe_dimension().0;
    output_mask_list
        .par_iter_mut()
        .zip(
            output_body_list
                .par_chunks_mut(max_ciphertext_per_bin)
                .zip(encoded.par_chunks(max_ciphertext_per_bin))
                .zip(binary_random_vector.par_chunks(max_ciphertext_per_bin))
                .zip(mask_noise.as_slice().par_chunks(max_ciphertext_per_bin))
                .zip(body_noise.as_slice().par_chunks(max_ciphertext_per_bin)),
        )
        .for_each(
            |(
                mut output_mask,
                (
                    (
                        ((mut output_body_chunk, input_plaintext_chunk), binary_random_slice),
                        mask_noise,
                    ),
                    body_noise,
                ),
            )| {
                // output_body_chunk may not be able to fit the full convolution result so we
                // create a temp buffer to compute the full convolution
                let mut pk_body_convolved = vec![Scalar::ZERO; max_ciphertext_per_bin];

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

                slice_wrapping_add_assign(output_mask.as_mut(), mask_noise);

                // Fill the body chunk afterward manually as it most likely will be smaller than
                // the full convolution result. rev(b convolved r) + Delta * m + e2
                // taking noise from Chi_2 for the body part of the encryption
                output_body_chunk
                    .iter_mut()
                    .zip(
                        pk_body_convolved
                            .iter()
                            .rev()
                            .zip(input_plaintext_chunk.iter()),
                    )
                    .zip(body_noise)
                    .for_each(|((dst, (&src, plaintext)), body_noise)| {
                        *dst.data = src.wrapping_add(*body_noise).wrapping_add(*plaintext.0);
                    });
            },
        );
    CompactPublicKeyRandomVectors {
        binary_random_vector,
        mask_noise,
        body_noise,
    }
}

/// Parallel variant of [`encrypt_lwe_compact_ciphertext_list_with_compact_public_key`]. Encrypt an
/// input plaintext list in an output [`LWE compact ciphertext list`](`LweCompactCiphertextList`)
/// using an [`LWE compact public key`](`LweCompactPublicKey`). The expanded ciphertext list can be
/// decrypted using the [`LWE secret key`](`LweSecretKey`) that was used to generate the public key.
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_ciphertext_count = LweCiphertextCount(lwe_dimension.0 * 4);
/// let glwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
///
/// // create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_noise_distribution,
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
///     glwe_noise_distribution,
///     glwe_noise_distribution,
///     encryption_generator.noise_generator_mut(),
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
    MaskDistribution,
    NoiseDistribution,
    KeyCont,
    InputCont,
    OutputCont,
    EncryptionGen,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    encoded: &PlaintextList<InputCont>,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
) where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution>
        + RandomGenerable<UniformBinary>
        + Sync
        + Send,
    MaskDistribution: Distribution + Sync,
    NoiseDistribution: Distribution + Sync,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    EncryptionGen: ParallelByteRandomGenerator,
{
    let _ = par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl(
        lwe_compact_public_key,
        output,
        encoded,
        mask_noise_distribution,
        body_noise_distribution,
        noise_generator,
    );
}

///  Parallel variant of [`encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key`].
/// Encrypt and generates a zero-knowledge proof of an input cleartext list in an output
/// [`LWE compact ciphertext list`](`LweCompactCiphertextList`)
/// using an [`LWE compact public key`](`LweCompactPublicKey`).
///
/// The expanded ciphertext list can be decrypted using the [`LWE secret key`](`LweSecretKey`) that
/// was used to generate the public key.
///
/// - The input cleartext list must have a length smaller or equal the maximum number of message
///   authorized by the CRS.
///
/// - The noise distributions must be bounded
///
///
/// # Example
///
/// ```rust
/// use tfhe::core_crypto::commons::math::random::RandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::zk::{ZkComputeLoad, ZkMSBZeroPaddingBitCount};
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_ciphertext_count = LweCiphertextCount(4);
/// let glwe_noise_distribution = TUniform::new(9);
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let delta_log = 59;
/// let delta = 1u64 << delta_log;
/// let msb_zero_padding_bit_count = ZkMSBZeroPaddingBitCount(1);
/// let plaintext_modulus = 1u64 << (64 - delta_log - msb_zero_padding_bit_count.0);
/// // We need the padding bit in the plaintext modulus for the ZK
/// let zk_plaintext_modulus = plaintext_modulus << msb_zero_padding_bit_count.0;
///
/// // We can add custom metadata that will be required for verification, allowing to tie the proof
/// // to some arbitrary data.
/// let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
/// let mut random_generator = RandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// let crs = CompactPkeCrs::new(
///     lwe_dimension,
///     lwe_ciphertext_count,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     zk_plaintext_modulus,
///     msb_zero_padding_bit_count,
///     &mut random_generator,
/// )
/// .unwrap();
///
/// // Create the LweSecretKey
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let lwe_compact_public_key = allocate_and_generate_new_lwe_compact_public_key(
///     &lwe_secret_key,
///     glwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// let cleartexts = (0..lwe_ciphertext_count.0 as u64).collect::<Vec<_>>();
///
/// // Create a new LweCompactCiphertextList
/// let mut output_compact_ct_list = LweCompactCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_ciphertext_count,
///     ciphertext_modulus,
/// );
///
/// let proof = par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key(
///     &lwe_compact_public_key,
///     &mut output_compact_ct_list,
///     &cleartexts,
///     delta,
///     glwe_noise_distribution,
///     glwe_noise_distribution,
///     encryption_generator.noise_generator_mut(),
///     &mut random_generator,
///     &crs,
///     &metadata,
///     ZkComputeLoad::Proof,
/// )
/// .unwrap();
///
/// // verify the ciphertext list with the proof
/// assert!(verify_lwe_compact_ciphertext_list(
///     &output_compact_ct_list,
///     &lwe_compact_public_key,
///     &proof,
///     &crs,
///     &metadata,
/// )
/// .is_valid());
///
/// let mut output_plaintext_list =
///     PlaintextList::new(0u64, PlaintextCount(lwe_ciphertext_count.0));
///
/// let lwe_ciphertext_list = output_compact_ct_list.expand_into_lwe_ciphertext_list();
///
/// decrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &lwe_ciphertext_list,
///     &mut output_plaintext_list,
/// );
///
/// let signed_decomposer = SignedDecomposer::new(
///     DecompositionBaseLog((64 - delta_log) as usize),
///     DecompositionLevelCount(1),
/// );
///
/// // Round the plaintexts
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0) >> delta_log);
///
/// // Check we recovered the original messages
/// assert_eq!(&cleartexts, output_plaintext_list.as_ref());
/// ```
#[cfg(feature = "zk-pok")]
#[allow(clippy::too_many_arguments)]
pub fn par_encrypt_and_prove_lwe_compact_ciphertext_list_with_compact_public_key<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
    MaskDistribution,
    NoiseDistribution,
    EncryptionGen,
    G,
>(
    lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
    output: &mut LweCompactCiphertextList<OutputCont>,
    messages: &InputCont,
    delta: Scalar,
    mask_noise_distribution: MaskDistribution,
    body_noise_distribution: NoiseDistribution,
    noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
    random_generator: &mut RandomGenerator<G>,
    crs: &CompactPkeCrs,
    metadata: &[u8],
    load: ZkComputeLoad,
) -> crate::Result<CompactPkeProof>
where
    Scalar: Encryptable<MaskDistribution, NoiseDistribution>
        + RandomGenerable<UniformBinary>
        + CastFrom<u64>,
    Scalar::Signed: CastFrom<u64>,
    i64: CastFrom<Scalar>,
    u64: CastFrom<Scalar> + CastInto<Scalar::Signed>,
    MaskDistribution: BoundedDistribution<Scalar::Signed>,
    NoiseDistribution: BoundedDistribution<Scalar::Signed>,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    EncryptionGen: ByteRandomGenerator,
    G: ByteRandomGenerator,
{
    verify_zero_knowledge_preconditions(
        lwe_compact_public_key,
        output.lwe_ciphertext_count(),
        output.ciphertext_modulus(),
        delta,
        mask_noise_distribution,
        body_noise_distribution,
        crs,
    )?;

    let encoded = PlaintextList::from_container(
        messages
            .as_ref()
            .iter()
            .copied()
            .map(|m| m * delta)
            .collect::<Vec<_>>(),
    );

    let CompactPublicKeyRandomVectors {
        binary_random_vector,
        mask_noise,
        body_noise,
    } = par_encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl(
        lwe_compact_public_key,
        output,
        &encoded,
        mask_noise_distribution,
        body_noise_distribution,
        noise_generator,
    );

    Ok(crs.prove(
        lwe_compact_public_key,
        messages,
        output,
        &binary_random_vector,
        &mask_noise,
        &body_noise,
        metadata,
        load,
        random_generator,
    ))
}

pub mod re_randomization {
    use super::*;
    pub fn rerand_encrypt_lwe_compact_ciphertext_list_with_compact_public_key<
        Scalar,
        MaskDistribution,
        NoiseDistribution,
        KeyCont,
        InputCont,
        OutputCont,
        EncryptionGen,
    >(
        lwe_compact_public_key: &LweCompactPublicKey<KeyCont>,
        output: &mut LweCompactCiphertextList<OutputCont>,
        encoded: &PlaintextList<InputCont>,
        mask_noise_distribution: MaskDistribution,
        body_noise_distribution: NoiseDistribution,
        noise_generator: &mut NoiseRandomGenerator<EncryptionGen>,
    ) where
        Scalar: Encryptable<MaskDistribution, NoiseDistribution> + RandomGenerable<UniformBinary>,
        MaskDistribution: Distribution,
        NoiseDistribution: Distribution,
        KeyCont: Container<Element = Scalar>,
        InputCont: Container<Element = Scalar>,
        OutputCont: ContainerMut<Element = Scalar>,
        EncryptionGen: ByteRandomGenerator,
    {
        // Rerand uses the optimized implementation of the negacyclic convolution
        let _ = encrypt_lwe_compact_ciphertext_list_with_compact_public_key_impl(
            lwe_compact_public_key,
            output,
            encoded,
            mask_noise_distribution,
            body_noise_distribution,
            noise_generator,
            slice_binary_semi_reverse_negacyclic_convolution,
        );
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::commons::generators::DeterministicSeeder;
    use crate::core_crypto::commons::test_tools;
    use crate::core_crypto::prelude::*;

    #[test]
    fn test_compact_public_key_encryption() {
        use rand::Rng;

        let lwe_dimension = LweDimension(2048);
        let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
            StandardDev(0.00000000000000029403601535432533),
            0.0,
        );
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
                glwe_noise_distribution,
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
                glwe_noise_distribution,
                glwe_noise_distribution,
                encryption_random_generator.noise_generator_mut(),
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
        let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
            StandardDev(0.00000000000000029403601535432533),
            0.0,
        );
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
                    DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
                let mut secret_random_generator =
                    SecretRandomGenerator::<DefaultRandomGenerator>::new(
                        deterministic_seeder.seed(),
                    );
                let mut encryption_random_generator =
                    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
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
                    glwe_noise_distribution,
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
                    glwe_noise_distribution,
                    glwe_noise_distribution,
                    encryption_random_generator.noise_generator_mut(),
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
                    DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
                let mut secret_random_generator =
                    SecretRandomGenerator::<DefaultRandomGenerator>::new(
                        deterministic_seeder.seed(),
                    );
                let mut encryption_random_generator =
                    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
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
                    glwe_noise_distribution,
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
                    glwe_noise_distribution,
                    glwe_noise_distribution,
                    encryption_random_generator.noise_generator_mut(),
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

    #[test]
    fn test_rerand_compact_lwe_list_public_key_encryption_equivalence() {
        use rand::Rng;
        use re_randomization::rerand_encrypt_lwe_compact_ciphertext_list_with_compact_public_key;

        let lwe_dimension = LweDimension(2048);
        let glwe_noise_distribution = TUniform::new(17);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let mut thread_rng = rand::thread_rng();

        let cleartext_bits_without_padding = 4;
        let cleartext_modulus = 1 << cleartext_bits_without_padding;
        let cleartext_bits_with_padding = cleartext_bits_without_padding + 1;

        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(cleartext_bits_with_padding),
            DecompositionLevelCount(1),
        );

        for _ in 0..100 {
            // We'll encrypt between 1 and 4 * lwe_dimension ciphertexts
            let ct_count: usize = thread_rng.gen_range(1..=lwe_dimension.0 * 4);
            let lwe_ciphertext_count = LweCiphertextCount(ct_count);

            println!("{lwe_dimension:?} {ct_count:?}");

            let seed = test_tools::random_seed();
            println!("seed={seed:?}");
            let mut input_plaintext_list =
                PlaintextList::new(0u64, PlaintextCount(lwe_ciphertext_count.0));
            input_plaintext_list.iter_mut().for_each(|x| {
                let msg: u64 = thread_rng.gen();
                *x.0 =
                    (msg % cleartext_modulus) << (u64::BITS - cleartext_bits_with_padding as u32);
            });

            let get_seeded_gen = || {
                let mut deterministic_seeder =
                    DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
                (
                    SecretRandomGenerator::<DefaultRandomGenerator>::new(
                        deterministic_seeder.seed(),
                    ),
                    EncryptionRandomGenerator::<DefaultRandomGenerator>::new(
                        deterministic_seeder.seed(),
                        &mut deterministic_seeder,
                    ),
                )
            };

            let rerand_lwe_ct_list = {
                let (mut secret_random_generator, mut encryption_random_generator) =
                    get_seeded_gen();

                let lwe_sk =
                    LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

                let mut compact_lwe_pk =
                    LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

                generate_lwe_compact_public_key(
                    &lwe_sk,
                    &mut compact_lwe_pk,
                    glwe_noise_distribution,
                    &mut encryption_random_generator,
                );

                let mut output_compact_ct_list = LweCompactCiphertextList::new(
                    0u64,
                    lwe_dimension.to_lwe_size(),
                    lwe_ciphertext_count,
                    ciphertext_modulus,
                );

                rerand_encrypt_lwe_compact_ciphertext_list_with_compact_public_key(
                    &compact_lwe_pk,
                    &mut output_compact_ct_list,
                    &input_plaintext_list,
                    glwe_noise_distribution,
                    glwe_noise_distribution,
                    encryption_random_generator.noise_generator_mut(),
                );

                let mut output_plaintext_list = input_plaintext_list.clone();
                output_plaintext_list.as_mut().fill(0u64);

                let lwe_ciphertext_list = output_compact_ct_list.expand_into_lwe_ciphertext_list();

                decrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &lwe_ciphertext_list,
                    &mut output_plaintext_list,
                );

                output_plaintext_list
                    .iter_mut()
                    .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

                assert_eq!(input_plaintext_list, output_plaintext_list);

                lwe_ciphertext_list
            };

            let lwe_ct_list = {
                let (mut secret_random_generator, mut encryption_random_generator) =
                    get_seeded_gen();

                let lwe_sk =
                    LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_random_generator);

                let mut compact_lwe_pk =
                    LweCompactPublicKey::new(0u64, lwe_dimension, ciphertext_modulus);

                generate_lwe_compact_public_key(
                    &lwe_sk,
                    &mut compact_lwe_pk,
                    glwe_noise_distribution,
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
                    glwe_noise_distribution,
                    glwe_noise_distribution,
                    encryption_random_generator.noise_generator_mut(),
                );

                let mut output_plaintext_list = input_plaintext_list.clone();
                output_plaintext_list.as_mut().fill(0u64);

                let lwe_ciphertext_list = output_compact_ct_list.expand_into_lwe_ciphertext_list();

                decrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &lwe_ciphertext_list,
                    &mut output_plaintext_list,
                );

                output_plaintext_list
                    .iter_mut()
                    .for_each(|x| *x.0 = signed_decomposer.closest_representable(*x.0));

                assert_eq!(input_plaintext_list, output_plaintext_list);

                lwe_ciphertext_list
            };

            assert_eq!(lwe_ct_list, rerand_lwe_ct_list);
        }
    }
}
