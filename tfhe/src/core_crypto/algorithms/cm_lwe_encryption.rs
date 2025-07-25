//! Module containing primitives pertaining to [`LWE ciphertext encryption and
//! decryption`](`LweCiphertext#lwe-encryption`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use itertools::Itertools;

/// Convenience function to share the core logic of the LWE encryption between all functions needing
/// it.
pub fn fill_cm_lwe_mask_and_bodies_for_encryption<
    Scalar,
    NoiseDistribution,
    KeyCont,
    EncodedCont,
    OutputMaskCont,
    OutputBodyCont,
    Gen,
>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    output_mask: &mut LweMask<OutputMaskCont>,
    output_bodies: &mut LweBodyList<OutputBodyCont>,
    encoded: &PlaintextList<EncodedCont>,
    noise_parameters: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    EncodedCont: Container<Element = Scalar>,
    OutputMaskCont: ContainerMut<Element = Scalar>,
    OutputBodyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert_eq!(
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus(),
        "Mismatched moduli between mask ({:?}) and body ({:?})",
        output_mask.ciphertext_modulus(),
        output_bodies.ciphertext_modulus()
    );

    let ciphertext_modulus = output_mask.ciphertext_modulus();

    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // generate a randomly uniform mask
    generator
        .fill_slice_with_random_uniform_mask_custom_mod(output_mask.as_mut(), ciphertext_modulus);

    for ((sk, body), encoded) in lwe_secret_keys
        .iter()
        .zip_eq(output_bodies.iter_mut())
        .zip_eq(encoded.iter())
    {
        // generate an error from the normal distribution described by std_dev
        let noise = generator
            .random_noise_from_distribution_custom_mod(noise_parameters, ciphertext_modulus);
        // compute the multisum between the secret key and the mask
        let mask_key_dot_product = slice_wrapping_dot_product(output_mask.as_ref(), sk.as_ref());

        // Store sum(ai * si) + delta * m + e in the body
        *body.data = mask_key_dot_product
            .wrapping_add(*encoded.0)
            .wrapping_add(noise);
    }
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
/// let lwe_noise_distribution =
///     DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.000007069849454709433));
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
pub fn encrypt_cm_lwe_ciphertext<Scalar, NoiseDistribution, KeyCont, EncodedCont, OutputCont, Gen>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    output: &mut CmLweCiphertext<OutputCont>,
    encoded: &PlaintextList<EncodedCont>,
    noise_parameters: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    EncodedCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let (mut mask, mut body) = output.get_mut_mask_and_bodies();

    fill_cm_lwe_mask_and_bodies_for_encryption(
        lwe_secret_keys,
        &mut mask,
        &mut body,
        encoded,
        noise_parameters,
        generator,
    );
}

pub fn decrypt_cm_lwe_ciphertext<Scalar, KeyCont, InputCont>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    cm_lwe_ciphertext: &CmLweCiphertext<InputCont>,
) -> Vec<Plaintext<Scalar>>
where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
{
    assert!(
        cm_lwe_ciphertext.lwe_dimension() == lwe_secret_keys[0].lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        cm_lwe_ciphertext.lwe_dimension(),
        lwe_secret_keys[0].lwe_dimension()
    );

    let ciphertext_modulus = cm_lwe_ciphertext.ciphertext_modulus();

    assert!(ciphertext_modulus.is_native_modulus());

    let (mask, bodies) = cm_lwe_ciphertext.get_mask_and_bodies();

    bodies
        .iter()
        .zip_eq(lwe_secret_keys.iter())
        .map(|(body, lwe_secret_key)| {
            let mask_key_dot_product =
                slice_wrapping_dot_product(mask.as_ref(), lwe_secret_key.as_ref());

            Plaintext(body.data.wrapping_sub(mask_key_dot_product))
        })
        .collect_vec()
}

/// Allocate a new [`CRS LWE ciphertext`](`CmLweCiphertextOwned`) and encrypt an input plaintext
/// list in it.
///
/// # Example
///
/// ```
/// use itertools::Itertools;
/// use tfhe::core_crypto::prelude::*;
///
/// let lwe_dimension = LweDimension(742);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.0000000007069849454709433), 0.);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// let cm_dimension = CmDimension(10);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let lwe_secret_keys = (0..cm_dimension.0)
///     .map(|_| {
///         allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator)
///     })
///     .collect_vec();
///
/// // Create the plaintext
///
/// let plaintext = (0..cm_dimension.0).map(|i| (i as u64) << 55).collect_vec();
///
/// let plaintext_list = PlaintextList::from_container(plaintext.as_slice());
///
/// // Create a new LweCiphertext
/// let lwe = allocate_and_encrypt_new_cm_lwe_ciphertext(
///     &lwe_secret_keys,
///     &plaintext_list,
///     lwe_noise_distribution,
///     ciphertext_modulus,
///     &mut encryption_generator,
/// );
///
/// for i in 0..cm_dimension.0 {
///     let decrypted_plaintext =
///         decrypt_lwe_ciphertext(&lwe_secret_keys[i], &lwe.extract_lwe_ciphertext(i));
///
///     // Round and remove encoding
///     // First create a decomposer working on the high 4 bits corresponding to our encoding.
///     let decomposer = SignedDecomposer::new(DecompositionBaseLog(9), DecompositionLevelCount(1));
///
///     let rounded = decomposer.closest_representable(decrypted_plaintext.0);
///
///     // Remove the encoding
///     let cleartext = rounded >> 55;
///
///     // Check we recovered the original message
///     assert_eq!(cleartext, plaintext[i] >> 55);
/// }
/// ```
pub fn allocate_and_encrypt_new_cm_lwe_ciphertext<
    Scalar,
    NoiseDistribution,
    KeyCont,
    EncodedCont,
    Gen,
>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    encoded: &PlaintextList<EncodedCont>,
    noise_parameters: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> CmLweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    EncodedCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct = CmLweCiphertextOwned::new(
        Scalar::ZERO,
        lwe_secret_keys[0].lwe_dimension(),
        CmDimension(encoded.as_ref().len()),
        ciphertext_modulus,
    );

    encrypt_cm_lwe_ciphertext(
        lwe_secret_keys,
        &mut new_ct,
        encoded,
        noise_parameters,
        generator,
    );

    new_ct
}

pub fn encrypt_cm_lwe_ciphertext_list<
    Scalar,
    NoiseDistribution,
    KeyCont,
    OutputCont,
    InputCont,
    Gen,
>(
    lwe_secret_keys: &[LweSecretKey<KeyCont>],
    output: &mut CmLweCiphertextList<OutputCont>,
    encoded: &[PlaintextList<InputCont>],
    noise_parameters: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    NoiseDistribution: Distribution,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    for (mut output, encoded) in output.iter_mut().zip_eq(encoded.iter()) {
        encrypt_cm_lwe_ciphertext(
            lwe_secret_keys,
            &mut output,
            encoded,
            noise_parameters,
            &mut *generator,
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::core_crypto::prelude::*;

    #[test]
    fn cm_encryption() {
        let lwe_dimension = LweDimension(742);
        let lwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(0.0000000007069849454709433), 0.);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let cm_dimension = CmDimension(10);

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        // Create the LweSecretKey
        let lwe_secret_keys = (0..cm_dimension.0)
            .map(|_| {
                allocate_and_generate_new_binary_lwe_secret_key(
                    lwe_dimension,
                    &mut secret_generator,
                )
            })
            .collect_vec();

        // Create the plaintext

        let plaintext = (0..cm_dimension.0).map(|i| (i as u64) << 55).collect_vec();

        let plaintext_list = PlaintextList::from_container(plaintext.as_slice());

        // Create a new LweCiphertext
        let lwe = allocate_and_encrypt_new_cm_lwe_ciphertext(
            &lwe_secret_keys,
            &plaintext_list,
            lwe_noise_distribution,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        for i in 0..cm_dimension.0 {
            let decrypted_plaintext =
                decrypt_lwe_ciphertext(&lwe_secret_keys[i], &lwe.extract_lwe_ciphertext(i));

            // Round and remove encoding
            // First create a decomposer working on the high 4 bits corresponding to our encoding.
            let decomposer =
                SignedDecomposer::new(DecompositionBaseLog(9), DecompositionLevelCount(1));

            let rounded = decomposer.closest_representable(decrypted_plaintext.0);

            // Remove the encoding
            let cleartext = rounded >> 55;

            // Check we recovered the original message
            assert_eq!(cleartext, plaintext[i] >> 55);
        }
    }
}
