//! Module containing primitives pertaining to [`LWE ciphertext encryption and
//! decryption`](`LweCiphertext#lwe-encryption`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
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
    output_body: LweBodyRefMut<Scalar>,
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

    let ciphertext_modulus = output_body.ciphertext_modulus();

    // First fill the output mask and output body with values of the output Scalar type
    generator.fill_slice_with_random_mask(output_mask.as_mut());

    // generate an error from the normal distribution described by std_dev
    *output_body.data = generator.random_noise(noise_parameters);

    // If the modulus is compatible with the native one then we just apply wrapping computation and
    // enjoy the perf gain
    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // compute the multisum between the secret key and the mask
        *output_body.data = (*output_body.data).wrapping_add(slice_wrapping_dot_product(
            output_mask.as_ref(),
            lwe_secret_key.as_ref(),
        ));

        *output_body.data = (*output_body.data).wrapping_add(encoded.0);

        if !ciphertext_modulus.is_native_modulus() {
            let modulus = Scalar::cast_from(ciphertext_modulus.get());
            slice_wrapping_rem_assign(output_mask.as_mut(), modulus);
            *output_body.data = (*output_body.data).wrapping_rem(modulus);
        }
    } else {
        // If the modulus is not the native one, then as a fallback we use a bigger data type to
        // compute without overflows and apply the modulus later
        let mut ct_128 = LweCiphertext::new(
            0u128,
            lwe_secret_key.lwe_dimension().to_lwe_size(),
            CiphertextModulus::new_native(),
        );
        let mut key_128 = LweSecretKey::new_empty_key(0u128, lwe_secret_key.lwe_dimension());

        let ciphertext_modulus = ciphertext_modulus.get();

        copy_from_convert(&mut key_128, &lwe_secret_key);

        let (mut mask_128, body_128) = ct_128.get_mut_mask_and_body();

        copy_from_convert(&mut mask_128, &output_mask);

        slice_wrapping_rem_assign(mask_128.as_mut(), ciphertext_modulus);

        *body_128.data = (*output_body.data).cast_into();

        // compute the multisum between the secret key and the mask
        *body_128.data = (*body_128.data)
            .wrapping_add(slice_wrapping_dot_product_custom_modulus(
                mask_128.as_ref(),
                key_128.as_ref(),
                ciphertext_modulus,
            ))
            .wrapping_rem(ciphertext_modulus);

        *body_128.data = (*body_128.data)
            .wrapping_add(encoded.0.cast_into())
            .wrapping_rem(ciphertext_modulus);

        copy_from_convert(output_mask, &mask_128);

        *output_body.data = (*body_128.data).cast_into();
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
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
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
/// let mut lwe = LweCiphertext::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     CiphertextModulus::new_native(),
/// );
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

    let (mut mask, body) = output.get_mut_mask_and_body();

    fill_lwe_mask_and_body_for_encryption(
        lwe_secret_key,
        &mut mask,
        body,
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
///     CiphertextModulus::new_native(),
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
/// let mut lwe = LweCiphertext::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     CiphertextModulus::new_native(),
/// );
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
    output
        .get_mut_mask()
        .as_mut()
        .iter_mut()
        .for_each(|elt| *elt = Scalar::ZERO);

    let output_modulus = output.ciphertext_modulus();
    let output_body = output.get_mut_body();

    *output_body.data = encoded.0;

    // output_modulus < native modulus always, so we can cast the u128 modulus to the smaller type
    // and compute in the smaller type
    if !output_modulus.is_native_modulus() {
        *output_body.data = (*output_body.data).wrapping_rem(output_modulus.get().cast_into());
    }
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

    let output_modulus = new_ct.ciphertext_modulus();
    let output_body = new_ct.get_mut_body();

    *output_body.data = encoded.0;

    // output_modulus < native modulus always, so we can cast the u128 modulus to the smaller type
    // and compute in the smaller type
    if !output_modulus.is_native_modulus() {
        *output_body.data = (*output_body.data).wrapping_rem(output_modulus.get().cast_into());
    }

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
    assert!(
        lwe_ciphertext.lwe_size().to_lwe_dimension() == lwe_secret_key.lwe_dimension(),
        "Mismatch between LweDimension of output ciphertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        lwe_ciphertext.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let ciphertext_modulus = lwe_ciphertext.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        let (mask, body) = lwe_ciphertext.get_mask_and_body();

        let decrypted_native_plaintext = body.data.wrapping_sub(slice_wrapping_dot_product(
            mask.as_ref(),
            lwe_secret_key.as_ref(),
        ));
        if ciphertext_modulus.is_native_modulus() {
            Plaintext(decrypted_native_plaintext)
        } else {
            // Power of two
            Plaintext(decrypted_native_plaintext.wrapping_rem(ciphertext_modulus.get().cast_into()))
        }
    } else {
        let mut ct_128 = LweCiphertext::new(
            0u128,
            lwe_ciphertext.lwe_size(),
            CiphertextModulus::new_native(),
        );
        let mut key_128 = LweSecretKey::new_empty_key(0u128, lwe_secret_key.lwe_dimension());

        copy_from_convert(&mut key_128, &lwe_secret_key);

        copy_from_convert(&mut ct_128, &lwe_ciphertext);

        let (mask_128, body_128) = ct_128.get_mask_and_body();

        let ciphertext_modulus = lwe_ciphertext.ciphertext_modulus().get();

        let decrypted: Scalar = (*body_128.data)
            .wrapping_sub(slice_wrapping_dot_product_custom_modulus(
                mask_128.as_ref(),
                key_128.as_ref(),
                ciphertext_modulus,
            ))
            .wrapping_rem(ciphertext_modulus)
            .cast_into();

        Plaintext(decrypted)
    }
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
///     CiphertextModulus::new_native(),
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
        )
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
            )
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

    let ciphertext_modulus = output.ciphertext_modulus();

    output.as_mut().fill(Scalar::ZERO);

    let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];

    generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero) in ct_choice.iter().zip(lwe_public_key.iter()) {
        if chosen == Scalar::ONE {
            // Already manages u128, avoids having to convert the pk to u128
            lwe_ciphertext_add_assign(output, &public_encryption_of_zero);
        }
    }

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        // Add encoded plaintext
        let body = output.get_mut_body();
        *body.data = (*body.data).wrapping_add(encoded.0);

        if !ciphertext_modulus.is_native_modulus() {
            *body.data = (*body.data).wrapping_rem(ciphertext_modulus.get().cast_into());
        }
    } else {
        let body = output.get_mut_body();
        let body_u128: u128 = (*body.data).cast_into();

        *body.data = body_u128
            .wrapping_add(encoded.0.cast_into())
            .wrapping_rem(ciphertext_modulus.get())
            .cast_into();
    }
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

    if ciphertext_modulus.is_compatible_with_native_modulus() {
        let mut tmp_ciphertext =
            LweCiphertext::new(Scalar::ZERO, lwe_public_key.lwe_size(), ciphertext_modulus);

        let mut random_generator = RandomGenerator::<ActivatedRandomGenerator>::new(
            lwe_public_key.compression_seed().seed,
        );

        // Add the public encryption of zeros to get the zero encryption
        for (&chosen, public_encryption_of_zero_body) in ct_choice.iter().zip(lwe_public_key.iter())
        {
            let (mut mask, body) = tmp_ciphertext.get_mut_mask_and_body();
            random_generator.fill_slice_with_random_uniform(mask.as_mut());
            *body.data = *public_encryption_of_zero_body.data;

            if chosen == Scalar::ONE {
                lwe_ciphertext_add_assign(output, &tmp_ciphertext);
            }
        }

        // Add encoded plaintext
        let body = output.get_mut_body();
        *body.data = (*body.data).wrapping_add(encoded.0);

        if !ciphertext_modulus.is_native_modulus() {
            *body.data = (*body.data).wrapping_rem(ciphertext_modulus.get().cast_into());
        }
    } else {
        let mut tmp_ciphertext = LweCiphertext::new(
            Scalar::ZERO,
            lwe_public_key.lwe_size(),
            CiphertextModulus::new_native(),
        );

        let mut random_generator = RandomGenerator::<ActivatedRandomGenerator>::new(
            lwe_public_key.compression_seed().seed,
        );

        let mut tmp_ct_128 = LweCiphertext::new(
            0u128,
            lwe_public_key.lwe_size(),
            CiphertextModulus::new_native(),
        );

        let mut output_128 = LweCiphertext::new(
            0u128,
            lwe_public_key.lwe_size(),
            CiphertextModulus::new_native(),
        );

        let ciphertext_modulus = ciphertext_modulus.get();

        // Add the public encryption of zeros to get the zero encryption
        for (&chosen, public_encryption_of_zero_body) in ct_choice.iter().zip(lwe_public_key.iter())
        {
            let (mut mask, body) = tmp_ciphertext.get_mut_mask_and_body();
            random_generator.fill_slice_with_random_uniform(mask.as_mut());
            *body.data = *public_encryption_of_zero_body.data;

            // output_modulus < native modulus always, so we can cast the u128 modulus to the
            // smaller type and compute in the smaller type
            slice_wrapping_rem_assign(tmp_ciphertext.as_mut(), ciphertext_modulus.cast_into());
            copy_from_convert(&mut tmp_ct_128, &tmp_ciphertext);

            if chosen == Scalar::ONE {
                lwe_ciphertext_add_assign(&mut output_128, &tmp_ct_128);
                slice_wrapping_rem_assign(output_128.as_mut(), ciphertext_modulus);
            }
        }

        // Add encoded plaintext
        let output_body_128 = output_128.get_mut_body();
        *output_body_128.data = (*output_body_128.data)
            .wrapping_add(encoded.0.cast_into())
            .wrapping_rem(ciphertext_modulus);

        copy_from_convert(output, &output_128);
    }
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

    for ((output_body, plaintext), mut loop_generator) in
        output.iter_mut().zip(encoded.iter()).zip(gen_iter)
    {
        fill_lwe_mask_and_body_for_encryption(
            lwe_secret_key,
            &mut output_mask,
            output_body,
            plaintext.into(),
            noise_parameters,
            &mut loop_generator,
        )
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
        .for_each(|((output_body, plaintext), mut loop_generator)| {
            let mut output_mask =
                LweMask::from_container(vec![Scalar::ZERO; lwe_dimension.0], ciphertext_modulus);
            fill_lwe_mask_and_body_for_encryption(
                lwe_secret_key,
                &mut output_mask,
                output_body,
                plaintext.into(),
                noise_parameters,
                &mut loop_generator,
            )
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
        output.get_mut_body(),
        encoded,
        noise_parameters,
        generator,
    )
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
///     CiphertextModulus::new_native(),
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
    )
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
///     CiphertextModulus::new_native(),
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

#[cfg(test)]
mod test {
    use crate::core_crypto::commons::generators::{
        DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
    };
    use crate::core_crypto::commons::math::random::ActivatedRandomGenerator;
    use crate::core_crypto::commons::test_tools;
    use crate::core_crypto::prelude::*;

    fn test_parallel_and_seeded_lwe_list_encryption_equivalence<
        Scalar: UnsignedTorus + Sync + Send,
    >() {
        // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
        // computations
        // Define parameters for LweCiphertext creation
        let lwe_dimension = LweDimension(742);
        let lwe_ciphertext_count = LweCiphertextCount(10);
        let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
        let ciphertext_modulus = CiphertextModulus::new_native();
        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let main_seed = seeder.seed();

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        const NB_TESTS: usize = 10;

        for _ in 0..NB_TESTS {
            // Create the LweSecretKey
            let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut secret_generator,
            );
            // Create the plaintext
            let msg: Scalar = test_tools::random_uint_between(Scalar::ZERO..Scalar::TWO.shl(2));
            let encoded_msg = msg << (Scalar::BITS - 5);
            let plaintext_list =
                PlaintextList::new(encoded_msg, PlaintextCount(lwe_ciphertext_count.0));
            // Create a new LweCiphertextList
            let mut par_lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                lwe_ciphertext_count,
                ciphertext_modulus,
            );

            let mut determinisitic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);
            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    determinisitic_seeder.seed(),
                    &mut determinisitic_seeder,
                );
            par_encrypt_lwe_ciphertext_list(
                &lwe_secret_key,
                &mut par_lwe_list,
                &plaintext_list,
                lwe_modular_std_dev,
                &mut encryption_generator,
            );

            let mut ser_lwe_list = LweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                lwe_ciphertext_count,
                ciphertext_modulus,
            );

            let mut determinisitic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);
            let mut encryption_generator =
                EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                    determinisitic_seeder.seed(),
                    &mut determinisitic_seeder,
                );
            encrypt_lwe_ciphertext_list(
                &lwe_secret_key,
                &mut ser_lwe_list,
                &plaintext_list,
                lwe_modular_std_dev,
                &mut encryption_generator,
            );

            assert_eq!(par_lwe_list, ser_lwe_list);

            let mut determinisitic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);
            // Create a new LweCiphertextList
            let mut par_seeded_lwe_list = SeededLweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                lwe_ciphertext_count,
                determinisitic_seeder.seed().into(),
                ciphertext_modulus,
            );

            par_encrypt_seeded_lwe_ciphertext_list(
                &lwe_secret_key,
                &mut par_seeded_lwe_list,
                &plaintext_list,
                lwe_modular_std_dev,
                &mut determinisitic_seeder,
            );

            let mut determinisitic_seeder =
                DeterministicSeeder::<ActivatedRandomGenerator>::new(main_seed);

            let mut ser_seeded_lwe_list = SeededLweCiphertextList::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                lwe_ciphertext_count,
                determinisitic_seeder.seed().into(),
                ciphertext_modulus,
            );

            encrypt_seeded_lwe_ciphertext_list(
                &lwe_secret_key,
                &mut ser_seeded_lwe_list,
                &plaintext_list,
                lwe_modular_std_dev,
                &mut determinisitic_seeder,
            );

            assert_eq!(par_seeded_lwe_list, ser_seeded_lwe_list);

            let decompressed_lwe_list = ser_seeded_lwe_list.decompress_into_lwe_ciphertext_list();

            assert_eq!(decompressed_lwe_list, ser_lwe_list);
        }
    }

    #[test]
    fn test_parallel_and_seeded_lwe_list_encryption_equivalence_u32() {
        test_parallel_and_seeded_lwe_list_encryption_equivalence::<u32>();
    }

    #[test]
    fn test_parallel_and_seeded_lwe_list_encryption_equivalence_u64() {
        test_parallel_and_seeded_lwe_list_encryption_equivalence::<u64>();
    }

    #[test]
    fn test_u128_encryption() {
        // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
        // computations
        // Define parameters for LweCiphertext creation
        let lwe_dimension = LweDimension(742);
        let lwe_modular_std_dev = StandardDev(4.998_277_131_225_527e-11);
        let ciphertext_modulus = CiphertextModulus::new_native();

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        const NB_TESTS: usize = 10;
        const MSG_BITS: u32 = 4;

        for _ in 0..NB_TESTS {
            for msg in 0..2u128.pow(MSG_BITS) {
                // Create the LweSecretKey
                let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
                    lwe_dimension,
                    &mut secret_generator,
                );

                // Create the plaintext
                const ENCODING: u32 = u128::BITS - MSG_BITS;
                let plaintext = Plaintext(msg << ENCODING);

                // Create a new LweCiphertext
                let mut lwe =
                    LweCiphertext::new(0u128, lwe_dimension.to_lwe_size(), ciphertext_modulus);

                encrypt_lwe_ciphertext(
                    &lwe_secret_key,
                    &mut lwe,
                    plaintext,
                    lwe_modular_std_dev,
                    &mut encryption_generator,
                );

                let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

                // Round and remove encoding
                // First create a decomposer working on the high 4 bits corresponding to our
                // encoding.
                let decomposer =
                    SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));

                let rounded = decomposer.closest_representable(decrypted_plaintext.0);

                // Remove the encoding
                let cleartext = rounded >> ENCODING;

                // Check we recovered the original message
                assert_eq!(cleartext, msg);
            }
        }
    }
}
