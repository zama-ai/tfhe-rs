//! Module containing functions related to LWE ciphertext encryption and decryption

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Encrypt an input plaintext in an output [`LWE ciphertext`](`LweCiphertext`).
///
/// # Formal Definition
///
/// ## LWE Encryption
/// ###### inputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean $\mu$
///
/// ###### outputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
///
/// ###### algorithm:
/// 1. uniformly sample a vector $\vec{a}\in\mathbb{Z}\_q^n$
/// 2. sample an integer error term $e \hookleftarrow \mathcal{D\_{\sigma^2,\mu}}$
/// 3. compute $b = \left\langle \vec{a} , \vec{s} \right\rangle + \mathsf{pt} + e \in\mathbb{Z}\_q$
/// 4. output $\left( \vec{a} , b\right)$
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let mut seeder = seeder.as_mut();
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
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size());
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
        "Mismatch between LweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mut mask, body) = output.get_mut_mask_and_body();

    generator.fill_slice_with_random_mask(mask.as_mut());

    // generate an error from the normal distribution described by std_dev
    *body.0 = generator.random_noise(noise_parameters);

    // compute the multisum between the secret key and the mask
    *body.0 = (*body.0).wrapping_add(slice_wrapping_dot_product(
        mask.as_ref(),
        lwe_secret_key.as_ref(),
    ));

    *body.0 = (*body.0).wrapping_add(encoded.0);
}

/// Allocate a new [`LWE ciphertext`](`LweCiphertext`) and encrypt an input plaintext in it.
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let mut seeder = seeder.as_mut();
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
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_ct =
        LweCiphertextOwned::new(Scalar::ZERO, lwe_secret_key.lwe_dimension().to_lwe_size());

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
/// use tfhe::core_crypto::commons::generators::SecretRandomGenerator;
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let mut seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size());
///
/// trivially_encrypt_lwe_ciphertext(&mut lwe, plaintext);
///
/// // Here we show the content of the trivial encryption is actually the input data in clear and
/// // that the mask is full of 0s
/// assert_eq!(*lwe.get_body().0, plaintext.0);
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
/// assert_eq!(decrypted_plaintext.0, *lwe.get_body().0);
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

    *output.get_mut_body().0 = encoded.0
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
/// use tfhe::core_crypto::commons::generators::SecretRandomGenerator;
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let mut seeder = seeder.as_mut();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe =
///     allocate_and_trivially_encrypt_new_lwe_ciphertext(lwe_dimension.to_lwe_size(), plaintext);
///
/// // Here we show the content of the trivial encryption is actually the input data in clear and
/// // that the mask is full of 0s
/// assert_eq!(*lwe.get_body().0, plaintext.0);
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
/// assert_eq!(decrypted_plaintext.0, *lwe.get_body().0);
/// ```
pub fn allocate_and_trivially_encrypt_new_lwe_ciphertext<Scalar>(
    lwe_size: LweSize,
    encoded: Plaintext<Scalar>,
) -> LweCiphertextOwned<Scalar>
where
    Scalar: UnsignedTorus,
{
    let mut new_ct = LweCiphertextOwned::new(Scalar::ZERO, lwe_size);

    *new_ct.get_mut_body().0 = encoded.0;

    new_ct
}

/// Decrypt an [`LWE ciphertext`](`LweCiphertext`) and return a noisy plaintext.
///
/// See [`encrypt_lwe_ciphertext`] for usage.
///
/// # Formal Definition
///
/// ## LWE Decryption
/// ###### inputs:
/// - $\mathsf{ct} = \left( \vec{a} , b\right) \in \mathsf{LWE}^n\_{\vec{s}}( \mathsf{pt} )\subseteq
///   \mathbb{Z}\_q^{(n+1)}$: an LWE ciphertext
/// - $\vec{s}\in\mathbb{Z}\_q^n$: a secret key
///
/// ###### outputs:
/// - $\mathsf{pt}\in\mathbb{Z}\_q$: a plaintext
///
/// ###### algorithm:
/// 1. compute $\mathsf{pt} = b - \left\langle \vec{a} , \vec{s} \right\rangle \in\mathbb{Z}\_q$
/// 2. output $\mathsf{pt}$
///
/// **Remark:** Observe that the decryption is followed by a decoding phase that will contain a
/// rounding.
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
        "Mismatch between LweDimension of output cipertext and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        lwe_ciphertext.lwe_size().to_lwe_dimension(),
        lwe_secret_key.lwe_dimension()
    );

    let (mask, body) = lwe_ciphertext.get_mask_and_body();

    Plaintext(body.0.wrapping_sub(slice_wrapping_dot_product(
        mask.as_ref(),
        lwe_secret_key.as_ref(),
    )))
}

/// Encrypt an input plaintext list in an output [`LWE ciphertext list`](`LweCiphertextList`).
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
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
/// let mut seeder = seeder.as_mut();
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
/// // Create a new LweCiphertext
/// let mut lwe_list =
///     LweCiphertextList::new(0u64, lwe_dimension.to_lwe_size(), lwe_ciphertext_count);
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
        "Mismatch between number of output cipertexts and input plaintexts. \
        Got {:?} plaintexts, and {:?} ciphertext.",
        encoded.plaintext_count(),
        output.lwe_ciphertext_count()
    );

    for (encoded_plaintext_ref, mut ciphertext) in encoded.iter().zip(output.iter_mut()) {
        encrypt_lwe_ciphertext(
            lwe_secret_key,
            &mut ciphertext,
            encoded_plaintext_ref.into(),
            noise_parameters,
            generator,
        )
    }
}

/// Parallel variant of [`encrypt_lwe_ciphertext_list`].
///
/// See this [`formal definition`](`encrypt_lwe_ciphertext#formal-definition`) for the definition
/// of the LWE encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
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
/// let mut seeder = seeder.as_mut();
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
/// // Create a new LweCiphertext
/// let mut lwe_list =
///     LweCiphertextList::new(0u64, lwe_dimension.to_lwe_size(), lwe_ciphertext_count);
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
        "Mismatch between number of output cipertexts and input plaintexts. \
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
/// use tfhe::core_crypto::commons::generators::{
///     EncryptionRandomGenerator, SecretRandomGenerator,
/// };
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposer;
/// use tfhe::core_crypto::commons::math::random::ActivatedRandomGenerator;
/// use tfhe::core_crypto::prelude::*;
/// use tfhe::seeders::new_seeder;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let zero_encryption_count =
///     LwePublicKeyZeroEncryptionCount(lwe_dimension.to_lwe_size().0 * 64 + 128);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let mut seeder = seeder.as_mut();
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
///     &mut encryption_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let plaintext = Plaintext(msg << 60);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size());
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
    assert!(
        output.lwe_size().to_lwe_dimension() == lwe_public_key.lwe_size().to_lwe_dimension(),
        "Mismatch between LweDimension of output cipertext and input public key. \
        Got {:?} in output, and {:?} in public key.",
        output.lwe_size().to_lwe_dimension(),
        lwe_public_key.lwe_size().to_lwe_dimension()
    );

    output.as_mut().fill(Scalar::ZERO);

    let mut ct_choice = vec![Scalar::ZERO; lwe_public_key.zero_encryption_count().0];

    generator.fill_slice_with_random_uniform_binary(&mut ct_choice);

    // Add the public encryption of zeros to get the zero encryption
    for (&chosen, public_encryption_of_zero) in ct_choice.iter().zip(lwe_public_key.iter()) {
        if chosen == Scalar::ONE {
            lwe_ciphertext_addition_assign(output, &public_encryption_of_zero);
        }
    }

    // Add encoded plaintext
    let body = output.get_mut_body();
    *body.0 = (*body.0).wrapping_add(encoded.0);
}
