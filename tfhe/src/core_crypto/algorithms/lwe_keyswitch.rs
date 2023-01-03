use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Keyswitch an [`LWE ciphertext`](`LweCiphertext`) encrytped under an
/// [`LWE secret key`](`LweSecretKey`) to another [`LWE secret key`](`LweSecretKey`).
///
/// # Formal Definition
///
/// ## LWE Keyswitch
///
/// This homomorphic procedure transforms an input
/// [`LWE ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
/// $\mathsf{ct}\_{\mathsf{in}} =
/// \left( \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in \mathsf{LWE}^{n\_{\mathsf{in}}}\_
/// {\vec{s}\_{\mathsf{in}}}( \mathsf{pt} ) \subseteq \mathbb{Z}\_q^{(n\_{\mathsf{in}}+1)}$ into an
/// output [`LWE ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
/// $\mathsf{ct}\_{\mathsf{out}} =
/// \left( \vec{a}\_{\mathsf{out}} , b\_{\mathsf{out}}\right) \in
/// \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}( \mathsf{pt} )\subseteq
/// \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$ where $n\_{\mathsf{in}} = |\vec{s}\_{\mathsf{in}}|$ and
/// $n\_{\mathsf{out}} = |\vec{s}\_{\mathsf{out}}|$. It requires a
/// [`key switching key`](`crate::core_crypto::entities::LweKeyswitchKey`).
/// The input ciphertext is encrypted under the
/// [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{in}}$ and the output ciphertext is
/// encrypted under the [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{out}}$.
///
/// $$\mathsf{ct}\_{\mathsf{in}} \in \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}(
/// \mathsf{pt} ) ~~~~~~~~~~\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow
/// \vec{s}\_{\mathsf{out}}}$$ $$ \mathsf{keyswitch}\left(\mathsf{ct}\_{\mathsf{in}} , \mathsf{KSK}
/// \right) \rightarrow \mathsf{ct}\_{\mathsf{out}} \in
/// \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}} \left( \mathsf{pt} \right)$$
///
/// ## Algorithm
/// ###### inputs:
/// - $\mathsf{ct}\_{\mathsf{in}} = \left( \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in
///   \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}( \mathsf{pt} )$: an [`LWE
///   ciphertext`](`LweCiphertext`) with $\vec{a}\_{\mathsf{in}}=\left(a\_0, \cdots
///   a\_{n\_{\mathsf{in}}-1}\right)$
/// - $\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{s}\_{\mathsf{out}}}$: a
/// [`key switching key`](`crate::core_crypto::entities::LweKeyswitchKey`)
///
/// ###### outputs:
/// - $\mathsf{ct}\_{\mathsf{out}} \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}
///   \left( \mathsf{pt} \right)$: an
/// [`LWE ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
///
/// ###### algorithm:
/// 1. set $\mathsf{ct}=\left( 0 , \cdots , 0 ,  b\_{\mathsf{in}} \right) \in
/// \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$
/// 2. compute $\mathsf{ct}\_{\mathsf{out}} = \mathsf{ct} -
/// \sum\_{i=0}^{n\_{\mathsf{in}}-1} \mathsf{decompProduct}\left( a\_i , \overline{\mathsf{ct}\_i}
/// \right)$
/// 3. output $\mathsf{ct}\_{\mathsf{out}}$
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
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweCiphertext creation
/// let input_lwe_dimension = LweDimension(742);
/// let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
/// let output_lwe_dimension = LweDimension(2048);
/// let decomp_base_log = DecompositionBaseLog(3);
/// let decomp_level_count = DecompositionLevelCount(5);
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
///     lwe_modular_std_dev,
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
///     &mut encryption_generator,
/// );
///
/// let mut output_lwe = LweCiphertext::new(0, output_lwe_secret_key.lwe_dimension().to_lwe_size());
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

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    *output_lwe_ciphertext.get_mut_body().0 = *input_lwe_ciphertext.get_body().0;

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
        // loop over the number of levels in reverse (from highest to lowest)
        for (level_key_ciphertext, decomposed) in
            keyswitch_key_block.iter().rev().zip(decomposition_iter)
        {
            slice_wrapping_sub_scalar_mul_assign(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.value(),
            );
        }
    }
}
