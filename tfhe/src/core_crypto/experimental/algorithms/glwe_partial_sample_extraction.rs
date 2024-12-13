//! Module containing primitives pertaining to the operation usually referred to as a
//! _sample extract_ in the literature. Allowing to extract a single
//! [`LWE Ciphertext`](`LweCiphertext`) from a given [`GLWE ciphertext`](`GlweCiphertext`).

use crate::core_crypto::commons::parameters::MonomialDegree;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Extract the nth coefficient from the body of a [`GLWE Ciphertext`](`GlweCiphertext`) encrypted
/// under a partial [`GLWE secret key`](`GlweSecretKey`). as an [`LWE ciphertext`](`LweCiphertext`).
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::experimental::prelude::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(8);
/// let glwe_noise_distribution =
///     DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.881784197001252e-16));
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let phi = PartialGlweSecretKeyRandomCoefCount(
///     glwe_size.to_glwe_dimension().0 * polynomial_size.0 - 4,
/// );
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_partial_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     phi,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// let special_value = 15;
/// *plaintext_list.get_mut(0).0 = 15 << 60;
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
/// // Now we get the equivalent LweSecretKey from the GlweSecretKey
/// let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();
///
/// let mut extracted_sample = LweCiphertext::new(
///     0u64,
///     equivalent_lwe_sk.lwe_dimension().to_lwe_size(),
///     ciphertext_modulus,
/// );
///
/// partial_extract_lwe_sample_from_glwe_ciphertext(
///     &glwe,
///     &mut extracted_sample,
///     MonomialDegree(0),
///     phi.0,
/// );
///
/// let decrypted_plaintext = decrypt_lwe_ciphertext(&equivalent_lwe_sk, &extracted_sample);
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let recovered_message = decomposer.closest_representable(decrypted_plaintext.0) >> 60;
///
/// // We check we recover our special value instead of the 3 stored in all other slots of the
/// // GlweCiphertext
/// assert_eq!(special_value, recovered_message);
/// ```
pub fn partial_extract_lwe_sample_from_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_glwe: &GlweCiphertext<InputCont>,
    output_lwe: &mut LweCiphertext<OutputCont>,
    nth: MonomialDegree,
    phi: usize,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let input_equivalent_lwe_dimension = input_glwe
        .glwe_size()
        .to_glwe_dimension()
        .to_equivalent_lwe_dimension(input_glwe.polynomial_size());
    let output_lwe_dimension = output_lwe.lwe_size().to_lwe_dimension();
    assert!(
        phi <= input_equivalent_lwe_dimension.0,
        "The secret key shared coefficient count phi needs to be smaller than the equivalent \
        input LweDimension. Got {:?} for phi and {:?} for the input LweDimension.",
        phi,
        input_equivalent_lwe_dimension.0,
    );

    assert!(
        phi <= output_lwe_dimension.0,
        "The secret key shared coefficient count phi needs to be smaller than the equivalent \
        output LweDimension. Got {:?} for phi and {:?} for the output LweDimension.",
        phi,
        output_lwe_dimension.0,
    );

    assert_eq!(
        input_glwe.ciphertext_modulus(),
        output_lwe.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe.ciphertext_modulus(),
        output_lwe.ciphertext_modulus()
    );

    output_lwe.as_mut().fill(Scalar::ZERO);

    // We retrieve the bodies and masks of the two ciphertexts.
    let (mut lwe_mask, lwe_body) = output_lwe.get_mut_mask_and_body();
    let (glwe_mask, glwe_body) = input_glwe.get_mask_and_body();
    // We copy the body
    *lwe_body.data = glwe_body.as_ref()[nth.0];

    // We copy the mask (each polynomial is in the wrong order)
    lwe_mask.as_mut()[0..phi].copy_from_slice(&glwe_mask.as_ref()[0..phi]);

    let big_n = input_glwe.polynomial_size().0;
    for i in 0..phi {
        let alpha = i / big_n;
        let beta = big_n.wrapping_sub(i) % big_n;
        lwe_mask.as_mut()[i] = glwe_mask.as_polynomial_list().get(alpha)[beta];
        if beta != 0 {
            lwe_mask.as_mut()[i] = lwe_mask.as_mut()[i].wrapping_neg()
        }
    }
}

/// This operation does the opposite of
/// [`extract_lwe_sample_from_glwe_ciphertext`](`crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext`)
/// and inserts the body of [`an LWE ciphertext`](`LweCiphertext`) in the first coefficient of
/// [`a GLWE ciphertext`](`GlweCiphertext`) and fills the mask to have a valid GLWE ciphertext. The
/// rest of the mask and body are filled with zeros.
///
/// For an `input_lwe` encrypted under [`an LWE secret
/// key`](`crate::core_crypto::entities::LweSecretKey`) that shares `phi` coefficients with [`an
/// output GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`), it only requires on the
/// order of `phi` computations instead of `k * N` computations where `phi` is smaller than `k * N`
/// (hence the partial name). The `output_glwe` can be decrypted with the output GLWE secret key
/// which shares parts of its coefficients with the input LWE secret key.
///
/// ```
/// use tfhe::core_crypto::experimental::prelude::*;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(8);
/// let lwe_dimension = LweDimension(glwe_size.to_glwe_dimension().0 * polynomial_size.0);
/// let lwe_noise_distribution =
///     DynamicDistribution::new_gaussian_from_std_dev(StandardDev(8.881784197001252e-16));
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let phi = PartialGlweSecretKeyRandomCoefCount(2);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_partial_binary_glwe_secret_key(
///     glwe_size.to_glwe_dimension(),
///     polynomial_size,
///     phi,
///     &mut secret_generator,
/// );
///
/// let lwe_secret_key = glwe_secret_key.clone().into_lwe_secret_key();
///
/// // Create the plaintext
/// let msg = 3u64;
/// let encoded_msg = msg << 60;
/// let mut plaintext = Plaintext(encoded_msg);
///
/// // Create a new LweCiphertext
/// let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);
///
/// let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);
///
/// encrypt_lwe_ciphertext(
///     &lwe_secret_key,
///     &mut lwe,
///     plaintext,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// partial_convert_lwe_ciphertext_into_constant_glwe_ciphertext(&lwe, &mut glwe, phi.0);
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(&glwe_secret_key, &glwe, &mut output_plaintext_list);
///
/// let decrypted_plaintext = output_plaintext_list.into_container()[0];
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// let recovered_message = decomposer.closest_representable(decrypted_plaintext) >> 60;
///
/// // We check we recover our special value instead of the 3 stored in all other slots of the
/// // GlweCiphertext
/// assert_eq!(msg, recovered_message);
/// ```
pub fn partial_convert_lwe_ciphertext_into_constant_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_lwe: &LweCiphertext<InputCont>,
    output_glwe: &mut GlweCiphertext<OutputCont>,
    phi: usize,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(phi <= input_lwe.lwe_size().to_lwe_dimension().0);
    assert!(phi <= output_glwe.get_mask().as_ref().len());

    // B' is set to the LWE body only so the rest of the mask should be zeroed out
    // if the index is greater than the shared dimension then the mask element is zeroed out as well
    // So clear the output once and then run the algorithm
    output_glwe.as_mut().fill(Scalar::ZERO);

    let big_n = output_glwe.polynomial_size().0;

    // We retrieve the bodies and masks of the two ciphertexts.
    let (lwe_mask, lwe_body) = input_lwe.get_mask_and_body();
    let (mut glwe_mask, mut glwe_body) = output_glwe.get_mut_mask_and_body();

    // We copy the body
    glwe_body.as_mut()[0] = *lwe_body.data;

    let glwe_mask_slice = glwe_mask.as_mut();

    for (i, &lwe_mask_element) in lwe_mask.as_ref()[..phi].iter().enumerate() {
        // alpha = index of the current polynomial being considered
        let alpha = i / big_n;
        // beta = index in the polynomial = 0 if i is the first element of the output polynomial
        // otherwise the end of the polynomial is reversed and negated
        // Example with N = 512
        // LWE:  | 0 1    ... 511 | 512  513  ...  1023| ...
        //         |           |
        //         |   ________|
        //         v   |
        // GLWE: | 0 -511 ...  -1 | 512 -1023 ... -513 | ...
        let beta = big_n.wrapping_sub(i) % big_n;
        if beta != 0 {
            glwe_mask_slice[alpha * big_n + beta] = lwe_mask_element.wrapping_neg();
        } else {
            glwe_mask_slice[alpha * big_n + beta] = lwe_mask_element;
        }
    }
}
