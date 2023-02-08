//! Module containing primitives pertaining to the operation usually referred to as a
//! _sample extract_ in the literature. Allowing to extract a single
//! [`LWE Ciphertext`](`LweCiphertext`) from a given [`GLWE ciphertext`](`GlweCiphertext`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{MonomialDegree, *};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Extract the nth coefficient from the body of a [`GLWE Ciphertext`](`GlweCiphertext`) as an
/// [`LWE ciphertext`](`LweCiphertext`).
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GlweCiphertext creation
/// let glwe_size = GlweSize(2);
/// let polynomial_size = PolynomialSize(1024);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
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
/// let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// let special_value = 15;
/// *plaintext_list.get_mut(42).0 = 15 << 60;
///
/// // Create a new GlweCiphertext
/// let mut glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size);
///
/// encrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &mut glwe,
///     &plaintext_list,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// // Now we get the equivalent LweSecretKey from the GlweSecretKey
/// let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();
///
/// let mut extracted_sample =
///     LweCiphertext::new(0u64, equivalent_lwe_sk.lwe_dimension().to_lwe_size());
///
/// // Here we chose to extract sample at index 42 (corresponding to the MonomialDegree(42))
/// extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut extracted_sample, MonomialDegree(42));
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
pub fn extract_lwe_sample_from_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_glwe: &GlweCiphertext<InputCont>,
    output_lwe: &mut LweCiphertext<OutputCont>,
    nth: MonomialDegree,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_glwe.glwe_size().to_glwe_dimension().0 * input_glwe.polynomial_size().0
            == output_lwe.lwe_size().to_lwe_dimension().0,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {:?} for input and {:?} for output.",
        LweDimension(input_glwe.glwe_size().to_glwe_dimension().0 * input_glwe.polynomial_size().0),
        output_lwe.lwe_size().to_lwe_dimension(),
    );

    // We retrieve the bodies and masks of the two ciphertexts.
    let (mut lwe_mask, lwe_body) = output_lwe.get_mut_mask_and_body();
    let (glwe_mask, glwe_body) = input_glwe.get_mask_and_body();

    // We copy the body
    *lwe_body.0 = glwe_body.as_ref()[nth.0];

    // We copy the mask (each polynomial is in the wrong order)
    lwe_mask.as_mut().copy_from_slice(glwe_mask.as_ref());

    // We compute the number of elements which must be
    // turned into their opposite
    let opposite_count = input_glwe.polynomial_size().0 - nth.0 - 1;

    // We loop through the polynomials
    for lwe_mask_poly in lwe_mask
        .as_mut()
        .chunks_exact_mut(input_glwe.polynomial_size().0)
    {
        // We reverse the polynomial
        lwe_mask_poly.reverse();
        // We compute the opposite of the proper coefficients
        slice_wrapping_opposite_assign(&mut lwe_mask_poly[0..opposite_count]);
        // We rotate the polynomial properly
        lwe_mask_poly.rotate_left(opposite_count);
    }
}
