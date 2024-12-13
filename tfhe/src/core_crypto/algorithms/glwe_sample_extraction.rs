//! Module containing primitives pertaining to the operation usually referred to as a
//! _sample extract_ in the literature. Allowing to extract a single
//! [`LWE Ciphertext`](`LweCiphertext`) from a given [`GLWE ciphertext`](`GlweCiphertext`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Extract the nth coefficient from the body of a [`GLWE Ciphertext`](`GlweCiphertext`) as an
/// [`LWE ciphertext`](`LweCiphertext`).
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
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
/// let mut plaintext_list = PlaintextList::new(encoded_msg, PlaintextCount(polynomial_size.0));
///
/// let special_value = 15;
/// *plaintext_list.get_mut(42).0 = 15 << 60;
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
    let in_lwe_dim = input_glwe
        .glwe_size()
        .to_glwe_dimension()
        .to_equivalent_lwe_dimension(input_glwe.polynomial_size());

    let out_lwe_dim = output_lwe.lwe_size().to_lwe_dimension();

    assert_eq!(
        in_lwe_dim, out_lwe_dim,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {in_lwe_dim:?} for input and {out_lwe_dim:?} for output.",
    );

    assert_eq!(
        input_glwe.ciphertext_modulus(),
        output_lwe.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe.ciphertext_modulus(),
        output_lwe.ciphertext_modulus()
    );

    // We retrieve the bodies and masks of the two ciphertexts.
    let (mut lwe_mask, lwe_body) = output_lwe.get_mut_mask_and_body();
    let (glwe_mask, glwe_body) = input_glwe.get_mask_and_body();

    // We copy the body
    *lwe_body.data = glwe_body.as_ref()[nth.0];

    // We copy the mask (each polynomial is in the wrong order)
    lwe_mask.as_mut().copy_from_slice(glwe_mask.as_ref());

    // We compute the number of elements which must be
    // turned into their opposite
    let opposite_count = input_glwe.polynomial_size().0 - nth.0 - 1;
    let ciphertext_modulus = input_glwe.ciphertext_modulus();

    if ciphertext_modulus.is_compatible_with_native_modulus() {
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
    } else {
        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
        // We loop through the polynomials
        for lwe_mask_poly in lwe_mask
            .as_mut()
            .chunks_exact_mut(input_glwe.polynomial_size().0)
        {
            // We reverse the polynomial
            lwe_mask_poly.reverse();
            // We compute the opposite of the proper coefficients
            slice_wrapping_opposite_assign_custom_mod(
                &mut lwe_mask_poly[0..opposite_count],
                modulus,
            );
            // We rotate the polynomial properly
            lwe_mask_poly.rotate_left(opposite_count);
        }
    }
}

/// Parallel variant of [`extract_lwe_sample_from_glwe_ciphertext`] performing a sample extract on
/// all coefficients from a [`GlweCiphertext`] in an output [`LweCiphertextList`].
///
/// This will use all threads available in the current rayon thread pool.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
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
/// // Now we get the equivalent LweSecretKey from the GlweSecretKey
/// let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();
///
/// let mut extracted_samples = LweCiphertextList::new(
///     0u64,
///     equivalent_lwe_sk.lwe_dimension().to_lwe_size(),
///     LweCiphertextCount(glwe.polynomial_size().0),
///     ciphertext_modulus,
/// );
///
/// // Use all threads available in the current rayon thread pool
/// par_extract_lwe_sample_from_glwe_ciphertext(&glwe, &mut extracted_samples);
///
/// let mut output_plaintext_list = PlaintextList::new(
///     0u64,
///     PlaintextCount(extracted_samples.lwe_ciphertext_count().0),
/// );
///
/// decrypt_lwe_ciphertext_list(
///     &equivalent_lwe_sk,
///     &extracted_samples,
///     &mut output_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // We check we recover our msg stored in all slots of the GlweCiphertext
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == msg));
/// ```
pub fn par_extract_lwe_sample_from_glwe_ciphertext<Scalar, InputCont, OutputCont>(
    input_glwe: &GlweCiphertext<InputCont>,
    output_lwe_list: &mut LweCiphertextList<OutputCont>,
) where
    Scalar: UnsignedInteger + Send + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let thread_count = ThreadCount(rayon::current_num_threads());
    par_extract_lwe_sample_from_glwe_ciphertext_with_thread_count(
        input_glwe,
        output_lwe_list,
        thread_count,
    );
}

/// Parallel variant of [`extract_lwe_sample_from_glwe_ciphertext`] performing a sample extract on
/// all coefficients from a [`GlweCiphertext`] in an output [`LweCiphertextList`].
///
/// This will try to use `thread_count` threads for the computation, if this number is bigger than
/// the available number of threads in the current rayon thread pool then only the number of
/// available threads will be used. Note that `thread_count` cannot be 0.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
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
/// // Now we get the equivalent LweSecretKey from the GlweSecretKey
/// let equivalent_lwe_sk = glwe_secret_key.clone().into_lwe_secret_key();
///
/// let mut extracted_samples = LweCiphertextList::new(
///     0u64,
///     equivalent_lwe_sk.lwe_dimension().to_lwe_size(),
///     LweCiphertextCount(glwe.polynomial_size().0),
///     ciphertext_modulus,
/// );
///
/// // Try to use 4 threads for the keyswitch if enough are available
/// // in the current rayon thread pool
/// par_extract_lwe_sample_from_glwe_ciphertext_with_thread_count(
///     &glwe,
///     &mut extracted_samples,
///     ThreadCount(4),
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(
///     0u64,
///     PlaintextCount(extracted_samples.lwe_ciphertext_count().0),
/// );
///
/// decrypt_lwe_ciphertext_list(
///     &equivalent_lwe_sk,
///     &extracted_samples,
///     &mut output_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
///
/// output_plaintext_list
///     .iter_mut()
///     .for_each(|x| *x.0 = decomposer.closest_representable(*x.0) >> 60);
///
/// // We check we recover our msg stored in all slots of the GlweCiphertext
/// assert!(output_plaintext_list.iter().all(|x| *x.0 == msg));
/// ```
pub fn par_extract_lwe_sample_from_glwe_ciphertext_with_thread_count<
    Scalar,
    InputCont,
    OutputCont,
>(
    input_glwe: &GlweCiphertext<InputCont>,
    output_lwe_list: &mut LweCiphertextList<OutputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
    InputCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let in_lwe_dim = input_glwe
        .glwe_size()
        .to_glwe_dimension()
        .to_equivalent_lwe_dimension(input_glwe.polynomial_size());

    let out_lwe_dim = output_lwe_list.lwe_size().to_lwe_dimension();

    assert_eq!(
        in_lwe_dim, out_lwe_dim,
        "Mismatch between equivalent LweDimension of input ciphertext and output ciphertext. \
        Got {in_lwe_dim:?} for input and {out_lwe_dim:?} for output.",
    );

    assert!(
        input_glwe.polynomial_size().0 <= output_lwe_list.lwe_ciphertext_count().0,
        "The output LweCiphertextList does not have enough space ({:?}) \
    to extract all input GlweCiphertext coefficients ({})",
        output_lwe_list.lwe_ciphertext_count(),
        input_glwe.polynomial_size().0
    );

    assert_eq!(
        input_glwe.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus(),
        "Mismatched moduli between input_glwe ({:?}) and output_lwe ({:?})",
        input_glwe.ciphertext_modulus(),
        output_lwe_list.ciphertext_modulus()
    );

    let polynomial_size = input_glwe.polynomial_size();
    let (glwe_mask, glwe_body) = input_glwe.get_mask_and_body();

    let thread_count = thread_count.0.min(rayon::current_num_threads());
    let chunk_size = polynomial_size.0.div_ceil(thread_count);

    glwe_body
        .as_ref()
        .par_chunks(chunk_size)
        .zip(output_lwe_list.par_chunks_mut(chunk_size))
        .enumerate()
        .for_each(
            |(chunk_idx, (glwe_body_chunk, mut output_lwe_list_chunk))| {
                for (coeff_idx, (glwe_coeff, mut output_lwe)) in glwe_body_chunk
                    .iter()
                    .zip(output_lwe_list_chunk.iter_mut())
                    .enumerate()
                {
                    let nth = chunk_idx * chunk_size + coeff_idx;

                    let (mut lwe_mask, lwe_body) = output_lwe.get_mut_mask_and_body();

                    // We copy the body
                    *lwe_body.data = *glwe_coeff;

                    // We copy the mask (each polynomial is in the wrong order)
                    lwe_mask.as_mut().copy_from_slice(glwe_mask.as_ref());

                    // We compute the number of elements which must be
                    // turned into their opposite
                    let opposite_count = input_glwe.polynomial_size().0 - nth - 1;
                    let ciphertext_modulus = input_glwe.ciphertext_modulus();

                    if ciphertext_modulus.is_compatible_with_native_modulus() {
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
                    } else {
                        let modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
                        // We loop through the polynomials
                        for lwe_mask_poly in lwe_mask
                            .as_mut()
                            .chunks_exact_mut(input_glwe.polynomial_size().0)
                        {
                            // We reverse the polynomial
                            lwe_mask_poly.reverse();
                            // We compute the opposite of the proper coefficients
                            slice_wrapping_opposite_assign_custom_mod(
                                &mut lwe_mask_poly[0..opposite_count],
                                modulus,
                            );
                            // We rotate the polynomial properly
                            lwe_mask_poly.rotate_left(opposite_count);
                        }
                    }
                }
            },
        );
}
