//! Module containing primitives pertaining to [`LWE ciphertext
//! keyswitch`](`CmLweKeyswitchKey#lwe-keyswitch`).

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::ThreadCount;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use itertools::Itertools;
use rayon::prelude::*;

/// Keyswitch an [`CM LWE ciphertext`](`CmLweCiphertext`) encrypted under an
/// [`LWE secret key`](`LweSecretKey`) to another [`LWE secret key`](`LweSecretKey`).
///
/// # Formal Definition
///
/// See [`LWE keyswitch key`](`CmLweKeyswitchKey#lwe-keyswitch`).
pub fn cm_keyswitch_lwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    cm_lwe_keyswitch_key: &CmLweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &CmLweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut CmLweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        cm_lwe_keyswitch_key.input_lwe_dimension() == input_lwe_ciphertext.lwe_dimension(),
        "Mismatched input LweDimension. \
        CmLweKeyswitchKey input LweDimension: {:?}, input CmLweCiphertext LweDimension {:?}.",
        cm_lwe_keyswitch_key.input_lwe_dimension(),
        input_lwe_ciphertext.lwe_dimension(),
    );
    assert!(
        cm_lwe_keyswitch_key.output_lwe_dimension() == output_lwe_ciphertext.lwe_dimension(),
        "Mismatched output LweDimension. \
        CmLweKeyswitchKey output LweDimension: {:?}, output CmLweCiphertext LweDimension {:?}.",
        cm_lwe_keyswitch_key.output_lwe_dimension(),
        output_lwe_ciphertext.lwe_dimension(),
    );

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        cm_lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        CmLweKeyswitchKey CiphertextModulus: {:?}, output CmLweCiphertext CiphertextModulus {:?}.",
        cm_lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // Copy the input body to the output ciphertext
    output_lwe_ciphertext
        .get_mut_bodies()
        .as_mut()
        .copy_from_slice(input_lwe_ciphertext.get_bodies().as_ref());

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        cm_lwe_keyswitch_key.decomposition_base_log(),
        cm_lwe_keyswitch_key.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_mask_element) in cm_lwe_keyswitch_key
        .iter()
        .zip(input_lwe_ciphertext.get_mask().as_ref())
    {
        let decomposition_iter = decomposer.decompose(input_mask_element);
        // Loop over the levels
        for (level_key_ciphertext, decomposed) in keyswitch_key_block.iter().zip(decomposition_iter)
        {
            slice_wrapping_sub_scalar_mul_assign(
                output_lwe_ciphertext.as_mut(),
                level_key_ciphertext.as_ref(),
                decomposed.value(),
            );
        }
    }
}

/// Parallel variant of [`cm_keyswitch_lwe_ciphertext`].
///
/// This will use all threads available in the current rayon thread pool.
pub fn par_cm_keyswitch_lwe_ciphertext<Scalar, KSKCont, InputCont, OutputCont>(
    cm_lwe_keyswitch_key: &CmLweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &CmLweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut CmLweCiphertext<OutputCont>,
) where
    Scalar: UnsignedInteger + Send + Sync,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let thread_count = ThreadCount(rayon::current_num_threads());
    par_cm_keyswitch_lwe_ciphertext_with_thread_count(
        cm_lwe_keyswitch_key,
        input_lwe_ciphertext,
        output_lwe_ciphertext,
        thread_count,
    );
}

/// Parallel variant of [`cm_keyswitch_lwe_ciphertext`].
///
/// This will try to use `thread_count` threads for the computation, if this number is bigger than
/// the available number of threads in the current rayon thread pool then only the number of
/// available threads will be used. Note that `thread_count` cannot be 0.
pub fn par_cm_keyswitch_lwe_ciphertext_with_thread_count<Scalar, KSKCont, InputCont, OutputCont>(
    cm_lwe_keyswitch_key: &CmLweKeyswitchKey<KSKCont>,
    input_lwe_ciphertext: &CmLweCiphertext<InputCont>,
    output_lwe_ciphertext: &mut CmLweCiphertext<OutputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
    KSKCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        cm_lwe_keyswitch_key.input_lwe_dimension() == input_lwe_ciphertext.lwe_dimension(),
        "Mismatched input LweDimension. \
        CmLweKeyswitchKey input LweDimension: {:?}, input CmLweCiphertext LweDimension {:?}.",
        cm_lwe_keyswitch_key.input_lwe_dimension(),
        input_lwe_ciphertext.lwe_dimension(),
    );
    assert!(
        cm_lwe_keyswitch_key.output_lwe_dimension() == output_lwe_ciphertext.lwe_dimension(),
        "Mismatched output LweDimension. \
        CmLweKeyswitchKey output LweDimension: {:?}, output CmLweCiphertext LweDimension {:?}.",
        cm_lwe_keyswitch_key.output_lwe_dimension(),
        output_lwe_ciphertext.lwe_dimension(),
    );

    let output_ciphertext_modulus = output_lwe_ciphertext.ciphertext_modulus();

    assert_eq!(
        cm_lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus,
        "Mismatched CiphertextModulus. \
        CmLweKeyswitchKey CiphertextModulus: {:?}, output CmLweCiphertext CiphertextModulus {:?}.",
        cm_lwe_keyswitch_key.ciphertext_modulus(),
        output_ciphertext_modulus
    );
    assert!(
        output_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    let input_ciphertext_modulus = input_lwe_ciphertext.ciphertext_modulus();

    assert!(
        input_ciphertext_modulus.is_compatible_with_native_modulus(),
        "This operation currently only supports power of 2 moduli"
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    // Clear the output ciphertext, as it will get updated gradually
    output_lwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let output_lwe_dimension = output_lwe_ciphertext.lwe_dimension();

    let cm_dimension = output_lwe_ciphertext.cm_dimension();

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        cm_lwe_keyswitch_key.decomposition_base_log(),
        cm_lwe_keyswitch_key.decomposition_level_count(),
    );

    // Don't go above the current number of threads
    let thread_count = thread_count.0.min(rayon::current_num_threads());
    let mut intermediate_accumulators = Vec::with_capacity(thread_count);

    // Smallest chunk_size such that thread_count * chunk_size >= input_lwe_dimension
    let chunk_size = input_lwe_ciphertext
        .lwe_dimension()
        .0
        .div_ceil(thread_count);

    cm_lwe_keyswitch_key
        .par_chunks(chunk_size)
        .zip(
            input_lwe_ciphertext
                .get_mask()
                .as_ref()
                .par_chunks(chunk_size),
        )
        .map(|(keyswitch_key_block_chunk, input_mask_element_chunk)| {
            let mut buffer = CmLweCiphertext::new(
                Scalar::ZERO,
                output_lwe_dimension,
                cm_dimension,
                output_ciphertext_modulus,
            );

            for (keyswitch_key_block, &input_mask_element) in keyswitch_key_block_chunk
                .iter()
                .zip(input_mask_element_chunk.iter())
            {
                let decomposition_iter = decomposer.decompose(input_mask_element);
                // Loop over the levels
                for (level_key_ciphertext, decomposed) in
                    keyswitch_key_block.iter().zip(decomposition_iter)
                {
                    slice_wrapping_sub_scalar_mul_assign(
                        buffer.as_mut(),
                        level_key_ciphertext.as_ref(),
                        decomposed.value(),
                    );
                }
            }
            buffer
        })
        .collect_into_vec(&mut intermediate_accumulators);

    let reduced = intermediate_accumulators
        .par_iter_mut()
        .reduce_with(|lhs, rhs| {
            lhs.as_mut()
                .iter_mut()
                .zip(rhs.as_ref().iter())
                .for_each(|(dst, &src)| *dst = (*dst).wrapping_add(src));

            lhs
        })
        .unwrap();

    let reduced = reduced.as_view();

    output_lwe_ciphertext
        .get_mut_mask()
        .as_mut()
        .copy_from_slice(reduced.get_mask().as_ref());

    let reduced_ksed_bodies = reduced.get_bodies();

    // Add the reduced body of the keyswitch to the output body to complete the keyswitch
    for ((out, in1), in2) in output_lwe_ciphertext
        .get_mut_bodies()
        .as_mut()
        .iter_mut()
        .zip_eq(input_lwe_ciphertext.get_bodies().as_ref())
        .zip_eq(reduced_ksed_bodies.as_ref())
    {
        *out = in1.wrapping_add(*in2);
    }
}
