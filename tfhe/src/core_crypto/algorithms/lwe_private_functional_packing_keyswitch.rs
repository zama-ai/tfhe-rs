//! Module containing primitives pertaining to LWE ciphertext private functional keyswitch and
//! packing keyswitch.
//!
//! Formal description can be found in: \
//! &nbsp;&nbsp;&nbsp;&nbsp; Chillotti, I., Gama, N., Georgieva, M. et al. \
//! &nbsp;&nbsp;&nbsp;&nbsp; TFHE: Fast Fully Homomorphic Encryption Over the Torus. \
//! &nbsp;&nbsp;&nbsp;&nbsp; J. Cryptol 33, 34–91 (2020). \
//! &nbsp;&nbsp;&nbsp;&nbsp; <https://doi.org/10.1007/s00145-019-09319-x>

use crate::core_crypto::algorithms::misc::divide_ceil;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use rayon::prelude::*;

/// Apply a private functional keyswitch on an input [`LWE ciphertext`](`LweCiphertext`) and write
/// the result in an output [`GLWE ciphertext`](`GlweCiphertext`).
pub fn private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pfpksk: &LwePrivateFunctionalPackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        lwe_pfpksk.input_key_lwe_dimension().0,
        input_lwe_ciphertext.lwe_size().to_lwe_dimension().0
    );
    assert_eq!(
        lwe_pfpksk.output_key_glwe_dimension().0,
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );

    assert_eq!(
        lwe_pfpksk.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus()
    );

    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );

    assert!(
        input_lwe_ciphertext
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_pfpksk.decomposition_base_log(),
        lwe_pfpksk.decomposition_level_count(),
    );

    for (keyswitch_key_block, &input_lwe_element) in
        lwe_pfpksk.iter().zip(input_lwe_ciphertext.as_ref().iter())
    {
        // We decompose
        let rounded = decomposer.closest_representable(input_lwe_element);
        let decomp = decomposer.decompose(rounded);

        // Loop over the number of levels:
        // We compute the multiplication of a ciphertext from the private functional
        // keyswitching key with a piece of the decomposition and subtract it to the buffer
        for (level_key_cipher, decomposed) in keyswitch_key_block.iter().rev().zip(decomp) {
            slice_wrapping_sub_scalar_mul_assign(
                output_glwe_ciphertext.as_mut(),
                level_key_cipher.as_ref(),
                decomposed.value(),
            );
        }
    }
}

/// Parallel variant of [`private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext`].
///
/// This will use all threads available in the current rayon thread pool.
pub fn par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pfpksk: &LwePrivateFunctionalPackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
) where
    Scalar: UnsignedInteger + Send + Sync,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    let thread_count = ThreadCount(rayon::current_num_threads());
    par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext_with_thread_count(
        lwe_pfpksk,
        output_glwe_ciphertext,
        input_lwe_ciphertext,
        thread_count,
    );
}

/// Parallel variant of [`private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext`].
///
/// This will try to use `thread_count` threads for the computation, if this number is bigger than
/// the available number of threads in the current rayon thread pool then only the number of
/// available threads will be used. Note that `thread_count` cannot be 0.
pub fn par_private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext_with_thread_count<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pfpksk: &LwePrivateFunctionalPackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext: &LweCiphertext<InputCont>,
    thread_count: ThreadCount,
) where
    Scalar: UnsignedInteger + Send + Sync,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        lwe_pfpksk.input_key_lwe_dimension().0,
        input_lwe_ciphertext.lwe_size().to_lwe_dimension().0
    );
    assert_eq!(
        lwe_pfpksk.output_key_glwe_dimension().0,
        output_glwe_ciphertext.glwe_size().to_glwe_dimension().0
    );

    assert_eq!(
        lwe_pfpksk.ciphertext_modulus(),
        output_glwe_ciphertext.ciphertext_modulus()
    );

    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        input_lwe_ciphertext.ciphertext_modulus()
    );

    assert!(
        input_lwe_ciphertext
            .ciphertext_modulus()
            .is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    assert!(
        thread_count.0 != 0,
        "Got thread_count == 0, this is not supported"
    );

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    // We instantiate a decomposer
    let decomposer = SignedDecomposer::new(
        lwe_pfpksk.decomposition_base_log(),
        lwe_pfpksk.decomposition_level_count(),
    );

    // Don't go above the current number of threads
    let thread_count = thread_count.0.min(rayon::current_num_threads());
    let mut intermediate_accumulators = Vec::with_capacity(thread_count);

    let output_glwe_size = output_glwe_ciphertext.glwe_size();
    let output_glwe_polynomial_size = output_glwe_ciphertext.polynomial_size();
    let output_glwe_ciphertext_modulus = output_glwe_ciphertext.ciphertext_modulus();

    // Smallest chunk_size such that thread_count * chunk_size >= input_lwe_size
    let chunk_size = divide_ceil(input_lwe_ciphertext.lwe_size().0, thread_count);

    lwe_pfpksk
        .par_chunks(chunk_size)
        .zip(input_lwe_ciphertext.as_ref().par_chunks(chunk_size))
        .map(|(keyswitch_key_block_chunk, input_lwe_element_chunk)| {
            let mut glwe_buffer = GlweCiphertext::new(
                Scalar::ZERO,
                output_glwe_size,
                output_glwe_polynomial_size,
                output_glwe_ciphertext_modulus,
            );

            for (keyswitch_key_block, &input_lwe_element) in keyswitch_key_block_chunk
                .iter()
                .zip(input_lwe_element_chunk.as_ref().iter())
            {
                // We decompose
                let rounded = decomposer.closest_representable(input_lwe_element);
                let decomp = decomposer.decompose(rounded);

                // Loop over the number of levels:
                // We compute the multiplication of a ciphertext from the private functional
                // keyswitching key with a piece of the decomposition and subtract it to the buffer
                for (level_key_cipher, decomposed) in keyswitch_key_block.iter().rev().zip(decomp) {
                    slice_wrapping_sub_scalar_mul_assign(
                        glwe_buffer.as_mut(),
                        level_key_cipher.as_ref(),
                        decomposed.value(),
                    );
                }
            }
            glwe_buffer
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

    output_glwe_ciphertext
        .as_mut()
        .copy_from_slice(reduced.as_ref());
}

/// Apply a private functional keyswitch on each [`LWE ciphertext`](`LweCiphertext`) of an input
/// [`LWE ciphertext list`](`LweCiphertextList`) and pack the result in an output
/// [`GLWE ciphertext`](`GlweCiphertext`).
pub fn private_functional_keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_pfpksk: &LwePrivateFunctionalPackingKeyswitchKey<KeyCont>,
    output: &mut GlweCiphertext<OutputCont>,
    input: &LweCiphertextList<InputCont>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(lwe_pfpksk.ciphertext_modulus(), output.ciphertext_modulus());
    assert_eq!(output.ciphertext_modulus(), input.ciphertext_modulus());
    assert!(
        input.ciphertext_modulus().is_native_modulus(),
        "This operation currently only supports native moduli"
    );

    assert!(input.lwe_ciphertext_count().0 <= output.polynomial_size().0);
    output.as_mut().fill(Scalar::ZERO);
    let mut buffer = GlweCiphertext::new(
        Scalar::ZERO,
        output.glwe_size(),
        output.polynomial_size(),
        output.ciphertext_modulus(),
    );
    // for each ciphertext, call mono_key_switch
    for (degree, input_ciphertext) in input.iter().enumerate() {
        private_functional_keyswitch_lwe_ciphertext_into_glwe_ciphertext(
            lwe_pfpksk,
            &mut buffer,
            &input_ciphertext,
        );
        buffer
            .as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_mul_assign(&mut poly, MonomialDegree(degree));
            });
        slice_wrapping_add_assign(output.as_mut(), buffer.as_ref());
    }
}
