//! Module containing primitives pertaining to [`LWE trace pacling
//! keyswitch`](`LweTracePackingKeyswitchKey#lwe-trace-packing-keyswitch`).

use crate::core_crypto::algorithms::glwe_keyswitch::*;
use crate::core_crypto::algorithms::polynomial_algorithms::*;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Apply a trace packing keyswitch on an input [`LWE ciphertext list`](`LweCiphertextList`) and
/// pack the result in an output [`GLWE ciphertext`](`GlweCiphertext`).
///
/// ```
/// use tfhe::core_crypto::commons::math::decomposition::SignedDecomposerNonNative;
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for LweTracePackingKeyswitchKey creation
/// let lwe_dimension = LweDimension(2048);
/// let lwe_count = LweCiphertextCount(100);
/// let polynomial_size = PolynomialSize(512);
/// let glwe_dim = (lwe_dimension.0 - 1) / polynomial_size.0 + 1;
/// let glwe_dimension = GlweDimension(glwe_dim);
/// let lwe_noise_distribution =
///     Gaussian::from_dispersion_parameter(StandardDev(0.000003925799891201197), 0.0);
/// let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
///     StandardDev(0.00000000000000000000007069849454709433),
///     0.0,
/// );
/// let ciphertext_modulus = CiphertextModulus::new_native();
/// let delta: u64 = 1 << 59;
///
/// let mut seeder = new_seeder();
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
/// let lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);
///
/// let mut glwe_secret_key = GlweSecretKey::new_empty_key(0u64, glwe_dimension, polynomial_size);
///
/// generate_tpksk_output_glwe_secret_key(
///     &lwe_secret_key,
///     &mut glwe_secret_key,
///     ciphertext_modulus,
///     &mut secret_generator,
/// );
///
/// let decomp_base_log = DecompositionBaseLog(28);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
///
/// let mut lwe_tpksk = LweTracePackingKeyswitchKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     lwe_dimension.to_lwe_size(),
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_trace_packing_keyswitch_key(
///     &glwe_secret_key,
///     &mut lwe_tpksk,
///     glwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut lwe_ctxt_list = LweCiphertextList::new(
///     0u64,
///     lwe_dimension.to_lwe_size(),
///     lwe_count,
///     ciphertext_modulus,
/// );
///
/// let msg = 7u64;
/// let plaintext_list = PlaintextList::new(msg * delta, PlaintextCount(lwe_count.0));
///
/// encrypt_lwe_ciphertext_list(
///     &lwe_secret_key,
///     &mut lwe_ctxt_list,
///     &plaintext_list,
///     lwe_noise_distribution,
///     &mut encryption_generator,
/// );
///
/// let mut output_glwe_ciphertext = GlweCiphertext::new(
///     0u64,
///     glwe_dimension.to_glwe_size(),
///     polynomial_size,
///     ciphertext_modulus,
/// );
///
/// let mut indices = vec![0_usize; lwe_count.0];
/// for (index, item) in indices.iter_mut().enumerate() {
///     *item = index;
/// }
///
/// trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext(
///     &lwe_tpksk,
///     &mut output_glwe_ciphertext,
///     &lwe_ctxt_list,
///     &indices,
/// );
///
/// let mut output_plaintext_list = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
///
/// decrypt_glwe_ciphertext(
///     &glwe_secret_key,
///     &output_glwe_ciphertext,
///     &mut output_plaintext_list,
/// );
///
/// // Round and remove encoding
/// // First create a decomposer working on the high 4 bits corresponding to our encoding.
/// let decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
///
/// // Get the raw vector
/// let mut cleartext_list = output_plaintext_list.into_container();
/// // Remove the encoding
/// cleartext_list
///     .iter_mut()
///     .for_each(|elt| *elt = decomposer.decode_plaintext(*elt));
/// // Get the list immutably
/// let cleartext_list = cleartext_list;
///
/// // Check we recovered the original message for each plaintext we encrypted
/// for (index, elt) in cleartext_list.iter().enumerate() {
///     if index < lwe_count.0 {
///         assert_eq!(*elt, msg);
///     } else {
///         assert_eq!(*elt, 0);
///     }
/// }
/// ```
pub fn trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    indices: &[usize],
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        input_lwe_ciphertext_list.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );

    if lwe_tpksk
        .ciphertext_modulus()
        .is_compatible_with_native_modulus()
    {
        trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_native_mod_compatible(
            lwe_tpksk,
            output_glwe_ciphertext,
            input_lwe_ciphertext_list,
            indices,
        )
    } else {
        let custom_modulus = lwe_tpksk.ciphertext_modulus().get_custom_modulus();
        if custom_modulus % 2 == 1 {
            trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_other_mod_odd(
                lwe_tpksk,
                output_glwe_ciphertext,
                input_lwe_ciphertext_list,
                indices,
            )
        } else {
            trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_other_mod_even(
                lwe_tpksk,
                output_glwe_ciphertext,
                input_lwe_ciphertext_list,
                indices,
            )
        }
    }
}

pub fn trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_native_mod_compatible<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    indices: &[usize],
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0
            <= output_glwe_ciphertext.polynomial_size().0
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        indices.len()
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_size(),
        lwe_tpksk.input_lwe_size()
    );
    assert!(indices
        .iter()
        .all(|&x| x < output_glwe_ciphertext.polynomial_size().0));
    assert_eq!(
        output_glwe_ciphertext.polynomial_size(),
        lwe_tpksk.polynomial_size()
    );
    assert_eq!(
        output_glwe_ciphertext.glwe_size(),
        lwe_tpksk.output_glwe_size()
    );
    assert_eq!(
        input_lwe_ciphertext_list.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert!(lwe_tpksk
        .ciphertext_modulus()
        .is_compatible_with_native_modulus());

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let poly_size = output_glwe_ciphertext.polynomial_size();
    let glwe_size = output_glwe_ciphertext.glwe_size();
    let glwe_count = GlweCiphertextCount(poly_size.0);
    let ciphertext_modulus = output_glwe_ciphertext.ciphertext_modulus();

    let mut glwe_list = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        poly_size,
        glwe_count,
        ciphertext_modulus,
    );

    // Construct the initial Glwe Ciphertexts
    for (index1, mut glwe_ct) in glwe_list.iter_mut().enumerate() {
        for (index2, index) in indices.iter().enumerate() {
            if index1 == *index {
                let lwe_ct = input_lwe_ciphertext_list.get(index2);
                let lwe_body = lwe_ct.get_body(); //lwe_ct.as_ref().last().unwrap();
                let lwe_mask = lwe_ct.get_mask();
                for (index3, mut poly) in glwe_ct
                    .get_mut_mask()
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .enumerate()
                {
                    for (index4, coef) in poly.iter_mut().enumerate() {
                        if index3 * poly_size.0 + index4 < lwe_mask.lwe_dimension().0 {
                            *coef =
                                coef.wrapping_add(lwe_mask.as_ref()[index3 * poly_size.0 + index4]);
                        }
                    }
                }
                let mut glwe_body = glwe_ct.get_mut_body();
                let mut glwe_body_poly = glwe_body.as_mut_polynomial();
                glwe_body_poly[0] = *lwe_body.data;
            }
        }
    }

    // This bit determines if we round an odd value down (if rounding_bit is zero)
    // or round up (if rounding_bit is one)
    // We flip this bit whenever it is used to get an rounding that is close to
    // randomly rounding up or down with equal probability.
    let mut rounding_bit = Scalar::ZERO;

    for l in 0..poly_size.log2().0 {
        for i in 0..(poly_size.0 / 2_usize.pow(l as u32 + 1)) {
            let ct_0 = glwe_list.get(i);
            //let glwe_size = ct_0.glwe_size();
            let j = (poly_size.0 / 2_usize.pow(l as u32 + 1)) + i;
            let ct_1 = glwe_list.get(j);
            if ct_0.as_ref().iter().any(|&x| x != Scalar::ZERO)
                || ct_1.as_ref().iter().any(|&x| x != Scalar::ZERO)
            {
                // Diving ct_0 and ct_1 by 2
                for mut pol in glwe_list.get_mut(i).as_mut_polynomial_list().iter_mut() {
                    pol.iter_mut().for_each(|coef| {
                        if *coef % Scalar::TWO == Scalar::ZERO {
                            *coef >>= 1
                        } else {
                            // Round up or down depending on rounding bit
                            *coef = (*coef >> 1) + rounding_bit;
                            rounding_bit = Scalar::ONE - rounding_bit;
                        }
                    })
                }
                for mut pol in glwe_list.get_mut(j).as_mut_polynomial_list().iter_mut() {
                    pol.iter_mut().for_each(|coef| {
                        if *coef % Scalar::TWO == Scalar::ZERO {
                            *coef >>= 1
                        } else {
                            // Round up or down depending on rounding bit
                            *coef = (*coef >> 1) + rounding_bit;
                            rounding_bit = Scalar::ONE - rounding_bit;
                        }
                    })
                }

                // Rotate ct_1 by N/2^(l+1)
                for mut pol in glwe_list.get_mut(j).as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign(
                        &mut pol,
                        MonomialDegree(poly_size.0 / 2_usize.pow(l as u32 + 1)),
                    );
                }

                let mut ct_plus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);
                let mut ct_minus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);

                for ((mut pol_plus, pol_0), pol_1) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_assign(&mut pol_plus, &pol_0);
                    polynomial_wrapping_add_assign(&mut pol_plus, &pol_1);
                }

                for ((mut pol_minus, pol_0), pol_1) in ct_minus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_assign(&mut pol_minus, &pol_0);
                    polynomial_wrapping_sub_assign(&mut pol_minus, &pol_1);
                }

                // Apply the automorphism sending X to X^(2^(l+1) + 1) to ct_minus
                for mut pol in ct_minus.as_mut_polynomial_list().iter_mut() {
                    apply_automorphism_assign(&mut pol, 2_usize.pow(l as u32 + 1) + 1)
                }

                let mut ks_out = GlweCiphertext::new(
                    Scalar::ZERO,
                    ct_minus.glwe_size(),
                    poly_size,
                    ciphertext_modulus,
                );

                let glwe_ksk = GlweKeyswitchKey::from_container(
                    lwe_tpksk.get(l).into_container(),
                    lwe_tpksk.decomposition_base_log(),
                    lwe_tpksk.decomposition_level_count(),
                    glwe_size,
                    lwe_tpksk.polynomial_size(),
                    lwe_tpksk.ciphertext_modulus(),
                );

                // Perform a Glwe keyswitch on ct_minus
                keyswitch_glwe_ciphertext(&glwe_ksk, &ct_minus, &mut ks_out);

                // Set ct_0 to zero
                glwe_list.get_mut(i).as_mut().fill(Scalar::ZERO);

                // Add the result to ct_plus and add this to ct_0
                for ((mut pol_plus, pol_ks), mut pol_0) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(ks_out.as_polynomial_list().iter())
                    .zip(glwe_list.get_mut(i).as_mut_polynomial_list().iter_mut())
                {
                    polynomial_wrapping_add_assign(&mut pol_plus, &pol_ks);
                    polynomial_wrapping_add_assign(&mut pol_0, &pol_plus);
                }
            }
        }
    }
    let res = glwe_list.get(0);
    for (mut pol_out, pol_res) in output_glwe_ciphertext
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(res.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_assign(&mut pol_out, &pol_res);
    }
}

pub fn trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_other_mod_odd<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    indices: &[usize],
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0
            <= output_glwe_ciphertext.polynomial_size().0
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        indices.len()
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_size(),
        lwe_tpksk.input_lwe_size()
    );
    assert!(indices
        .iter()
        .all(|&x| x < output_glwe_ciphertext.polynomial_size().0));
    assert_eq!(
        output_glwe_ciphertext.polynomial_size(),
        lwe_tpksk.polynomial_size()
    );
    assert_eq!(
        output_glwe_ciphertext.glwe_size(),
        lwe_tpksk.output_glwe_size()
    );
    assert_eq!(
        input_lwe_ciphertext_list.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert!(!lwe_tpksk
        .ciphertext_modulus()
        .is_compatible_with_native_modulus());

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let poly_size = output_glwe_ciphertext.polynomial_size();
    let glwe_size = output_glwe_ciphertext.glwe_size();
    let glwe_count = GlweCiphertextCount(poly_size.0);
    let ciphertext_modulus = output_glwe_ciphertext.ciphertext_modulus();
    let modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();

    let mut glwe_list = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        poly_size,
        glwe_count,
        ciphertext_modulus,
    );

    // Construct the initial Glwe Ciphertexts
    for (index1, mut glwe_ct) in glwe_list.iter_mut().enumerate() {
        for (index2, index) in indices.iter().enumerate() {
            if index1 == *index {
                let lwe_ct = input_lwe_ciphertext_list.get(index2);
                let lwe_body = lwe_ct.get_body();
                let lwe_mask = lwe_ct.get_mask();
                for (index3, mut poly) in glwe_ct
                    .get_mut_mask()
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .enumerate()
                {
                    for (index4, coef) in poly.iter_mut().enumerate() {
                        if index3 * poly_size.0 + index4 < lwe_mask.lwe_dimension().0 {
                            *coef =
                                coef.wrapping_add(lwe_mask.as_ref()[index3 * poly_size.0 + index4]);
                        }
                    }
                }
                let mut glwe_body = glwe_ct.get_mut_body();
                let mut glwe_body_poly = glwe_body.as_mut_polynomial();
                glwe_body_poly[0] = *lwe_body.data;
            }
        }
    }

    for l in 0..poly_size.log2().0 {
        for i in 0..(poly_size.0 / 2_usize.pow(l as u32 + 1)) {
            let ct_0 = glwe_list.get(i);
            //let glwe_size = ct_0.glwe_size();
            let j = (poly_size.0 / 2_usize.pow(l as u32 + 1)) + i;
            let ct_1 = glwe_list.get(j);
            if ct_0.as_ref().iter().any(|&x| x != Scalar::ZERO)
                || ct_1.as_ref().iter().any(|&x| x != Scalar::ZERO)
            {
                // Rotate ct_1 by N/2^(l+1)
                for mut pol in glwe_list.get_mut(j).as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign_custom_mod(
                        &mut pol,
                        MonomialDegree(poly_size.0 / 2_usize.pow(l as u32 + 1)),
                        modulus_as_scalar,
                    );
                }

                let mut ct_plus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);
                let mut ct_minus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);

                for ((mut pol_plus, pol_0), pol_1) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_assign(&mut pol_plus, &pol_0);
                    polynomial_wrapping_add_assign_custom_mod(
                        &mut pol_plus,
                        &pol_1,
                        modulus_as_scalar,
                    );
                }

                for ((mut pol_minus, pol_0), pol_1) in ct_minus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_assign(&mut pol_minus, &pol_0);
                    polynomial_wrapping_sub_assign_custom_mod(
                        &mut pol_minus,
                        &pol_1,
                        modulus_as_scalar,
                    );
                }

                // Scale the ciphertexts by 2^-1 = (q + 1)/2 when q is odd
                let scalar = (modulus_as_scalar + Scalar::ONE) / Scalar::TWO;
                for mut pol in ct_plus.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_scalar_mul_assign_custom_mod(
                        &mut pol,
                        scalar,
                        modulus_as_scalar,
                    );
                }
                for mut pol in ct_minus.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_scalar_mul_assign_custom_mod(
                        &mut pol,
                        scalar,
                        modulus_as_scalar,
                    );
                }

                // Apply the automorphism sending X to X^(2^(l+1) + 1) to ct_minus
                for mut pol in ct_minus.as_mut_polynomial_list().iter_mut() {
                    apply_automorphism_assign_custom_mod(
                        &mut pol,
                        2_usize.pow(l as u32 + 1) + 1,
                        modulus_as_scalar,
                    )
                }

                let mut ks_out = GlweCiphertext::new(
                    Scalar::ZERO,
                    ct_minus.glwe_size(),
                    poly_size,
                    ciphertext_modulus,
                );

                let glwe_ksk = GlweKeyswitchKey::from_container(
                    lwe_tpksk.get(l).into_container(),
                    lwe_tpksk.decomposition_base_log(),
                    lwe_tpksk.decomposition_level_count(),
                    glwe_size,
                    lwe_tpksk.polynomial_size(),
                    lwe_tpksk.ciphertext_modulus(),
                );

                // Perform a Glwe keyswitch on ct_minus
                keyswitch_glwe_ciphertext(&glwe_ksk, &ct_minus, &mut ks_out);

                // Set ct_0 to zero
                glwe_list.get_mut(i).as_mut().fill(Scalar::ZERO);

                // Add the result to ct_plus and add this to ct_0
                for ((mut pol_plus, pol_ks), mut pol_0) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(ks_out.as_polynomial_list().iter())
                    .zip(glwe_list.get_mut(i).as_mut_polynomial_list().iter_mut())
                {
                    polynomial_wrapping_add_assign_custom_mod(
                        &mut pol_plus,
                        &pol_ks,
                        modulus_as_scalar,
                    );
                    polynomial_wrapping_add_assign(&mut pol_0, &pol_plus);
                }
            }
        }
    }
    let res = glwe_list.get(0);
    for (mut pol_out, pol_res) in output_glwe_ciphertext
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(res.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_assign(&mut pol_out, &pol_res);
    }
}

pub fn trace_packing_keyswitch_lwe_ciphertext_list_into_glwe_ciphertext_other_mod_even<
    Scalar,
    KeyCont,
    InputCont,
    OutputCont,
>(
    lwe_tpksk: &LweTracePackingKeyswitchKey<KeyCont>,
    output_glwe_ciphertext: &mut GlweCiphertext<OutputCont>,
    input_lwe_ciphertext_list: &LweCiphertextList<InputCont>,
    indices: &[usize],
) where
    Scalar: UnsignedInteger,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0
            <= output_glwe_ciphertext.polynomial_size().0
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_ciphertext_count().0,
        indices.len()
    );
    assert_eq!(
        input_lwe_ciphertext_list.lwe_size(),
        lwe_tpksk.input_lwe_size()
    );
    assert!(indices
        .iter()
        .all(|&x| x < output_glwe_ciphertext.polynomial_size().0));
    assert_eq!(
        output_glwe_ciphertext.polynomial_size(),
        lwe_tpksk.polynomial_size()
    );
    assert_eq!(
        output_glwe_ciphertext.glwe_size(),
        lwe_tpksk.output_glwe_size()
    );
    assert_eq!(
        input_lwe_ciphertext_list.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert_eq!(
        output_glwe_ciphertext.ciphertext_modulus(),
        lwe_tpksk.ciphertext_modulus()
    );
    assert!(!lwe_tpksk
        .ciphertext_modulus()
        .is_compatible_with_native_modulus());

    // We reset the output
    output_glwe_ciphertext.as_mut().fill(Scalar::ZERO);

    let poly_size = output_glwe_ciphertext.polynomial_size();
    let glwe_size = output_glwe_ciphertext.glwe_size();
    let glwe_count = GlweCiphertextCount(poly_size.0);
    let ciphertext_modulus = output_glwe_ciphertext.ciphertext_modulus();
    let modulus_as_scalar: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();

    let mut glwe_list = GlweCiphertextList::new(
        Scalar::ZERO,
        glwe_size,
        poly_size,
        glwe_count,
        ciphertext_modulus,
    );

    // Construct the initial Glwe Ciphertexts
    for (index1, mut glwe_ct) in glwe_list.iter_mut().enumerate() {
        for (index2, index) in indices.iter().enumerate() {
            if index1 == *index {
                let lwe_ct = input_lwe_ciphertext_list.get(index2);
                let lwe_body = lwe_ct.get_body();
                let lwe_mask = lwe_ct.get_mask();
                for (index3, mut poly) in glwe_ct
                    .get_mut_mask()
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .enumerate()
                {
                    for (index4, coef) in poly.iter_mut().enumerate() {
                        if index3 * poly_size.0 + index4 < lwe_mask.lwe_dimension().0 {
                            *coef =
                                coef.wrapping_add(lwe_mask.as_ref()[index3 * poly_size.0 + index4]);
                        }
                    }
                }
                let mut glwe_body = glwe_ct.get_mut_body();
                let mut glwe_body_poly = glwe_body.as_mut_polynomial();
                glwe_body_poly[0] = *lwe_body.data;
            }
        }
    }

    // This bit determines if we round an odd value down (if rounding_bit is zero)
    // or round up (if rounding_bit is one)
    // We flip this bit whenever it is used to get an rounding that is close to
    // randomly rounding up or down with equal probability.
    let mut rounding_bit = Scalar::ZERO;

    for l in 0..poly_size.log2().0 {
        for i in 0..(poly_size.0 / 2_usize.pow(l as u32 + 1)) {
            let ct_0 = glwe_list.get(i);
            //let glwe_size = ct_0.glwe_size();
            let j = (poly_size.0 / 2_usize.pow(l as u32 + 1)) + i;
            let ct_1 = glwe_list.get(j);
            if ct_0.as_ref().iter().any(|&x| x != Scalar::ZERO)
                || ct_1.as_ref().iter().any(|&x| x != Scalar::ZERO)
            {
                // Diving ct_0 and ct_1 by 2
                for mut pol in glwe_list.get_mut(i).as_mut_polynomial_list().iter_mut() {
                    pol.iter_mut().for_each(|coef| {
                        if *coef % Scalar::TWO == Scalar::ZERO {
                            *coef >>= 1
                        } else {
                            // Round up or down depending on rounding bit
                            *coef = (*coef >> 1) + rounding_bit;
                            rounding_bit = Scalar::ONE - rounding_bit;
                        }
                    })
                }
                for mut pol in glwe_list.get_mut(j).as_mut_polynomial_list().iter_mut() {
                    pol.iter_mut().for_each(|coef| {
                        if *coef % Scalar::TWO == Scalar::ZERO {
                            *coef >>= 1
                        } else {
                            // Round up or down depending on rounding bit
                            *coef = (*coef >> 1) + rounding_bit;
                            rounding_bit = Scalar::ONE - rounding_bit;
                        }
                    })
                }

                // Rotate ct_1 by N/2^(l+1)
                for mut pol in glwe_list.get_mut(j).as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign_custom_mod(
                        &mut pol,
                        MonomialDegree(poly_size.0 / 2_usize.pow(l as u32 + 1)),
                        modulus_as_scalar,
                    );
                }

                let mut ct_plus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);
                let mut ct_minus =
                    GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size, ciphertext_modulus);

                for ((mut pol_plus, pol_0), pol_1) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_assign(&mut pol_plus, &pol_0);
                    polynomial_wrapping_add_assign_custom_mod(
                        &mut pol_plus,
                        &pol_1,
                        modulus_as_scalar,
                    );
                }

                for ((mut pol_minus, pol_0), pol_1) in ct_minus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(glwe_list.get(i).as_polynomial_list().iter())
                    .zip(glwe_list.get(j).as_polynomial_list().iter())
                {
                    polynomial_wrapping_add_assign(&mut pol_minus, &pol_0);
                    polynomial_wrapping_sub_assign_custom_mod(
                        &mut pol_minus,
                        &pol_1,
                        modulus_as_scalar,
                    );
                }

                // Apply the automorphism sending X to X^(2^(l+1) + 1) to ct_minus
                for mut pol in ct_minus.as_mut_polynomial_list().iter_mut() {
                    apply_automorphism_assign_custom_mod(
                        &mut pol,
                        2_usize.pow(l as u32 + 1) + 1,
                        modulus_as_scalar,
                    )
                }

                let mut ks_out = GlweCiphertext::new(
                    Scalar::ZERO,
                    ct_minus.glwe_size(),
                    poly_size,
                    ciphertext_modulus,
                );

                let glwe_ksk = GlweKeyswitchKey::from_container(
                    lwe_tpksk.get(l).into_container(),
                    lwe_tpksk.decomposition_base_log(),
                    lwe_tpksk.decomposition_level_count(),
                    glwe_size,
                    lwe_tpksk.polynomial_size(),
                    lwe_tpksk.ciphertext_modulus(),
                );

                // Perform a Glwe keyswitch on ct_minus
                keyswitch_glwe_ciphertext(&glwe_ksk, &ct_minus, &mut ks_out);

                // Set ct_0 to zero
                glwe_list.get_mut(i).as_mut().fill(Scalar::ZERO);

                // Add the result to ct_plus and add this to ct_0
                for ((mut pol_plus, pol_ks), mut pol_0) in ct_plus
                    .as_mut_polynomial_list()
                    .iter_mut()
                    .zip(ks_out.as_polynomial_list().iter())
                    .zip(glwe_list.get_mut(i).as_mut_polynomial_list().iter_mut())
                {
                    polynomial_wrapping_add_assign_custom_mod(
                        &mut pol_plus,
                        &pol_ks,
                        modulus_as_scalar,
                    );
                    polynomial_wrapping_add_assign(&mut pol_0, &pol_plus);
                }
            }
        }
    }
    let res = glwe_list.get(0);
    for (mut pol_out, pol_res) in output_glwe_ciphertext
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(res.as_polynomial_list().iter())
    {
        polynomial_wrapping_add_assign(&mut pol_out, &pol_res);
    }
}
