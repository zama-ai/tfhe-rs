//! Module containing primitives pertaining to the [`LWE programmable
//! bootstrap`](`crate::core_crypto::entities::LweBootstrapKey#programmable-bootstrapping`) using 64
//! bits NTT for polynomial multiplication.

use crate::core_crypto::algorithms::glwe_sample_extraction::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::algorithms::misc::divide_round;
use crate::core_crypto::algorithms::polynomial_algorithms::{
    polynomial_wrapping_monic_monomial_div_assign_custom_mod,
    polynomial_wrapping_monic_monomial_mul_assign_custom_mod,
};
use crate::core_crypto::commons::math::decomposition::{
    SignedDecomposerNonNative, TensorSignedDecompositionLendingIterNonNative,
};
use crate::core_crypto::commons::math::ntt::ntt64::Ntt64View;
use crate::core_crypto::commons::parameters::{GlweSize, MonomialDegree, PolynomialSize};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

pub fn blind_rotate_ntt64_assign_mem_optimized<InputCont, OutputCont, KeyCont>(
    input: &LweCiphertext<InputCont>,
    lut: &mut GlweCiphertext<OutputCont>,
    bsk: &NttLweBootstrapKey<KeyCont>,
    ntt: Ntt64View<'_>,
    stack: PodStack<'_>,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    fn implementation(
        bsk: NttLweBootstrapKeyView<'_, u64>,
        mut lut: GlweCiphertextMutView<'_, u64>,
        lwe: &[u64],
        ntt: Ntt64View<'_>,
        mut stack: PodStack<'_>,
    ) {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();
        let modulus = ntt.custom_modulus();

        let lut_poly_size = lut.polynomial_size();
        let ciphertext_modulus = lut.ciphertext_modulus();
        let monomial_degree = pbs_modulus_switch_non_native(
            *lwe_body,
            lut_poly_size,
            ciphertext_modulus.get_custom_modulus().cast_into(),
        );

        lut.as_mut_polynomial_list()
            .iter_mut()
            .for_each(|mut poly| {
                polynomial_wrapping_monic_monomial_div_assign_custom_mod(
                    &mut poly,
                    MonomialDegree(monomial_degree),
                    modulus,
                )
            });

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0 = lut;

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), bsk.into_ggsw_iter()) {
            if *lwe_mask_element != 0u64 {
                let stack = stack.rb_mut();
                // We copy ct_0 to ct_1
                let (mut ct1, stack) =
                    stack.collect_aligned(CACHELINE_ALIGN, ct0.as_ref().iter().copied());
                let mut ct1 = GlweCiphertextMutView::from_container(
                    &mut *ct1,
                    lut_poly_size,
                    ciphertext_modulus,
                );

                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                for mut poly in ct1.as_mut_polynomial_list().iter_mut() {
                    polynomial_wrapping_monic_monomial_mul_assign_custom_mod(
                        &mut poly,
                        MonomialDegree(pbs_modulus_switch_non_native(
                            *lwe_mask_element,
                            lut_poly_size,
                            ciphertext_modulus.get_custom_modulus().cast_into(),
                        )),
                        modulus,
                    );
                }

                // ct1 is re-created each loop it can be moved, ct0 is already a view, but
                // as_mut_view is required to keep borrow rules consistent
                cmux_ntt64_assign(ct0.as_mut_view(), ct1, bootstrap_key_ggsw, ntt, stack);
            }
        }
    }
    implementation(bsk.as_view(), lut.as_mut_view(), input.as_ref(), ntt, stack);
}

pub fn programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized<
    InputCont,
    OutputCont,
    AccCont,
    KeyCont,
>(
    input: &LweCiphertext<InputCont>,
    output: &mut LweCiphertext<OutputCont>,
    accumulator: &GlweCiphertext<AccCont>,
    bsk: &NttLweBootstrapKey<KeyCont>,
    ntt: Ntt64View<'_>,
    stack: PodStack<'_>,
) where
    InputCont: Container<Element = u64>,
    OutputCont: ContainerMut<Element = u64>,
    AccCont: Container<Element = u64>,
    KeyCont: Container<Element = u64>,
{
    fn implementation(
        bsk: NttLweBootstrapKeyView<'_, u64>,
        mut lwe_out: LweCiphertextMutView<'_, u64>,
        lwe_in: LweCiphertextView<'_, u64>,
        accumulator: GlweCiphertextView<'_, u64>,
        ntt: Ntt64View<'_>,
        stack: PodStack<'_>,
    ) {
        debug_assert_eq!(lwe_out.ciphertext_modulus(), lwe_in.ciphertext_modulus());
        debug_assert_eq!(
            lwe_in.ciphertext_modulus(),
            accumulator.ciphertext_modulus()
        );

        let (mut local_accumulator_data, stack) =
            stack.collect_aligned(CACHELINE_ALIGN, accumulator.as_ref().iter().copied());
        let mut local_accumulator = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_data,
            accumulator.polynomial_size(),
            accumulator.ciphertext_modulus(),
        );
        blind_rotate_ntt64_assign_mem_optimized(&lwe_in, &mut local_accumulator, &bsk, ntt, stack);

        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut lwe_out,
            MonomialDegree(0),
        );
    }

    implementation(
        bsk.as_view(),
        output.as_mut_view(),
        input.as_view(),
        accumulator.as_view(),
        ntt,
        stack,
    )
}

pub fn pbs_modulus_switch_non_native<Scalar: UnsignedTorus + CastInto<usize>>(
    input: Scalar,
    poly_size: PolynomialSize,
    modulus: Scalar,
) -> usize {
    let input_u128: u128 = input.cast_into();
    let modulus_u128: u128 = modulus.cast_into();
    let switched = divide_round(input_u128 << (poly_size.log2().0 + 1), modulus_u128);
    switched as usize
}

/// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
#[cfg_attr(__profiling, inline(never))]
pub(crate) fn add_external_product_ntt64_assign<InputGlweCont>(
    mut out: GlweCiphertextMutView<'_, u64>,
    ggsw: NttGgswCiphertextView<'_, u64>,
    glwe: &GlweCiphertext<InputGlweCont>,
    ntt: Ntt64View<'_>,
    stack: PodStack<'_>,
) where
    InputGlweCont: Container<Element = u64>,
{
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());

    let align = CACHELINE_ALIGN;
    let poly_size = ggsw.polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposerNonNative::<u64>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
        out.ciphertext_modulus(),
    );

    let (mut output_fft_buffer, mut substack0) =
        stack.make_aligned_raw::<u64>(poly_size * ggsw.glwe_size().0, align);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the ntt domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIterNonNative::new(
            &decomposer,
            glwe.as_ref(),
            ntt.custom_modulus(),
            substack0.rb_mut(),
        );

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        ggsw.into_levels().rev().for_each(|ggsw_decomp_matrix| {
            // We retrieve the decomposition of this level.
            let (glwe_level, glwe_decomp_term, mut substack2) =
                decomposition.collect_next_term(&mut substack1, align);
            let glwe_decomp_term = GlweCiphertextView::from_container(
                &*glwe_decomp_term,
                ggsw.polynomial_size(),
                out.ciphertext_modulus(),
            );
            debug_assert_eq!(ggsw_decomp_matrix.decomposition_level(), glwe_level);

            // For each level we have to add the result of the vector-matrix product between the
            // decomposition of the glwe, and the ggsw level matrix to the output. To do so, we
            // iteratively add to the output, the product between every line of the matrix, and
            // the corresponding (scalar) polynomial in the glwe decomposition:
            //
            //                ggsw_mat                        ggsw_mat
            //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
            //  | - - - | x | - - - - |         | - - - | x | - - - - | <
            //    ^         | - - - - |             ^       | - - - - |
            //
            //        t = 1                           t = 2                     ...

            izip!(
                ggsw_decomp_matrix.into_rows(),
                glwe_decomp_term.as_polynomial_list().iter()
            )
            .for_each(|(ggsw_row, glwe_poly)| {
                let (mut ntt_poly, _) =
                    substack2.rb_mut().make_aligned_raw::<u64>(poly_size, align);
                // We perform the forward ntt transform for the glwe polynomial
                ntt.forward(PolynomialMutView::from_container(&mut ntt_poly), glwe_poly);
                // Now we loop through the polynomials of the output, and add the
                // corresponding product of polynomials.

                update_with_fmadd_ntt64(
                    output_fft_buffer,
                    ggsw_row.data(),
                    &ntt_poly,
                    is_output_uninit,
                    poly_size,
                    ntt,
                );

                // we initialized `output_fft_buffer, so we can set this to false
                is_output_uninit = false;
            });
        });
    }

    // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
    // In this section, we bring the result from the ntt domain, back to the standard
    // domain, and add it to the output.
    //
    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        izip!(
            out.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer
                .into_chunks(poly_size)
                .map(PolynomialMutView::from_container),
        )
        .for_each(|(out, ntt_poly)| {
            ntt.add_backward(out, ntt_poly);
        });
    }
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub(crate) fn cmux_ntt64_assign(
    ct0: GlweCiphertextMutView<'_, u64>,
    mut ct1: GlweCiphertextMutView<'_, u64>,
    ggsw: NttGgswCiphertextView<'_, u64>,
    ntt: Ntt64View<'_>,
    stack: PodStack<'_>,
) {
    izip!(ct1.as_mut(), ct0.as_ref(),).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub_custom_mod(*c0, ntt.custom_modulus());
    });
    add_external_product_ntt64_assign(ct0, ggsw, &ct1, ntt, stack);
}

#[cfg_attr(__profiling, inline(never))]
pub(crate) fn update_with_fmadd_ntt64(
    output_fft_buffer: &mut [u64],
    lhs_polynomial_list: &[u64],
    ntt_poly: &[u64],
    is_output_uninit: bool,
    poly_size: usize,
    ntt: Ntt64View<'_>,
) {
    if is_output_uninit {
        output_fft_buffer.fill(0);
    }

    izip!(
        output_fft_buffer.into_chunks(poly_size),
        lhs_polynomial_list.into_chunks(poly_size)
    )
    .for_each(|(output_ntt, ggsw_poly)| {
        ntt.plan.mul_accumulate(output_ntt, ggsw_poly, ntt_poly);
    });
}

/// Return the required memory for [`add_external_product_ntt64_assign`].
pub(crate) fn ntt64_add_external_product_assign_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, align)?;
    let decomp_sign_scratch =
        StackReq::try_new_aligned::<u8>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch = StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, align)?;
    let ntt_scratch_single = StackReq::try_new_aligned::<u64>(polynomial_size.0, align)?;
    let _ = &ntt;

    let substack2 = ntt_scratch_single;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = substack1
        .try_and(standard_scratch)?
        .try_and(decomp_sign_scratch)?;
    substack0.try_and(ntt_scratch)
}

/// Return the required memory for [`cmux_ntt64_assign`].
pub(crate) fn ntt64_cmux_scratch(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    ntt64_add_external_product_assign_scratch(glwe_size, polynomial_size, ntt)
}

/// Return the required memory for [`blind_rotate_ntt64_assign_mem_optimized`].
pub fn blind_rotate_ntt64_assign_mem_optimized_requirement(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?
        .try_and(ntt64_cmux_scratch(glwe_size, polynomial_size, ntt)?)
}

/// Return the required memory for [`programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized`].
pub fn programmable_bootstrap_ntt64_lwe_ciphertext_mem_optimized_requirement(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ntt: Ntt64View<'_>,
) -> Result<StackReq, SizeOverflow> {
    blind_rotate_ntt64_assign_mem_optimized_requirement(glwe_size, polynomial_size, ntt)?.try_and(
        StackReq::try_new_aligned::<u64>(glwe_size.0 * polynomial_size.0, CACHELINE_ALIGN)?,
    )
}
