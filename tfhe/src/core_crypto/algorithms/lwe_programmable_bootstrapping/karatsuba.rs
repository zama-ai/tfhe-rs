use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::PodStack;

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::collect_next_term;
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use crate::core_crypto::prelude::polynomial_algorithms::*;
use crate::core_crypto::prelude::{
    programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement, ComputationBuffers,
    DecompositionBaseLog, DecompositionLevelCount, ModulusSwitchedLweCiphertext, MonomialDegree,
    SignedDecomposer,
};

pub fn karatsuba_blind_rotate_assign<OutputScalar, OutputCont, KeyCont>(
    msed_input: &impl ModulusSwitchedLweCiphertext<usize>,
    lut: &mut GlweCiphertext<OutputCont>,
    bsk: &LweBootstrapKey<KeyCont>,
) where
    OutputScalar: UnsignedTorus + CastInto<usize>,
    OutputCont: ContainerMut<Element = OutputScalar>,
    KeyCont: Container<Element = OutputScalar>,
{
    assert!(lut.ciphertext_modulus().is_power_of_two());

    let mut buffers = ComputationBuffers::new();

    let fft = Fft::new(bsk.polynomial_size());
    let fft = fft.as_view();

    buffers.resize(
        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<OutputScalar>(
            bsk.glwe_size(),
            bsk.polynomial_size(),
            fft,
        )
        .unwrap()
        .unaligned_bytes_required()
            * 10,
    );

    let stack = buffers.stack();

    assert_eq!(
        bsk.input_lwe_dimension(),
        msed_input.lwe_dimension(),
        "Mismatched input LweDimension. \
        LweBootstrapKey input LweDimension: {:?}, input LweCiphertext LweDimension {:?}.",
        bsk.input_lwe_dimension(),
        msed_input.lwe_dimension(),
    );
    assert_eq!(
        bsk.glwe_size(),
        lut.glwe_size(),
        "Mismatched output LweDimension. \
        LweBootstrapKey input GlweDimension: {:?}, lut GlweDimension {:?}.",
        bsk.glwe_size(),
        lut.glwe_size(),
    );
    assert_eq!(lut.polynomial_size(), bsk.polynomial_size());

    let (local_accumulator_data, stack) =
        stack.collect_aligned(CACHELINE_ALIGN, lut.as_ref().iter().copied());
    let mut local_accumulator = GlweCiphertextMutView::from_container(
        &mut *local_accumulator_data,
        lut.polynomial_size(),
        lut.ciphertext_modulus(),
    );

    let mut lut = local_accumulator.as_mut_view();

    let msed_lwe_mask = msed_input.mask();

    let msed_lwe_body = msed_input.body();

    let monomial_degree = MonomialDegree(msed_lwe_body.cast_into());

    let lut_poly_size = lut.polynomial_size();
    let ciphertext_modulus = lut.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    lut.as_mut_polynomial_list()
        .iter_mut()
        .for_each(|mut poly| {
            let (tmp_poly, _) = stack.make_aligned_raw(poly.as_ref().len(), CACHELINE_ALIGN);

            let mut tmp_poly = Polynomial::from_container(&mut *tmp_poly);
            tmp_poly.as_mut().copy_from_slice(poly.as_ref());
            polynomial_wrapping_monic_monomial_div(&mut poly, &tmp_poly, monomial_degree);
        });

    // We initialize the ct_0 used for the successive cmuxes
    let mut ct0 = lut;
    let (ct1, stack) = stack.make_aligned_raw(ct0.as_ref().len(), CACHELINE_ALIGN);
    let mut ct1 =
        GlweCiphertextMutView::from_container(&mut *ct1, lut_poly_size, ciphertext_modulus);

    for (lwe_mask_element, bootstrap_key_ggsw) in izip_eq!(msed_lwe_mask, bsk.iter()) {
        if lwe_mask_element != 0 {
            let monomial_degree = MonomialDegree(lwe_mask_element);

            // we effectively inline the body of cmux here, merging the initial subtraction
            // operation with the monic polynomial multiplication, then performing the
            // external product manually

            // We rotate ct_1 and subtract ct_0 (first step of cmux) by performing
            // ct_1 <- (ct_0 * X^{a_hat}) - ct_0
            for (mut ct1_poly, ct0_poly) in izip_eq!(
                ct1.as_mut_polynomial_list().iter_mut(),
                ct0.as_polynomial_list().iter(),
            ) {
                polynomial_wrapping_monic_monomial_mul_and_subtract(
                    &mut ct1_poly,
                    &ct0_poly,
                    monomial_degree,
                );
            }

            // as_mut_view is required to keep borrow rules consistent
            // second step of cmux
            karatsuba_add_external_product_assign(
                ct0.as_mut_view(),
                bootstrap_key_ggsw,
                ct1.as_view(),
                stack,
            );
        }
    }

    if !ciphertext_modulus.is_native_modulus() {
        // When we convert back from the fourier domain, integer values will contain up to
        // 53 MSBs with information. In our representation of power of 2
        // moduli < native modulus we fill the MSBs and leave the LSBs
        // empty, this usage of the signed decomposer allows to round while
        // keeping the data in the MSBs
        let signed_decomposer = SignedDecomposer::new(
            DecompositionBaseLog(ciphertext_modulus.get_custom_modulus().ilog2() as usize),
            DecompositionLevelCount(1),
        );
        ct0.as_mut()
            .iter_mut()
            .for_each(|x| *x = signed_decomposer.closest_representable(*x));
    }
}

/// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
#[cfg_attr(feature = "__profiling", inline(never))]
pub fn karatsuba_add_external_product_assign<Scalar>(
    mut out: GlweCiphertextMutView<'_, Scalar>,
    ggsw: GgswCiphertextView<Scalar>,
    glwe: GlweCiphertextView<Scalar>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
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
    let decomposer = SignedDecomposer::<Scalar>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );

    let (output_buffer, substack0) =
        stack.make_aligned_raw::<Scalar>(poly_size * ggsw.glwe_size().0, align);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_buffer = &mut *output_buffer;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIter::new(
            glwe.as_ref()
                .iter()
                .map(|s| decomposer.init_decomposer_state(*s)),
            DecompositionBaseLog(decomposer.base_log),
            DecompositionLevelCount(decomposer.level_count),
            substack0,
        );

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        ggsw.iter().for_each(|ggsw_decomp_matrix| {
            // We retrieve the decomposition of this level.
            let (_glwe_level, glwe_decomp_term, _substack2) =
                collect_next_term(&mut decomposition, &mut substack1, align);
            let glwe_decomp_term = GlweCiphertextView::from_container(
                &*glwe_decomp_term,
                ggsw.polynomial_size(),
                out.ciphertext_modulus(),
            );

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

            izip_eq!(
                ggsw_decomp_matrix.as_glwe_list().iter(),
                glwe_decomp_term.as_polynomial_list().iter()
            )
            .for_each(|(ggsw_row, glwe_poly)| {
                // let (fourier, substack3) =
                //     substack2.rb_mut().make_aligned_raw::<c64>(poly_size, align);
                // // We perform the forward fft transform for the glwe polynomial
                // let fourier = fft
                //     .forward_as_integer(
                //         FourierPolynomialMutView { data: fourier },
                //         glwe_poly,
                //         substack3,
                //     )
                //     .data;
                // // Now we loop through the polynomials of the output, and add the
                // // corresponding product of polynomials.

                // update_with_fmadd(
                //     output_buffer,
                //     ggsw_row.data(),
                //     fourier,
                //     is_output_uninit,
                //     poly_size,
                // );

                // // we initialized `output_fft_buffer, so we can set this to false
                // is_output_uninit = false;

                let row_as_poly_list = ggsw_row.as_polynomial_list();
                if is_output_uninit {
                    for (mut output_poly, row_poly) in output_buffer
                        .chunks_exact_mut(poly_size)
                        .map(Polynomial::from_container)
                        .zip(row_as_poly_list.iter())
                    {
                        polynomial_wrapping_mul(&mut output_poly, &row_poly, &glwe_poly);
                    }
                } else {
                    for (mut output_poly, row_poly) in output_buffer
                        .chunks_exact_mut(poly_size)
                        .map(Polynomial::from_container)
                        .zip(row_as_poly_list.iter())
                    {
                        polynomial_wrapping_add_mul_assign(&mut output_poly, &row_poly, &glwe_poly);
                    }
                }

                is_output_uninit = false;
            });
        });
    }

    // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
    // In this section, we bring the result from the fourier domain, back to the standard
    // domain, and add it to the output.
    //
    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        izip_eq!(
            out.as_mut_polynomial_list().iter_mut(),
            output_buffer
                .into_chunks(poly_size)
                .map(Polynomial::from_container),
        )
        .for_each(|(mut out, res)| polynomial_wrapping_add_assign(&mut out, &res));
    }
}
