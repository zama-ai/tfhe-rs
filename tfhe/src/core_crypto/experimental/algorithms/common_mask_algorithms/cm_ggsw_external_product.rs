use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::Split;
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::fft_impl::fft64::math;
use crate::core_crypto::prelude::{ContiguousEntityContainer, ContiguousEntityContainerMut};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, StackReq};
use itertools::izip;
use math::decomposition::TensorSignedDecompositionLendingIter;
use math::fft::FftView;
use math::polynomial::FourierPolynomialMutView;
use tfhe_fft::c64;

pub fn cm_add_external_product_assign_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    let align = CACHELINE_ALIGN;
    let standard_scratch = StackReq::new_aligned::<Scalar>(
        cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size),
        align,
    );
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size();
    let fourier_scratch = StackReq::new_aligned::<c64>(
        cm_glwe_ciphertext_fourier_size(glwe_dimension, cm_dimension, fourier_polynomial_size),
        align,
    );
    let fourier_scratch_single = StackReq::new_aligned::<c64>(fourier_polynomial_size.0, align);

    let substack3 = fft.forward_scratch();
    let substack2 = substack3.and(fourier_scratch_single);
    let substack1 = substack2.and(standard_scratch);
    let substack0 = StackReq::any_of(&[substack1.and(standard_scratch), fft.backward_scratch()]);
    substack0.and(fourier_scratch)
}

#[cfg_attr(feature = "__profiling", inline(never))]
pub fn cm_add_external_product_assign<Scalar>(
    mut out: CmGlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierCmGgswCiphertextView<'_>,
    glwe: CmGlweCiphertextView<Scalar>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
{
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_dimension(), glwe.glwe_dimension());
    debug_assert_eq!(ggsw.glwe_dimension(), out.glwe_dimension());

    let align = CACHELINE_ALIGN;
    let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposer::<Scalar>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );

    let (output_fft_buffer, substack0) = stack.make_aligned_raw::<c64>(
        fourier_poly_size * (ggsw.glwe_dimension().0 + ggsw.cm_dimension().0),
        align,
    );
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, substack1) = TensorSignedDecompositionLendingIter::new(
            glwe.as_ref()
                .iter()
                .map(|s| decomposer.init_decomposer_state(*s)),
            DecompositionBaseLog(decomposer.base_log),
            DecompositionLevelCount(decomposer.level_count),
            substack0,
        );

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        ggsw.into_levels().rev().for_each(|ggsw_decomp_matrix| {
            // We retrieve the decomposition of this level.
            let (glwe_level, glwe_decomp_term, substack2) =
                collect_next_term(&mut decomposition, substack1, align);
            let glwe_decomp_term = CmGlweCiphertextView::from_container(
                &*glwe_decomp_term,
                ggsw.glwe_dimension(),
                ggsw.cm_dimension(),
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
                let (mut fourier, substack3) =
                    substack2.make_aligned_raw::<c64>(fourier_poly_size, align);
                // We perform the forward fft transform for the glwe polynomial
                let fourier = fft
                    .forward_as_integer(
                        FourierPolynomialMutView { data: &mut fourier },
                        glwe_poly,
                        substack3,
                    )
                    .data;
                // Now we loop through the polynomials of the output, and add the
                // corresponding product of polynomials.

                update_with_fmadd(
                    output_fft_buffer,
                    ggsw_row.data(),
                    fourier,
                    is_output_uninit,
                    fourier_poly_size,
                );

                // we initialized `output_fft_buffer, so we can set this to false
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
        izip!(
            out.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer
                .into_chunks(fourier_poly_size)
                .map(|slice| FourierPolynomialMutView { data: slice }),
        )
        .for_each(|(out, fourier)| {
            // The fourier buffer is not re-used afterwards so we can use the in-place version of
            // the add_backward_as_torus function
            fft.add_backward_in_place_as_torus(out, fourier, substack0);
        });
    }
}

#[cfg_attr(feature = "__profiling", inline(never))]
pub(crate) fn collect_next_term<'a, Scalar: UnsignedTorus>(
    decomposition: &mut TensorSignedDecompositionLendingIter<'_, Scalar>,
    substack1: &'a mut PodStack,
    align: usize,
) -> (DecompositionLevel, &'a mut [Scalar], &'a mut PodStack) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

#[cfg_attr(feature = "__profiling", inline(never))]
pub(crate) fn update_with_fmadd(
    output_fft_buffer: &mut [c64],
    lhs_polynomial_list: &[c64],
    fourier: &[c64],
    is_output_uninit: bool,
    fourier_poly_size: usize,
) {
    struct Impl<'a> {
        output_fft_buffer: &'a mut [c64],
        lhs_polynomial_list: &'a [c64],
        fourier: &'a [c64],
        is_output_uninit: bool,
        fourier_poly_size: usize,
    }

    impl pulp::WithSimd for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn with_simd<S: pulp::Simd>(self, simd: S) -> Self::Output {
            // Introducing a function boundary here means that the slices
            // get `noalias` markers, possibly allowing better optimizations from LLVM.
            //
            // see:
            // https://github.com/rust-lang/rust/blob/56e1aaadb31542b32953292001be2312810e88fd/library/core/src/slice/mod.rs#L960-L966
            #[inline(always)]
            fn implementation<S: pulp::Simd>(
                simd: S,
                output_fft_buffer: &mut [c64],
                lhs_polynomial_list: &[c64],
                fourier: &[c64],
                is_output_uninit: bool,
                fourier_poly_size: usize,
            ) {
                let rhs = S::as_simd_c64s(fourier).0;

                if is_output_uninit {
                    for (output_fourier, ggsw_poly) in izip!(
                        output_fft_buffer.into_chunks(fourier_poly_size),
                        lhs_polynomial_list.into_chunks(fourier_poly_size)
                    ) {
                        let out = S::as_mut_simd_c64s(output_fourier).0;
                        let lhs = S::as_simd_c64s(ggsw_poly).0;

                        for (out, lhs, rhs) in izip!(out, lhs, rhs) {
                            *out = simd.mul_c64s(*lhs, *rhs);
                        }
                    }
                } else {
                    for (output_fourier, ggsw_poly) in izip!(
                        output_fft_buffer.into_chunks(fourier_poly_size),
                        lhs_polynomial_list.into_chunks(fourier_poly_size)
                    ) {
                        let out = S::as_mut_simd_c64s(output_fourier).0;
                        let lhs = S::as_simd_c64s(ggsw_poly).0;

                        for (out, lhs, rhs) in izip!(out, lhs, rhs) {
                            *out = simd.mul_add_c64s(*lhs, *rhs, *out);
                        }
                    }
                }
            }

            implementation(
                simd,
                self.output_fft_buffer,
                self.lhs_polynomial_list,
                self.fourier,
                self.is_output_uninit,
                self.fourier_poly_size,
            );
        }
    }

    pulp::Arch::new().dispatch(Impl {
        output_fft_buffer,
        lhs_polynomial_list,
        fourier,
        is_output_uninit,
        fourier_poly_size,
    });
}

pub fn cm_cmux_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> StackReq {
    cm_add_external_product_assign_scratch::<Scalar>(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        fft,
    )
}

pub fn cm_cmux<Scalar: UnsignedTorus>(
    ct0: CmGlweCiphertextMutView<'_, Scalar>,
    mut ct1: CmGlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierCmGgswCiphertextView<'_>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) {
    izip!(ct1.as_mut(), ct0.as_ref()).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub(*c0);
    });
    cm_add_external_product_assign(ct0, ggsw, ct1.as_view(), fft, stack);
}

#[cfg(test)]
mod tests {
    use dyn_stack::PodBuffer;
    use itertools::Itertools;

    use super::*;
    use crate::core_crypto::prelude::*;

    #[test]
    fn test_cm_ep() {
        let glwe_dimension = GlweDimension(2);
        let cm_dimension = CmDimension(2);
        let polynomial_size = PolynomialSize(64);
        let decomp_base_log = DecompositionBaseLog(8);
        let decomp_level_count = DecompositionLevelCount(3);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let noise_distribution =
            DynamicDistribution::new_gaussian_from_std_dev(StandardDev(0.0000006791658447437413));

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        let mut mem = PodBuffer::new(StackReq::new_aligned::<u64>(100_000, 512));

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let glwe_secret_keys = (0..cm_dimension.0)
            .map(|_| {
                allocate_and_generate_new_binary_glwe_secret_key(
                    glwe_dimension,
                    polynomial_size,
                    &mut secret_generator,
                )
            })
            .collect_vec();

        let mut ggsw = CmGgswCiphertext::new(
            0u64,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        );

        let cleartexts = (0..cm_dimension.0).map(|_| Cleartext(1)).collect_vec();

        encrypt_constant_cm_ggsw_ciphertext(
            &glwe_secret_keys,
            &mut ggsw,
            &cleartexts,
            noise_distribution,
            &mut encryption_generator,
        );

        let mut ggsw_fourier = FourierCmGgswCiphertext::new(
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        );

        let stack = PodStack::new(&mut mem);

        ggsw_fourier
            .as_mut_view()
            .fill_with_forward_fourier(ggsw.as_view(), fft, stack);

        let mut glwe_in = CmGlweCiphertext::new(
            0u64,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        );

        let input_plaintext_list = PlaintextList::from_container(
            (0..cm_dimension.0 * polynomial_size.0)
                .map(|i| (i as u64 + 1) << 60)
                .collect_vec(),
        );

        encrypt_cm_glwe_ciphertext(
            &glwe_secret_keys,
            &mut glwe_in,
            &input_plaintext_list,
            noise_distribution,
            &mut encryption_generator,
        );

        let mut glwe_out = CmGlweCiphertext::new(
            0u64,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        );

        let stack = PodStack::new(&mut mem);

        super::cm_add_external_product_assign(
            glwe_out.as_mut_view(),
            ggsw_fourier.as_view(),
            glwe_in.as_view(),
            fft,
            stack,
        );

        let mut decrypted =
            PlaintextList::new(0, PlaintextCount(cm_dimension.0 * polynomial_size.0));

        decrypt_cm_glwe_ciphertext(&glwe_secret_keys, &glwe_out, &mut decrypted);

        for (i, j) in input_plaintext_list.iter().zip_eq(decrypted.iter()) {
            let diff = j.0.wrapping_sub(*i.0) as i64;

            assert!(diff.abs() < (1 << 57));
        }
    }
}
