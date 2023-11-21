use super::super::math::fft::{wrapping_add, wrapping_sub, zeroing_shl, zeroing_shr, Fft128View};
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::traits::container::Split;
use crate::core_crypto::commons::traits::contiguous_entity_container::{
    ContiguousEntityContainer, ContiguousEntityContainerMut,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::crypto::ggsw::{
    update_with_fmadd, Fourier128GgswCiphertext,
};
use crate::core_crypto::prelude::{Container, ContainerMut, SignedDecomposer};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, ReborrowMut};

#[cfg_attr(__profiling, inline(never))]
pub fn add_external_product_assign_split<ContOutLo, ContOutHi, ContGgsw, ContGlweLo, ContGlweHi>(
    out_lo: &mut GlweCiphertext<ContOutLo>,
    out_hi: &mut GlweCiphertext<ContOutHi>,
    ggsw: &Fourier128GgswCiphertext<ContGgsw>,
    glwe_lo: &GlweCiphertext<ContGlweLo>,
    glwe_hi: &GlweCiphertext<ContGlweHi>,
    fft: Fft128View<'_>,
    stack: PodStack<'_>,
) where
    ContOutLo: ContainerMut<Element = u64>,
    ContOutHi: ContainerMut<Element = u64>,
    ContGgsw: Container<Element = f64>,
    ContGlweLo: Container<Element = u64>,
    ContGlweHi: Container<Element = u64>,
{
    fn implementation(
        mut out_lo: GlweCiphertext<&mut [u64]>,
        mut out_hi: GlweCiphertext<&mut [u64]>,
        ggsw: Fourier128GgswCiphertext<&[f64]>,
        glwe_lo: GlweCiphertext<&[u64]>,
        glwe_hi: GlweCiphertext<&[u64]>,
        fft: Fft128View<'_>,
        stack: PodStack<'_>,
    ) {
        // we check that the polynomial sizes match
        debug_assert_eq!(ggsw.polynomial_size(), glwe_lo.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), glwe_hi.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out_lo.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out_hi.polynomial_size());
        // we check that the glwe sizes match
        debug_assert_eq!(ggsw.glwe_size(), glwe_lo.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), glwe_hi.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out_lo.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out_hi.glwe_size());

        debug_assert_eq!(out_lo.ciphertext_modulus(), out_hi.ciphertext_modulus());
        debug_assert_eq!(glwe_lo.ciphertext_modulus(), glwe_hi.ciphertext_modulus());
        debug_assert_eq!(glwe_hi.ciphertext_modulus(), out_hi.ciphertext_modulus());

        let align = CACHELINE_ALIGN;
        let poly_size = ggsw.polynomial_size().0;
        let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;
        let glwe_size = ggsw.glwe_size().0;
        let ciphertext_modulus = out_hi.ciphertext_modulus();

        // we round the input mask and body
        let decomposer = SignedDecomposer::<u128>::new(
            ggsw.decomposition_base_log(),
            ggsw.decomposition_level_count(),
        );

        let (mut output_fft_buffer_re0, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * ggsw.glwe_size().0, align);
        let (mut output_fft_buffer_re1, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * ggsw.glwe_size().0, align);
        let (mut output_fft_buffer_im0, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * ggsw.glwe_size().0, align);
        let (mut output_fft_buffer_im1, mut substack0) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * ggsw.glwe_size().0, align);

        // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
        // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
        // it has been fully initialized for the first time.
        let output_fft_buffer_re0 = &mut *output_fft_buffer_re0;
        let output_fft_buffer_re1 = &mut *output_fft_buffer_re1;
        let output_fft_buffer_im0 = &mut *output_fft_buffer_im0;
        let output_fft_buffer_im1 = &mut *output_fft_buffer_im1;
        let mut is_output_uninit = true;

        {
            // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER
            // DOMAIN In this section, we perform the external product in the fourier
            // domain, and accumulate the result in the output_fft_buffer variable.
            let (mut decomposition_states_lo, stack) = substack0
                .rb_mut()
                .make_aligned_raw::<u64>(poly_size * glwe_size, align);
            let (mut decomposition_states_hi, mut substack1) =
                stack.make_aligned_raw::<u64>(poly_size * glwe_size, align);

            let shift = 128 - decomposer.base_log * decomposer.level_count;

            for (out_lo, out_hi, in_lo, in_hi) in izip!(
                &mut *decomposition_states_lo,
                &mut *decomposition_states_hi,
                glwe_lo.as_ref(),
                glwe_hi.as_ref(),
            ) {
                let input = (*in_lo as u128) | ((*in_hi as u128) << 64);
                let value = decomposer.closest_representable(input) >> shift;
                *out_lo = value as u64;
                *out_hi = (value >> 64) as u64;
            }
            let decomposition_states_lo = &mut *decomposition_states_lo;
            let decomposition_states_hi = &mut *decomposition_states_hi;
            let mut current_level = decomposer.level_count;
            let mod_b_mask = (1u128 << decomposer.base_log) - 1;
            let mod_b_mask_lo = mod_b_mask as u64;
            let mod_b_mask_hi = (mod_b_mask >> 64) as u64;

            // We loop through the levels (we reverse to match the order of the decomposition
            // iterator.)
            for ggsw_decomp_matrix in ggsw.into_levels().rev() {
                // We retrieve the decomposition of this level.
                assert_ne!(current_level, 0);
                let glwe_level = DecompositionLevel(current_level);
                current_level -= 1;
                let (mut glwe_decomp_term_lo, stack) = substack1
                    .rb_mut()
                    .make_aligned_raw::<u64>(poly_size * glwe_size, align);
                let (mut glwe_decomp_term_hi, mut substack2) =
                    stack.make_aligned_raw::<u64>(poly_size * glwe_size, align);

                let base_log = decomposer.base_log;

                collect_next_term_split(
                    &mut glwe_decomp_term_lo,
                    &mut glwe_decomp_term_hi,
                    decomposition_states_lo,
                    decomposition_states_hi,
                    mod_b_mask_lo,
                    mod_b_mask_hi,
                    base_log,
                );

                let glwe_decomp_term_lo = &mut *glwe_decomp_term_lo;
                let glwe_decomp_term_hi = &mut *glwe_decomp_term_hi;

                let glwe_decomp_term_lo = GlweCiphertextView::from_container(
                    &*glwe_decomp_term_lo,
                    ggsw.polynomial_size(),
                    ciphertext_modulus,
                );
                let glwe_decomp_term_hi = GlweCiphertextView::from_container(
                    &*glwe_decomp_term_hi,
                    ggsw.polynomial_size(),
                    ciphertext_modulus,
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

                for (ggsw_row, glwe_poly_lo, glwe_poly_hi) in izip!(
                    ggsw_decomp_matrix.into_rows(),
                    glwe_decomp_term_lo.as_polynomial_list().iter(),
                    glwe_decomp_term_hi.as_polynomial_list().iter(),
                ) {
                    let len = fourier_poly_size;
                    let stack = substack2.rb_mut();
                    let (mut fourier_re0, stack) = stack.make_aligned_raw::<f64>(len, align);
                    let (mut fourier_re1, stack) = stack.make_aligned_raw::<f64>(len, align);
                    let (mut fourier_im0, stack) = stack.make_aligned_raw::<f64>(len, align);
                    let (mut fourier_im1, _) = stack.make_aligned_raw::<f64>(len, align);
                    // We perform the forward fft transform for the glwe polynomial
                    fft.forward_as_integer_split(
                        &mut fourier_re0,
                        &mut fourier_re1,
                        &mut fourier_im0,
                        &mut fourier_im1,
                        glwe_poly_lo.as_ref(),
                        glwe_poly_hi.as_ref(),
                    );
                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.

                    update_with_fmadd(
                        output_fft_buffer_re0,
                        output_fft_buffer_re1,
                        output_fft_buffer_im0,
                        output_fft_buffer_im1,
                        ggsw_row,
                        &fourier_re0,
                        &fourier_re1,
                        &fourier_im0,
                        &fourier_im1,
                        is_output_uninit,
                        fourier_poly_size,
                    );

                    // we initialized `output_fft_buffer, so we can set this to false
                    is_output_uninit = false;
                }
            }
        }

        // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
        // In this section, we bring the result from the fourier domain, back to the standard
        // domain, and add it to the output.
        //
        // We iterate over the polynomials in the output.
        if !is_output_uninit {
            for (mut out_lo, mut out_hi, fourier_re0, fourier_re1, fourier_im0, fourier_im1) in izip!(
                out_lo.as_mut_polynomial_list().iter_mut(),
                out_hi.as_mut_polynomial_list().iter_mut(),
                output_fft_buffer_re0.into_chunks(fourier_poly_size),
                output_fft_buffer_re1.into_chunks(fourier_poly_size),
                output_fft_buffer_im0.into_chunks(fourier_poly_size),
                output_fft_buffer_im1.into_chunks(fourier_poly_size),
            ) {
                fft.add_backward_as_torus_split(
                    out_lo.as_mut(),
                    out_hi.as_mut(),
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    substack0.rb_mut(),
                );
            }
        }
    }
    implementation(
        out_lo.as_mut_view(),
        out_hi.as_mut_view(),
        ggsw.as_view(),
        glwe_lo.as_view(),
        glwe_hi.as_view(),
        fft,
        stack,
    );
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
fn collect_next_term_split_avx512(
    simd: pulp::x86::V4,
    glwe_decomp_term_lo: &mut [u64],
    glwe_decomp_term_hi: &mut [u64],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    struct Impl<'a> {
        simd: pulp::x86::V4,
        glwe_decomp_term_lo: &'a mut [u64],
        glwe_decomp_term_hi: &'a mut [u64],
        decomposition_states_lo: &'a mut [u64],
        decomposition_states_hi: &'a mut [u64],
        mod_b_mask_lo: u64,
        mod_b_mask_hi: u64,
        base_log: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn call(self) -> Self::Output {
            use super::super::math::fft::{wrapping_add_avx512, wrapping_sub_avx512};

            let Self {
                simd,
                glwe_decomp_term_lo,
                glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
                mod_b_mask_lo,
                mod_b_mask_hi,
                base_log,
            } = self;

            assert!(base_log < 128);
            assert!(base_log > 0);

            let glwe_decomp_term_lo = pulp::as_arrays_mut::<8, _>(glwe_decomp_term_lo).0;
            let glwe_decomp_term_hi = pulp::as_arrays_mut::<8, _>(glwe_decomp_term_hi).0;
            let decomposition_states_lo = pulp::as_arrays_mut::<8, _>(decomposition_states_lo).0;
            let decomposition_states_hi = pulp::as_arrays_mut::<8, _>(decomposition_states_hi).0;
            let base_log = base_log as u64;
            let shift = base_log - 1;

            let mod_b_mask_lo = simd.splat_u64x8(mod_b_mask_lo);
            let mod_b_mask_hi = simd.splat_u64x8(mod_b_mask_hi);

            let shift_minus_64 = simd.splat_u64x8(shift.wrapping_sub(64));
            let _64_minus_shift = simd.splat_u64x8(64u64.wrapping_sub(shift));
            let shift = simd.splat_u64x8(shift);
            let base_log_minus_64 = simd.splat_u64x8(base_log.wrapping_sub(64));
            let _64_minus_base_log = simd.splat_u64x8(64u64.wrapping_sub(base_log));
            let base_log = simd.splat_u64x8(base_log);

            for (out_lo, out_hi, state_lo, state_hi) in izip!(
                glwe_decomp_term_lo,
                glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
            ) {
                let mut vstate_lo = pulp::cast(*state_lo);
                let mut vstate_hi = pulp::cast(*state_hi);

                let res_lo = simd.and_u64x8(vstate_lo, mod_b_mask_lo);
                let res_hi = simd.and_u64x8(vstate_hi, mod_b_mask_hi);

                vstate_lo = simd.or_u64x8(
                    simd.shr_dyn_u64x8(vstate_hi, base_log_minus_64),
                    simd.or_u64x8(
                        simd.shl_dyn_u64x8(vstate_hi, _64_minus_base_log),
                        simd.shr_dyn_u64x8(vstate_lo, base_log),
                    ),
                );
                vstate_hi = simd.shr_dyn_u64x8(vstate_hi, base_log);

                let res_sub1_lo = simd.wrapping_sub_u64x8(res_lo, simd.splat_u64x8(1));
                let overflow =
                    simd.convert_mask_b8_to_u64x8(simd.cmp_eq_u64x8(res_lo, simd.splat_u64x8(0)));
                let res_sub1_hi = simd.wrapping_add_u64x8(res_hi, overflow);

                let mut carry_lo = simd.and_u64x8(simd.or_u64x8(res_sub1_lo, vstate_lo), res_lo);
                let mut carry_hi = simd.and_u64x8(simd.or_u64x8(res_sub1_hi, vstate_hi), res_hi);

                carry_lo = simd.or_u64x8(
                    simd.shr_dyn_u64x8(carry_hi, shift_minus_64),
                    simd.or_u64x8(
                        simd.shr_dyn_u64x8(carry_lo, shift),
                        simd.shr_dyn_u64x8(carry_hi, _64_minus_shift),
                    ),
                );
                carry_hi = simd.shr_dyn_u64x8(carry_hi, shift);

                (vstate_lo, vstate_hi) =
                    wrapping_add_avx512(simd, (vstate_lo, vstate_hi), (carry_lo, carry_hi));
                *state_lo = pulp::cast(vstate_lo);
                *state_hi = pulp::cast(vstate_hi);

                carry_hi = simd.or_u64x8(
                    simd.or_u64x8(
                        simd.shl_dyn_u64x8(carry_hi, base_log),
                        simd.shr_dyn_u64x8(carry_lo, _64_minus_base_log),
                    ),
                    simd.shl_dyn_u64x8(carry_lo, base_log_minus_64),
                );
                carry_lo = simd.shl_dyn_u64x8(carry_lo, base_log);

                let (res_lo, res_hi) =
                    wrapping_sub_avx512(simd, (res_lo, res_hi), (carry_lo, carry_hi));

                *out_lo = pulp::cast(res_lo);
                *out_hi = pulp::cast(res_hi);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
        mod_b_mask_lo,
        mod_b_mask_hi,
        base_log,
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn collect_next_term_split_avx2(
    simd: pulp::x86::V3,
    glwe_decomp_term_lo: &mut [u64],
    glwe_decomp_term_hi: &mut [u64],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    struct Impl<'a> {
        simd: pulp::x86::V3,
        glwe_decomp_term_lo: &'a mut [u64],
        glwe_decomp_term_hi: &'a mut [u64],
        decomposition_states_lo: &'a mut [u64],
        decomposition_states_hi: &'a mut [u64],
        mod_b_mask_lo: u64,
        mod_b_mask_hi: u64,
        base_log: usize,
    }
    impl pulp::NullaryFnOnce for Impl<'_> {
        type Output = ();

        #[inline(always)]
        // _ is used for varables bginning with a number , which is not allowed
        #[allow(clippy::used_underscore_binding)]
        fn call(self) -> Self::Output {
            use super::super::math::fft::{wrapping_add_avx2, wrapping_sub_avx2};

            let Self {
                simd,
                glwe_decomp_term_lo,
                glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
                mod_b_mask_lo,
                mod_b_mask_hi,
                base_log,
            } = self;

            assert!(base_log < 128);
            assert!(base_log > 0);

            let glwe_decomp_term_lo = pulp::as_arrays_mut::<4, _>(glwe_decomp_term_lo).0;
            let glwe_decomp_term_hi = pulp::as_arrays_mut::<4, _>(glwe_decomp_term_hi).0;
            let decomposition_states_lo = pulp::as_arrays_mut::<4, _>(decomposition_states_lo).0;
            let decomposition_states_hi = pulp::as_arrays_mut::<4, _>(decomposition_states_hi).0;
            let base_log = base_log as u64;
            let shift = base_log - 1;

            let mod_b_mask_lo = simd.splat_u64x4(mod_b_mask_lo);
            let mod_b_mask_hi = simd.splat_u64x4(mod_b_mask_hi);

            let shift_minus_64 = simd.splat_u64x4(shift.wrapping_sub(64));
            let _64_minus_shift = simd.splat_u64x4(64u64.wrapping_sub(shift));
            let shift = simd.splat_u64x4(shift);
            let base_log_minus_64 = simd.splat_u64x4(base_log.wrapping_sub(64));
            let _64_minus_base_log = simd.splat_u64x4(64u64.wrapping_sub(base_log));
            let base_log = simd.splat_u64x4(base_log);

            for (out_lo, out_hi, state_lo, state_hi) in izip!(
                glwe_decomp_term_lo,
                glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
            ) {
                let mut vstate_lo = pulp::cast(*state_lo);
                let mut vstate_hi = pulp::cast(*state_hi);

                let res_lo = simd.and_u64x4(vstate_lo, mod_b_mask_lo);
                let res_hi = simd.and_u64x4(vstate_hi, mod_b_mask_hi);

                vstate_lo = simd.or_u64x4(
                    simd.shr_dyn_u64x4(vstate_hi, base_log_minus_64),
                    simd.or_u64x4(
                        simd.shl_dyn_u64x4(vstate_hi, _64_minus_base_log),
                        simd.shr_dyn_u64x4(vstate_lo, base_log),
                    ),
                );
                vstate_hi = simd.shr_dyn_u64x4(vstate_hi, base_log);

                let res_sub1_lo = simd.wrapping_sub_u64x4(res_lo, simd.splat_u64x4(1));
                let overflow = pulp::cast(simd.cmp_eq_u64x4(res_lo, simd.splat_u64x4(0)));
                let res_sub1_hi = simd.wrapping_add_u64x4(res_hi, overflow);

                let mut carry_lo = simd.and_u64x4(simd.or_u64x4(res_sub1_lo, vstate_lo), res_lo);
                let mut carry_hi = simd.and_u64x4(simd.or_u64x4(res_sub1_hi, vstate_hi), res_hi);

                carry_lo = simd.or_u64x4(
                    simd.shr_dyn_u64x4(carry_hi, shift_minus_64),
                    simd.or_u64x4(
                        simd.shr_dyn_u64x4(carry_lo, shift),
                        simd.shr_dyn_u64x4(carry_hi, _64_minus_shift),
                    ),
                );
                carry_hi = simd.shr_dyn_u64x4(carry_hi, shift);

                (vstate_lo, vstate_hi) =
                    wrapping_add_avx2(simd, (vstate_lo, vstate_hi), (carry_lo, carry_hi));
                *state_lo = pulp::cast(vstate_lo);
                *state_hi = pulp::cast(vstate_hi);

                carry_hi = simd.or_u64x4(
                    simd.or_u64x4(
                        simd.shl_dyn_u64x4(carry_hi, base_log),
                        simd.shr_dyn_u64x4(carry_lo, _64_minus_base_log),
                    ),
                    simd.shl_dyn_u64x4(carry_lo, base_log_minus_64),
                );
                carry_lo = simd.shl_dyn_u64x4(carry_lo, base_log);

                let (res_lo, res_hi) =
                    wrapping_sub_avx2(simd, (res_lo, res_hi), (carry_lo, carry_hi));

                *out_lo = pulp::cast(res_lo);
                *out_hi = pulp::cast(res_hi);
            }
        }
    }

    simd.vectorize(Impl {
        simd,
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
        mod_b_mask_lo,
        mod_b_mask_hi,
        base_log,
    });
}

fn collect_next_term_split_scalar(
    glwe_decomp_term_lo: &mut [u64],
    glwe_decomp_term_hi: &mut [u64],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    assert!(base_log < 128);
    for (out_lo, out_hi, state_lo, state_hi) in izip!(
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
    ) {
        // decompose one level
        let res_lo = *state_lo & mod_b_mask_lo;
        let res_hi = *state_hi & mod_b_mask_hi;
        let base_log = base_log as u64;

        if base_log < 64 {
            *state_lo = zeroing_shl(*state_hi, 64 - base_log) | zeroing_shr(*state_lo, base_log);
            *state_hi = zeroing_shr(*state_hi, base_log);
        } else {
            *state_lo = zeroing_shr(*state_hi, base_log - 64);
            *state_hi = 0;
        }
        let (res_sub1_lo, overflow) = res_lo.overflowing_sub(1);
        let res_sub1_hi = res_hi.wrapping_sub(overflow as u64);

        let mut carry_lo = (res_sub1_lo | *state_lo) & res_lo;
        let mut carry_hi = (res_sub1_hi | *state_hi) & res_hi;

        let shift = base_log - 1;
        if shift < 64 {
            carry_lo = zeroing_shl(carry_hi, 64 - shift) | zeroing_shr(carry_lo, shift);
            carry_hi = zeroing_shr(carry_hi, shift);
        } else {
            carry_lo = zeroing_shr(carry_hi, shift - 64);
            carry_hi = 0;
        }
        (*state_lo, *state_hi) = wrapping_add((*state_lo, *state_hi), (carry_lo, carry_hi));

        if base_log < 64 {
            carry_hi = zeroing_shl(carry_hi, base_log) | zeroing_shr(carry_lo, 64 - base_log);
            carry_lo = zeroing_shl(carry_lo, base_log);
        } else {
            carry_hi = zeroing_shl(carry_lo, base_log - 64);
            carry_lo = 0;
        }
        let (res_lo, res_hi) = wrapping_sub((res_lo, res_hi), (carry_lo, carry_hi));
        *out_lo = res_lo;
        *out_hi = res_hi;
    }
}

fn collect_next_term_split(
    glwe_decomp_term_lo: &mut [u64],
    glwe_decomp_term_hi: &mut [u64],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly-avx512")]
    if let Some(simd) = pulp::x86::V4::try_new() {
        return collect_next_term_split_avx512(
            simd,
            glwe_decomp_term_lo,
            glwe_decomp_term_hi,
            decomposition_states_lo,
            decomposition_states_hi,
            mod_b_mask_lo,
            mod_b_mask_hi,
            base_log,
        );
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(simd) = pulp::x86::V3::try_new() {
        return collect_next_term_split_avx2(
            simd,
            glwe_decomp_term_lo,
            glwe_decomp_term_hi,
            decomposition_states_lo,
            decomposition_states_hi,
            mod_b_mask_lo,
            mod_b_mask_hi,
            base_log,
        );
    }

    collect_next_term_split_scalar(
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
        mod_b_mask_lo,
        mod_b_mask_hi,
        base_log,
    );
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux_split<ContCt0Lo, ContCt0Hi, ContCt1Lo, ContCt1Hi, ContGgsw>(
    ct0_lo: &mut GlweCiphertext<ContCt0Lo>,
    ct0_hi: &mut GlweCiphertext<ContCt0Hi>,
    ct1_lo: &mut GlweCiphertext<ContCt1Lo>,
    ct1_hi: &mut GlweCiphertext<ContCt1Hi>,
    ggsw: &Fourier128GgswCiphertext<ContGgsw>,
    fft: Fft128View<'_>,
    stack: PodStack<'_>,
) where
    ContCt0Lo: ContainerMut<Element = u64>,
    ContCt0Hi: ContainerMut<Element = u64>,
    ContCt1Lo: ContainerMut<Element = u64>,
    ContCt1Hi: ContainerMut<Element = u64>,
    ContGgsw: Container<Element = f64>,
{
    fn implementation(
        mut ct0_lo: GlweCiphertext<&mut [u64]>,
        mut ct0_hi: GlweCiphertext<&mut [u64]>,
        mut ct1_lo: GlweCiphertext<&mut [u64]>,
        mut ct1_hi: GlweCiphertext<&mut [u64]>,
        ggsw: Fourier128GgswCiphertext<&[f64]>,
        fft: Fft128View<'_>,
        stack: PodStack<'_>,
    ) {
        for (c1_lo, c1_hi, c0_lo, c0_hi) in izip!(
            ct1_lo.as_mut(),
            ct1_hi.as_mut(),
            ct0_lo.as_ref(),
            ct0_hi.as_ref(),
        ) {
            let overflow;
            (*c1_lo, overflow) = c1_lo.overflowing_sub(*c0_lo);
            *c1_hi = c1_hi.wrapping_sub(*c0_hi).wrapping_sub(overflow as u64);
        }

        add_external_product_assign_split(
            &mut ct0_lo,
            &mut ct0_hi,
            &ggsw,
            &ct1_lo,
            &ct1_hi,
            fft,
            stack,
        );
    }
    implementation(
        ct0_lo.as_mut_view(),
        ct0_hi.as_mut_view(),
        ct1_lo.as_mut_view(),
        ct1_hi.as_mut_view(),
        ggsw.as_view(),
        fft,
        stack,
    );
}
