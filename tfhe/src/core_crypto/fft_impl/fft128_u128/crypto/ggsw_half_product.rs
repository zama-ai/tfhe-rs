//! `u128` (split lo/hi `u64`-limb) external product for [`half-product GGSW
//! ciphertexts`](`Fourier128HalfProductGgswCiphertext`).

use super::super::math::fft::Fft128View;
use super::ggsw::collect_next_term_split;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::traits::container::Split;
use crate::core_crypto::commons::traits::contiguous_entity_container::{
    ContiguousEntityContainer, ContiguousEntityContainerMut,
};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft128::crypto::ggsw::{
    update_with_fmadd, Fourier128GgswLevelRow,
};
use crate::core_crypto::fft_impl::fft128::crypto::ggsw_half_product::Fourier128HalfProductGgswCiphertext;
use crate::core_crypto::prelude::{Container, ContainerMut, SignedDecomposer};
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::PodStack;

/// Split (lo/hi `u64`-limb) analog of
/// [`add_external_product_assign_half_product`](crate::core_crypto::fft_impl::fft128::crypto::ggsw_half_product::add_external_product_assign_half_product).
///
/// The decomposition state array is split at `k * N` so that the mask polynomials and the body
/// polynomial advance with their own level counter and base.
#[cfg_attr(feature = "__profiling", inline(never))]
pub fn add_external_product_assign_split_half_product<
    ContOutLo,
    ContOutHi,
    ContGgsw,
    ContGlweLo,
    ContGlweHi,
>(
    out_lo: &mut GlweCiphertext<ContOutLo>,
    out_hi: &mut GlweCiphertext<ContOutHi>,
    ggsw: &Fourier128HalfProductGgswCiphertext<ContGgsw>,
    glwe_lo: &GlweCiphertext<ContGlweLo>,
    glwe_hi: &GlweCiphertext<ContGlweHi>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
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
        ggsw: Fourier128HalfProductGgswCiphertext<&[f64]>,
        glwe_lo: GlweCiphertext<&[u64]>,
        glwe_hi: GlweCiphertext<&[u64]>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) {
        debug_assert_eq!(ggsw.polynomial_size(), glwe_lo.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), glwe_hi.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out_lo.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out_hi.polynomial_size());
        debug_assert_eq!(ggsw.glwe_size(), glwe_lo.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), glwe_hi.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out_lo.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out_hi.glwe_size());
        debug_assert_eq!(out_lo.ciphertext_modulus(), out_hi.ciphertext_modulus());
        debug_assert_eq!(glwe_lo.ciphertext_modulus(), glwe_hi.ciphertext_modulus());

        let align = CACHELINE_ALIGN;
        let polynomial_size = ggsw.polynomial_size();
        let poly_size = polynomial_size.0;
        let fourier_poly_size = polynomial_size.to_fourier_polynomial_size().0;
        let glwe_size = ggsw.glwe_size().0;
        let mask_len = ggsw.glwe_size().to_glwe_dimension().0 * poly_size;

        // The vectorised `collect_next_term_split` variants process 8 (AVX-512) or 4 (AVX2)
        // elements at a time and drop the remainder, so both regions must be a multiple of the
        // widest lane count.
        assert!(
            poly_size.is_multiple_of(8),
            "The half-product split external product requires a polynomial size multiple of 8, \
            got {poly_size}"
        );

        let decomposer_mask = SignedDecomposer::<u128>::new(
            ggsw.decomposition_base_log_mask(),
            ggsw.decomposition_level_count_mask(),
        );
        let decomposer_body = SignedDecomposer::<u128>::new(
            ggsw.decomposition_base_log_body(),
            ggsw.decomposition_level_count_body(),
        );

        let (output_fft_buffer_re0, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size, align);
        let (output_fft_buffer_re1, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size, align);
        let (output_fft_buffer_im0, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size, align);
        let (output_fft_buffer_im1, substack0) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size, align);

        // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
        // the cost of filling it up with zeros. A single `update_with_fmadd` writes every one of
        // the `glwe_size` output chunks, so the flag is shared by the mask and body passes.
        let mut is_output_uninit = true;

        {
            let (decomposition_states_lo, stack) =
                substack0.make_aligned_raw::<u64>(poly_size * glwe_size, align);
            let (decomposition_states_hi, substack1) =
                stack.make_aligned_raw::<u64>(poly_size * glwe_size, align);

            for (out_lo, out_hi, in_lo, in_hi, is_mask) in izip_eq!(
                &mut *decomposition_states_lo,
                &mut *decomposition_states_hi,
                glwe_lo.as_ref(),
                glwe_hi.as_ref(),
                (0..poly_size * glwe_size).map(|i| i < mask_len),
            ) {
                let input = (*in_lo as u128) | ((*in_hi as u128) << 64);
                let value = if is_mask {
                    decomposer_mask.init_decomposer_state(input)
                } else {
                    decomposer_body.init_decomposer_state(input)
                };
                *out_lo = value as u64;
                *out_hi = (value >> 64) as u64;
            }

            let (mask_states_lo, body_states_lo) = decomposition_states_lo.split_at_mut(mask_len);
            let (mask_states_hi, body_states_hi) = decomposition_states_hi.split_at_mut(mask_len);

            let mod_b_mask_mask = (1u128 << decomposer_mask.base_log) - 1;
            let mod_b_mask_body = (1u128 << decomposer_body.base_log) - 1;

            // A decomposition term covers either the mask polynomials or the body polynomial, never
            // both, so `mask_len` (>= `poly_size`) is enough for either pass.
            let term_len = mask_len.max(poly_size);
            let (glwe_decomp_term_lo, stack) = substack1.make_aligned_raw::<u64>(term_len, align);
            let (glwe_decomp_term_hi, substack2) = stack.make_aligned_raw::<u64>(term_len, align);

            let mut current_level = decomposer_mask.level_count;
            for ggsw_level_matrix in ggsw.into_mask_levels() {
                assert_ne!(current_level, 0);
                let glwe_level = DecompositionLevel(current_level);
                current_level -= 1;

                let term_lo = &mut glwe_decomp_term_lo[..mask_len];
                let term_hi = &mut glwe_decomp_term_hi[..mask_len];

                collect_next_term_split(
                    term_lo,
                    term_hi,
                    mask_states_lo,
                    mask_states_hi,
                    mod_b_mask_mask as u64,
                    (mod_b_mask_mask >> 64) as u64,
                    decomposer_mask.base_log,
                );

                let term_lo = PolynomialListView::from_container(&*term_lo, polynomial_size);
                let term_hi = PolynomialListView::from_container(&*term_hi, polynomial_size);

                for (ggsw_row, glwe_poly_lo, glwe_poly_hi) in izip_eq!(
                    ggsw_level_matrix.into_rows(),
                    term_lo.iter(),
                    term_hi.iter(),
                ) {
                    debug_assert_eq!(ggsw_row.decomposition_level(), glwe_level);
                    fmadd_row_split(
                        output_fft_buffer_re0,
                        output_fft_buffer_re1,
                        output_fft_buffer_im0,
                        output_fft_buffer_im1,
                        ggsw_row,
                        glwe_poly_lo.as_ref(),
                        glwe_poly_hi.as_ref(),
                        &mut is_output_uninit,
                        fourier_poly_size,
                        fft,
                        substack2,
                    );
                }
            }

            let mut current_level = decomposer_body.level_count;
            for ggsw_row in ggsw.into_body_rows() {
                assert_ne!(current_level, 0);
                let glwe_level = DecompositionLevel(current_level);
                current_level -= 1;
                debug_assert_eq!(ggsw_row.decomposition_level(), glwe_level);

                let term_lo = &mut glwe_decomp_term_lo[..poly_size];
                let term_hi = &mut glwe_decomp_term_hi[..poly_size];

                collect_next_term_split(
                    term_lo,
                    term_hi,
                    body_states_lo,
                    body_states_hi,
                    mod_b_mask_body as u64,
                    (mod_b_mask_body >> 64) as u64,
                    decomposer_body.base_log,
                );

                fmadd_row_split(
                    output_fft_buffer_re0,
                    output_fft_buffer_re1,
                    output_fft_buffer_im0,
                    output_fft_buffer_im1,
                    ggsw_row,
                    term_lo,
                    term_hi,
                    &mut is_output_uninit,
                    fourier_poly_size,
                    fft,
                    substack2,
                );
            }
        }

        if !is_output_uninit {
            for (mut out_lo, mut out_hi, fourier_re0, fourier_re1, fourier_im0, fourier_im1) in izip_eq!(
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
                    substack0,
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

/// Forward transform one lo/hi polynomial and accumulate its product with `ggsw_row`.
#[allow(clippy::too_many_arguments)]
fn fmadd_row_split(
    output_fft_buffer_re0: &mut [f64],
    output_fft_buffer_re1: &mut [f64],
    output_fft_buffer_im0: &mut [f64],
    output_fft_buffer_im1: &mut [f64],
    ggsw_row: Fourier128GgswLevelRow<&[f64]>,
    glwe_poly_lo: &[u64],
    glwe_poly_hi: &[u64],
    is_output_uninit: &mut bool,
    fourier_poly_size: usize,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) {
    let align = CACHELINE_ALIGN;
    let (fourier_re0, stack) = stack.make_aligned_raw::<f64>(fourier_poly_size, align);
    let (fourier_re1, stack) = stack.make_aligned_raw::<f64>(fourier_poly_size, align);
    let (fourier_im0, stack) = stack.make_aligned_raw::<f64>(fourier_poly_size, align);
    let (fourier_im1, _) = stack.make_aligned_raw::<f64>(fourier_poly_size, align);

    fft.forward_as_integer_split(
        fourier_re0,
        fourier_re1,
        fourier_im0,
        fourier_im1,
        glwe_poly_lo,
        glwe_poly_hi,
    );

    update_with_fmadd(
        output_fft_buffer_re0,
        output_fft_buffer_re1,
        output_fft_buffer_im0,
        output_fft_buffer_im1,
        ggsw_row,
        fourier_re0,
        fourier_re1,
        fourier_im0,
        fourier_im1,
        *is_output_uninit,
        fourier_poly_size,
    );

    *is_output_uninit = false;
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
///
/// # Panics
/// This will panic if ct0_lo, ct0_hi, ct1_lo and ct1_hi are not of the same size
pub fn cmux_split_half_product<ContCt0Lo, ContCt0Hi, ContCt1Lo, ContCt1Hi, ContGgsw>(
    ct0_lo: &mut GlweCiphertext<ContCt0Lo>,
    ct0_hi: &mut GlweCiphertext<ContCt0Hi>,
    ct1_lo: &mut GlweCiphertext<ContCt1Lo>,
    ct1_hi: &mut GlweCiphertext<ContCt1Hi>,
    ggsw: &Fourier128HalfProductGgswCiphertext<ContGgsw>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
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
        ggsw: Fourier128HalfProductGgswCiphertext<&[f64]>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) {
        for (c1_lo, c1_hi, c0_lo, c0_hi) in izip_eq!(
            ct1_lo.as_mut(),
            ct1_hi.as_mut(),
            ct0_lo.as_ref(),
            ct0_hi.as_ref()
        ) {
            let (diff, overflow) = (*c1_lo).overflowing_sub(*c0_lo);
            *c1_lo = diff;
            *c1_hi = (*c1_hi).wrapping_sub(*c0_hi).wrapping_sub(overflow as u64);
        }
        add_external_product_assign_split_half_product(
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
