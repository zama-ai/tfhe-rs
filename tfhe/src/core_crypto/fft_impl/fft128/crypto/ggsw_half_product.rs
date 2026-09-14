//! Fourier-domain [`half-product GGSW ciphertext`](`HalfProductGgswCiphertext`) and the external
//! product that consumes it.

use super::super::math::fft::Fft128View;
use super::ggsw::{update_with_fmadd, Fourier128GgswLevelRow};
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::entities::half_product_ggsw_ciphertext::{
    assert_valid_decomposition, fourier_half_product_ggsw_ciphertext_size,
    half_product_ggsw_ciphertext_mask_row_count, HalfProductGgswCiphertext,
};
use crate::core_crypto::entities::{GlweCiphertext, PolynomialListView};
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::prelude::ContainerMut;

use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{PodStack, StackReq};

/// A [`half-product GGSW ciphertext`](`HalfProductGgswCiphertext`) in the Fourier domain.
///
/// The four containers follow the same row order as the standard-domain entity: the `k * l_msk`
/// mask rows first, then the `l_body` body rows, levels in decreasing order within each block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fourier128HalfProductGgswCiphertext<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_base_log_mask: DecompositionBaseLog,
    decomposition_level_count_mask: DecompositionLevelCount,
    decomposition_base_log_body: DecompositionBaseLog,
    decomposition_level_count_body: DecompositionLevelCount,
}

impl<C: Container<Element = f64>> Fourier128HalfProductGgswCiphertext<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log_mask: DecompositionBaseLog,
        decomposition_level_count_mask: DecompositionLevelCount,
        decomposition_base_log_body: DecompositionBaseLog,
        decomposition_level_count_body: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        let container_len = fourier_half_product_ggsw_ciphertext_size(
            glwe_size,
            polynomial_size.to_fourier_polynomial_size(),
            decomposition_level_count_mask,
            decomposition_level_count_body,
        );
        assert_eq!(data_re0.container_len(), container_len);
        assert_eq!(data_re1.container_len(), container_len);
        assert_eq!(data_im0.container_len(), container_len);
        assert_eq!(data_im1.container_len(), container_len);

        Self {
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size,
            glwe_size,
            decomposition_base_log_mask,
            decomposition_level_count_mask,
            decomposition_base_log_body,
            decomposition_level_count_body,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log_mask(&self) -> DecompositionBaseLog {
        self.decomposition_base_log_mask
    }

    pub fn decomposition_level_count_mask(&self) -> DecompositionLevelCount {
        self.decomposition_level_count_mask
    }

    pub fn decomposition_base_log_body(&self) -> DecompositionBaseLog {
        self.decomposition_base_log_body
    }

    pub fn decomposition_level_count_body(&self) -> DecompositionLevelCount {
        self.decomposition_level_count_body
    }

    /// Number of Fourier coefficients held by one row (one GLWE ciphertext).
    fn row_len(&self) -> usize {
        self.polynomial_size.to_fourier_polynomial_size().0 * self.glwe_size.0
    }

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }

    pub fn as_view(&self) -> Fourier128HalfProductGgswCiphertext<&[C::Element]>
    where
        C: AsRef<[C::Element]>,
    {
        Fourier128HalfProductGgswCiphertext {
            data_re0: self.data_re0.as_ref(),
            data_re1: self.data_re1.as_ref(),
            data_im0: self.data_im0.as_ref(),
            data_im1: self.data_im1.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log_mask: self.decomposition_base_log_mask,
            decomposition_level_count_mask: self.decomposition_level_count_mask,
            decomposition_base_log_body: self.decomposition_base_log_body,
            decomposition_level_count_body: self.decomposition_level_count_body,
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128HalfProductGgswCiphertext<&mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        Fourier128HalfProductGgswCiphertext {
            data_re0: self.data_re0.as_mut(),
            data_re1: self.data_re1.as_mut(),
            data_im0: self.data_im0.as_mut(),
            data_im1: self.data_im1.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log_mask: self.decomposition_base_log_mask,
            decomposition_level_count_mask: self.decomposition_level_count_mask,
            decomposition_base_log_body: self.decomposition_base_log_body,
            decomposition_level_count_body: self.decomposition_level_count_body,
        }
    }

    /// Length of the mask block, in Fourier coefficients.
    fn mask_len(&self) -> usize {
        half_product_ggsw_ciphertext_mask_row_count(
            self.glwe_size,
            self.decomposition_level_count_mask,
        ) * self.row_len()
    }

    /// Return the containers of the mask block.
    fn mask_data(self) -> (C, C, C, C)
    where
        C: Split,
    {
        let mask_len = self.mask_len();

        (
            self.data_re0.split_at(mask_len).0,
            self.data_re1.split_at(mask_len).0,
            self.data_im0.split_at(mask_len).0,
            self.data_im1.split_at(mask_len).0,
        )
    }

    /// Return the containers of the body block.
    fn body_data(self) -> (C, C, C, C)
    where
        C: Split,
    {
        let mask_len = self.mask_len();

        (
            self.data_re0.split_at(mask_len).1,
            self.data_re1.split_at(mask_len).1,
            self.data_im0.split_at(mask_len).1,
            self.data_im1.split_at(mask_len).1,
        )
    }

    /// Return an iterator over the mask levels, each holding the `k` rows of that level.
    ///
    /// Levels are yielded in decreasing order, matching the order of
    /// [`TensorSignedDecompositionLendingIter`].
    pub fn into_mask_levels(
        self,
    ) -> impl DoubleEndedIterator<Item = Fourier128HalfProductGgswLevelMatrix<C>>
    where
        C: Split,
    {
        let level_count = self.decomposition_level_count_mask.0;
        let row_count = self.glwe_size.to_glwe_dimension().0;
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;

        let (data_re0, data_re1, data_im0, data_im1) = self.mask_data();

        izip_eq!(
            data_re0.split_into(level_count),
            data_re1.split_into(level_count),
            data_im0.split_into(level_count),
            data_im1.split_into(level_count)
        )
        .enumerate()
        .map(move |(i, (data_re0, data_re1, data_im0, data_im1))| {
            Fourier128HalfProductGgswLevelMatrix {
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                polynomial_size,
                glwe_size,
                row_count,
                decomposition_level: DecompositionLevel(level_count - i),
            }
        })
    }

    /// Return an iterator over the body rows, one per body level, in decreasing level order.
    pub fn into_body_rows(self) -> impl DoubleEndedIterator<Item = Fourier128GgswLevelRow<C>>
    where
        C: Split,
    {
        let level_count = self.decomposition_level_count_body.0;
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;

        let (data_re0, data_re1, data_im0, data_im1) = self.body_data();

        izip_eq!(
            data_re0.split_into(level_count),
            data_re1.split_into(level_count),
            data_im0.split_into(level_count),
            data_im1.split_into(level_count)
        )
        .enumerate()
        .map(move |(i, (data_re0, data_re1, data_im0, data_im1))| {
            Fourier128GgswLevelRow::from_container(
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                glwe_size,
                polynomial_size,
                DecompositionLevel(level_count - i),
            )
        })
    }
}

/// One mask level of a [`Fourier128HalfProductGgswCiphertext`].
///
/// Unlike [`crate::core_crypto::entities::Fourier128GgswLevelMatrix`] it holds `k` rows rather than
/// `k + 1`: the body row of this level lives in the body block, and only exists for the first
/// `level_count_body` levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fourier128HalfProductGgswLevelMatrix<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    row_count: usize,
    decomposition_level: DecompositionLevel,
}

impl<C: Container<Element = f64>> Fourier128HalfProductGgswLevelMatrix<C> {
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn row_count(&self) -> usize {
        self.row_count
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    /// Return an iterator over the rows of the level matrix.
    pub fn into_rows(
        self,
    ) -> impl DoubleEndedIterator<Item = Fourier128GgswLevelRow<C>>
           + ExactSizeIterator<Item = Fourier128GgswLevelRow<C>>
    where
        C: Split,
    {
        let row_count = self.row_count;
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;
        let decomposition_level = self.decomposition_level;

        izip_eq!(
            self.data_re0.split_into(row_count),
            self.data_re1.split_into(row_count),
            self.data_im0.split_into(row_count),
            self.data_im1.split_into(row_count)
        )
        .map(move |(data_re0, data_re1, data_im0, data_im1)| {
            Fourier128GgswLevelRow::from_container(
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                glwe_size,
                polynomial_size,
                decomposition_level,
            )
        })
    }
}

impl<Cont> Fourier128HalfProductGgswCiphertext<Cont>
where
    Cont: ContainerMut<Element = f64>,
{
    /// Fill a Fourier half-product GGSW ciphertext with the Fourier transform of a half-product
    /// GGSW ciphertext in the standard domain.
    ///
    /// Both domains share the same row order, so this is a flat polynomial-wise transform.
    pub fn fill_with_forward_fourier<Scalar, ContGgsw>(
        &mut self,
        coef_ggsw: &HalfProductGgswCiphertext<ContGgsw>,
        fft: Fft128View<'_>,
    ) where
        Scalar: UnsignedTorus,
        ContGgsw: Container<Element = Scalar>,
    {
        fn implementation<Scalar: UnsignedTorus>(
            this: Fourier128HalfProductGgswCiphertext<&mut [f64]>,
            coef_ggsw: HalfProductGgswCiphertext<&[Scalar]>,
            fft: Fft128View<'_>,
        ) {
            debug_assert_eq!(coef_ggsw.polynomial_size(), this.polynomial_size());
            debug_assert_eq!(coef_ggsw.glwe_size(), this.glwe_size());
            let poly_size = coef_ggsw.polynomial_size().to_fourier_polynomial_size().0;

            let (data_re0, data_re1, data_im0, data_im1) = this.data();

            for (fourier_re0, fourier_re1, fourier_im0, fourier_im1, coef_poly) in izip_eq!(
                data_re0.into_chunks(poly_size),
                data_re1.into_chunks(poly_size),
                data_im0.into_chunks(poly_size),
                data_im1.into_chunks(poly_size),
                coef_ggsw.as_polynomial_list().iter()
            ) {
                fft.forward_as_torus(
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    coef_poly.as_ref(),
                );
            }
        }
        implementation(self.as_mut_view(), coef_ggsw.as_view(), fft);
    }
}

/// Return the required memory for [`add_external_product_assign_half_product`].
pub fn add_external_product_assign_half_product_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    let align = CACHELINE_ALIGN;
    let glwe_dimension = glwe_size.to_glwe_dimension().0;

    // The mask and body decompositions own separate state buffers, hence two allocations rather
    // than a single one of `glwe_size * polynomial_size`.
    let states_scratch = StackReq::all_of(&[
        StackReq::new_aligned::<Scalar>(glwe_dimension * polynomial_size.0, align),
        StackReq::new_aligned::<Scalar>(polynomial_size.0, align),
    ]);
    // A decomposition term covers the mask polynomials or the body polynomial, never both.
    let term_scratch =
        StackReq::new_aligned::<Scalar>(glwe_dimension.max(1) * polynomial_size.0, align);

    let fourier_scratch = StackReq::new_aligned::<f64>(
        glwe_size.0 * polynomial_size.to_fourier_polynomial_size().0,
        align,
    );
    let fourier_scratch_single =
        StackReq::new_aligned::<f64>(polynomial_size.to_fourier_polynomial_size().0, align);

    let substack2 = StackReq::all_of(&[fourier_scratch_single; 4]);
    let substack1 = substack2.and(term_scratch);
    let substack0 = StackReq::any_of(&[substack1.and(states_scratch), fft.backward_scratch()]);
    substack0.and(StackReq::all_of(&[fourier_scratch; 4]))
}

/// External product between a [`Fourier128HalfProductGgswCiphertext`] and a GLWE ciphertext.
///
/// The `k` mask polynomials of `glwe` are decomposed with the mask parameters and the body
/// polynomial with the body parameters; both partial products accumulate into the same output.
#[cfg_attr(feature = "__profiling", inline(never))]
pub fn add_external_product_assign_half_product<Scalar, ContOut, ContGgsw, ContGlwe>(
    out: &mut GlweCiphertext<ContOut>,
    ggsw: &Fourier128HalfProductGgswCiphertext<ContGgsw>,
    glwe: &GlweCiphertext<ContGlwe>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    ContOut: ContainerMut<Element = Scalar>,
    ContGgsw: Container<Element = f64>,
    ContGlwe: Container<Element = Scalar>,
{
    fn implementation<Scalar: UnsignedTorus>(
        mut out: GlweCiphertext<&mut [Scalar]>,
        ggsw: Fourier128HalfProductGgswCiphertext<&[f64]>,
        glwe: GlweCiphertext<&[Scalar]>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) {
        debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
        debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());
        debug_assert_eq!(glwe.ciphertext_modulus(), out.ciphertext_modulus());

        let align = CACHELINE_ALIGN;
        let polynomial_size = ggsw.polynomial_size();
        let fourier_poly_size = polynomial_size.to_fourier_polynomial_size().0;
        let glwe_size = ggsw.glwe_size();
        let mask_len = glwe_size.to_glwe_dimension().0 * polynomial_size.0;

        assert_valid_decomposition::<Scalar>(
            ggsw.decomposition_base_log_mask(),
            ggsw.decomposition_level_count_mask(),
            "mask",
        );
        assert_valid_decomposition::<Scalar>(
            ggsw.decomposition_base_log_body(),
            ggsw.decomposition_level_count_body(),
            "body",
        );

        let decomposer_mask = SignedDecomposer::<Scalar>::new(
            ggsw.decomposition_base_log_mask(),
            ggsw.decomposition_level_count_mask(),
        );
        let decomposer_body = SignedDecomposer::<Scalar>::new(
            ggsw.decomposition_base_log_body(),
            ggsw.decomposition_level_count_body(),
        );

        let (output_fft_buffer_re0, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size.0, align);
        let (output_fft_buffer_re1, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size.0, align);
        let (output_fft_buffer_im0, stack) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size.0, align);
        let (output_fft_buffer_im1, substack0) =
            stack.make_aligned_raw::<f64>(fourier_poly_size * glwe_size.0, align);

        // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
        // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
        // it has been fully initialized for the first time. A single `update_with_fmadd` writes
        // every one of the `glwe_size` output chunks, so the flag is shared by the mask and body
        // passes.
        let mut is_output_uninit = true;

        {
            let (glwe_mask, glwe_body) = glwe.as_ref().split_at(mask_len);

            let (mut decomposition_mask, substack1) = TensorSignedDecompositionLendingIter::new(
                glwe_mask
                    .iter()
                    .map(|s| decomposer_mask.init_decomposer_state(*s)),
                DecompositionBaseLog(decomposer_mask.base_log),
                DecompositionLevelCount(decomposer_mask.level_count),
                substack0,
            );
            let (mut decomposition_body, substack1) = TensorSignedDecompositionLendingIter::new(
                glwe_body
                    .iter()
                    .map(|s| decomposer_body.init_decomposer_state(*s)),
                DecompositionBaseLog(decomposer_body.base_log),
                DecompositionLevelCount(decomposer_body.level_count),
                substack1,
            );

            for ggsw_level_matrix in ggsw.into_mask_levels() {
                let (glwe_level, glwe_decomp_term, substack2) =
                    collect_next_term(&mut decomposition_mask, substack1, align);
                // The mask decomposition term only covers the `k` mask polynomials, so it is not a
                // full GLWE ciphertext.
                let glwe_decomp_term =
                    PolynomialListView::from_container(&*glwe_decomp_term, polynomial_size);

                for (ggsw_row, glwe_poly) in
                    izip_eq!(ggsw_level_matrix.into_rows(), glwe_decomp_term.iter())
                {
                    debug_assert_eq!(ggsw_row.decomposition_level(), glwe_level);
                    fmadd_row(
                        output_fft_buffer_re0,
                        output_fft_buffer_re1,
                        output_fft_buffer_im0,
                        output_fft_buffer_im1,
                        ggsw_row,
                        glwe_poly.as_ref(),
                        &mut is_output_uninit,
                        fourier_poly_size,
                        fft,
                        substack2,
                    );
                }
            }

            for ggsw_row in ggsw.into_body_rows() {
                let (glwe_level, glwe_decomp_term, substack2) =
                    collect_next_term(&mut decomposition_body, substack1, align);
                debug_assert_eq!(ggsw_row.decomposition_level(), glwe_level);

                fmadd_row(
                    output_fft_buffer_re0,
                    output_fft_buffer_re1,
                    output_fft_buffer_im0,
                    output_fft_buffer_im1,
                    ggsw_row,
                    glwe_decomp_term,
                    &mut is_output_uninit,
                    fourier_poly_size,
                    fft,
                    substack2,
                );
            }
        }

        if !is_output_uninit {
            for (mut out, fourier_re0, fourier_re1, fourier_im0, fourier_im1) in izip_eq!(
                out.as_mut_polynomial_list().iter_mut(),
                output_fft_buffer_re0.into_chunks(fourier_poly_size),
                output_fft_buffer_re1.into_chunks(fourier_poly_size),
                output_fft_buffer_im0.into_chunks(fourier_poly_size),
                output_fft_buffer_im1.into_chunks(fourier_poly_size),
            ) {
                fft.add_backward_as_torus(
                    out.as_mut(),
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
        out.as_mut_view(),
        ggsw.as_view(),
        glwe.as_view(),
        fft,
        stack,
    );
}

/// Forward transform `glwe_poly` and accumulate its product with `ggsw_row` into the output
/// buffers.
#[allow(clippy::too_many_arguments)]
fn fmadd_row<Scalar: UnsignedTorus>(
    output_fft_buffer_re0: &mut [f64],
    output_fft_buffer_re1: &mut [f64],
    output_fft_buffer_im0: &mut [f64],
    output_fft_buffer_im1: &mut [f64],
    ggsw_row: Fourier128GgswLevelRow<&[f64]>,
    glwe_poly: &[Scalar],
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

    fft.forward_as_integer(
        fourier_re0,
        fourier_re1,
        fourier_im0,
        fourier_im1,
        glwe_poly,
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

fn collect_next_term<'a, Scalar: UnsignedTorus>(
    decomposition: &mut TensorSignedDecompositionLendingIter<'_, Scalar>,
    substack1: &'a mut PodStack,
    align: usize,
) -> (DecompositionLevel, &'a mut [Scalar], &'a mut PodStack) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

/// Return the required memory for [`cmux_half_product`].
pub fn cmux_half_product_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> StackReq {
    add_external_product_assign_half_product_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
///
/// # Panics
/// This will panic if ct0 and ct1 are not of the same size
pub fn cmux_half_product<Scalar, ContCt0, ContCt1, ContGgsw>(
    ct0: &mut GlweCiphertext<ContCt0>,
    ct1: &mut GlweCiphertext<ContCt1>,
    ggsw: &Fourier128HalfProductGgswCiphertext<ContGgsw>,
    fft: Fft128View<'_>,
    stack: &mut PodStack,
) where
    Scalar: UnsignedTorus,
    ContCt0: ContainerMut<Element = Scalar>,
    ContCt1: ContainerMut<Element = Scalar>,
    ContGgsw: Container<Element = f64>,
{
    fn implementation<Scalar: UnsignedTorus>(
        mut ct0: GlweCiphertext<&mut [Scalar]>,
        mut ct1: GlweCiphertext<&mut [Scalar]>,
        ggsw: Fourier128HalfProductGgswCiphertext<&[f64]>,
        fft: Fft128View<'_>,
        stack: &mut PodStack,
    ) {
        for (c1, c0) in izip_eq!(ct1.as_mut(), ct0.as_ref()) {
            *c1 = c1.wrapping_sub(*c0);
        }
        add_external_product_assign_half_product(&mut ct0, &ggsw, &ct1, fft, stack);
    }

    implementation(
        ct0.as_mut_view(),
        ct1.as_mut_view(),
        ggsw.as_view(),
        fft,
        stack,
    );
}
