use super::super::math::decomposition::TensorSignedDecompositionLendingIter;
use super::super::math::fft::{FftView, FourierPolynomialList};
use super::super::math::polynomial::FourierPolynomialMutView;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::{
    cm_fourier_ggsw_level_matrix_size, CmDimension, CmGgswCiphertextView, CmGlweCiphertextMutView,
    CmGlweCiphertextView,
};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

/// A GGSW ciphertext in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierCmGgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierCmGgswLevelMatrix<C: Container<Element = c64>> {
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierCmGgswLevelRow<C: Container<Element = c64>> {
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

pub type FourierCmGgswCiphertextView<'a> = FourierCmGgswCiphertext<&'a [c64]>;
pub type FourierCmGgswCiphertextMutView<'a> = FourierCmGgswCiphertext<&'a mut [c64]>;
pub type FourierCmGgswLevelMatrixView<'a> = FourierCmGgswLevelMatrix<&'a [c64]>;
pub type FourierCmGgswLevelMatrixMutView<'a> = FourierCmGgswLevelMatrix<&'a mut [c64]>;
pub type FourierCmGgswLevelRowView<'a> = FourierCmGgswLevelRow<&'a [c64]>;
pub type FourierCmGgswLevelRowMutView<'a> = FourierCmGgswLevelRow<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierCmGgswCiphertext<C> {
    pub fn from_container(
        data: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
                * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            glwe_dimension,
            cm_dimension,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn as_view(&self) -> FourierCmGgswCiphertextView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierCmGgswCiphertextView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierCmGgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierCmGgswCiphertextMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<C: Container<Element = c64>> FourierCmGgswLevelMatrix<C> {
    pub fn new(
        data: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            cm_fourier_ggsw_level_matrix_size(
                glwe_dimension,
                cm_dimension,
                polynomial_size.to_fourier_polynomial_size()
            ),
        );
        Self {
            data,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = FourierCmGgswLevelRow<C>>
    where
        C: Split,
    {
        let row_count = self.row_count();
        self.data
            .split_into(row_count)
            .map(move |slice| FourierCmGgswLevelRow {
                data: slice,
                polynomial_size: self.polynomial_size,
                glwe_dimension: self.glwe_dimension,
                cm_dimension: self.cm_dimension,
                decomposition_level: self.decomposition_level,
            })
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn row_count(&self) -> usize {
        self.glwe_dimension.0 + self.cm_dimension.0
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<C: Container<Element = c64>> FourierCmGgswLevelRow<C> {
    pub fn new(
        data: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * (glwe_dimension.0 + cm_dimension.0)
        );
        Self {
            data,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomposition_level,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<'a> FourierCmGgswCiphertextView<'a> {
    /// Return an iterator over the level matrices.
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = FourierCmGgswLevelMatrixView<'a>> {
        self.fourier
            .data
            .split_into(self.decomposition_level_count.0)
            .enumerate()
            .map(move |(i, slice)| {
                FourierCmGgswLevelMatrixView::new(
                    slice,
                    self.glwe_dimension,
                    self.cm_dimension,
                    self.fourier.polynomial_size,
                    DecompositionLevel(i + 1),
                )
            })
    }
}

/// Return the required memory for [`FourierCmGgswCiphertextMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl FourierCmGgswCiphertextMutView<'_> {
    /// Fill a GGSW ciphertext with the Fourier transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_ggsw: CmGgswCiphertextView<'_, Scalar>,
        fft: FftView<'_>,
        stack: &mut PodStack,
    ) {
        debug_assert_eq!(coef_ggsw.polynomial_size(), self.polynomial_size());
        let fourier_poly_size = coef_ggsw.polynomial_size().to_fourier_polynomial_size().0;

        for (fourier_poly, coef_poly) in izip!(
            self.data().into_chunks(fourier_poly_size),
            coef_ggsw.as_polynomial_list().iter()
        ) {
            fft.forward_as_torus(
                FourierPolynomialMutView { data: fourier_poly },
                coef_poly,
                stack,
            );
        }
    }
}

#[allow(unused)]
type FourierCmGgswCiphertextOwned = FourierCmGgswCiphertext<ABox<[c64]>>;

impl FourierCmGgswCiphertext<ABox<[c64]>> {
    pub fn new(
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * (glwe_dimension.0+cm_dimension.0)
                * (glwe_dimension.0+cm_dimension.0)
                * decomposition_level_count.0
        ]
        .into_boxed_slice();

        FourierCmGgswCiphertext::from_container(
            boxed,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct FourierCmGgswCiphertextList<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    cm_dimension: CmDimension,
    glwe_dimension: GlweDimension,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    count: usize,
}

pub type FourierCmGgswCiphertextListView<'a> = FourierCmGgswCiphertextList<&'a [c64]>;
pub type FourierCmGgswCiphertextListMutView<'a> = FourierCmGgswCiphertextList<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierCmGgswCiphertextList<C> {
    pub fn new(
        data: C,
        count: usize,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            count
                * polynomial_size.to_fourier_polynomial_size().0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
                * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            count,
            glwe_dimension,
            cm_dimension,
            decomposition_level_count,
            decomposition_base_log,
        }
    }

    pub fn data(self) -> C {
        self.fourier.data
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn as_view(&self) -> FourierCmGgswCiphertextListView<'_> {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_ref(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierCmGgswCiphertextListView {
            fourier,
            count: self.count,
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierCmGgswCiphertextListMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_mut(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierCmGgswCiphertextListMutView {
            fourier,
            count: self.count,
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierCmGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier.data.split_into(self.count).map(move |slice| {
            FourierCmGgswCiphertext::from_container(
                slice,
                self.glwe_dimension,
                self.cm_dimension,
                self.fourier.polynomial_size,
                self.decomposition_base_log,
                self.decomposition_level_count,
            )
        })
    }

    pub fn split_at(self, mid: usize) -> (Self, Self)
    where
        C: Split,
    {
        let polynomial_size = self.fourier.polynomial_size;
        let glwe_dimension = self.glwe_dimension;
        let cm_dimension = self.cm_dimension;

        let decomposition_level_count = self.decomposition_level_count;
        let decomposition_base_log = self.decomposition_base_log;

        let (left, right) = self.fourier.data.split_at(
            mid * polynomial_size.to_fourier_polynomial_size().0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
                * decomposition_level_count.0,
        );
        (
            Self::new(
                left,
                mid,
                glwe_dimension,
                cm_dimension,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
            Self::new(
                right,
                self.count - mid,
                glwe_dimension,
                cm_dimension,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
        )
    }
}

/// Return the required memory for [`cm_add_external_product_assign`].
pub fn cm_add_external_product_assign_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch = StackReq::try_new_aligned::<Scalar>(
        (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0,
        align,
    )?;
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;
    let fourier_scratch = StackReq::try_new_aligned::<c64>(
        (glwe_dimension.0 + cm_dimension.0) * fourier_polynomial_size,
        align,
    )?;
    let fourier_scratch_single = StackReq::try_new_aligned::<c64>(fourier_polynomial_size, align)?;

    let substack3 = fft.forward_scratch()?;
    let substack2 = substack3.try_and(fourier_scratch_single)?;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = StackReq::try_any_of([
        substack1.try_and(standard_scratch)?,
        fft.backward_scratch()?,
    ])?;
    substack0.try_and(fourier_scratch)
}

/// Perform the external product of `ggsw` and `glwe`, and adds the result to `out`.
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

/// Return the required memory for [`cm_cmux`].
pub fn cm_cmux_scratch<Scalar>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    cm_add_external_product_assign_scratch::<Scalar>(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        fft,
    )
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
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
    use dyn_stack::GlobalPodBuffer;
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

        let mut mem = GlobalPodBuffer::new(StackReq::try_new_aligned::<u64>(100_000, 512).unwrap());

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

        let cleartexts = (0..cm_dimension.0)
            // .map(|i| Cleartext(i as u64 + 1))
            .map(|_| Cleartext(1))
            .collect_vec();

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
            // println!("{:.3}", *i.0 as i64 as f64 / 2.0.powi(64));
            // println!("{:.3}", *j.0 as i64 as f64 / 2.0.powi(64));

            let diff = j.0.wrapping_sub(*i.0) as i64;

            assert!(diff.abs() < (1 << 57));
        }
    }
}
