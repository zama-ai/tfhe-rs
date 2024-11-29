use super::super::math::decomposition::TensorSignedDecompositionLendingIter;
use super::super::math::fft::{FftView, FourierPolynomialList};
use super::super::math::polynomial::FourierPolynomialMutView;
use crate::core_crypto::backward_compatibility::fft_impl::FourierGgswCiphertextVersions;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::ggsw_ciphertext::{
    fourier_ggsw_level_matrix_size, GgswCiphertextView,
};
use crate::core_crypto::entities::glwe_ciphertext::{GlweCiphertextMutView, GlweCiphertextView};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;
use tfhe_versionable::Versionize;

/// A GGSW ciphertext in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
#[versionize(FourierGgswCiphertextVersions)]
pub struct FourierGgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierGgswLevelMatrix<C: Container<Element = c64>> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierGgswLevelRow<C: Container<Element = c64>> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

pub type FourierGgswCiphertextView<'a> = FourierGgswCiphertext<&'a [c64]>;
pub type FourierGgswCiphertextMutView<'a> = FourierGgswCiphertext<&'a mut [c64]>;
pub type FourierGgswLevelMatrixView<'a> = FourierGgswLevelMatrix<&'a [c64]>;
pub type FourierGgswLevelMatrixMutView<'a> = FourierGgswLevelMatrix<&'a mut [c64]>;
pub type FourierGgswLevelRowView<'a> = FourierGgswLevelRow<&'a [c64]>;
pub type FourierGgswLevelRowMutView<'a> = FourierGgswLevelRow<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierGgswCiphertext<C> {
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
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

    pub fn as_view(&self) -> FourierGgswCiphertextView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierGgswCiphertextView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierGgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierGgswCiphertextMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<C: Container<Element = c64>> FourierGgswLevelMatrix<C> {
    pub fn new(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            fourier_ggsw_level_matrix_size(glwe_size, polynomial_size.to_fourier_polynomial_size()),
        );
        Self {
            data,
            glwe_size,
            polynomial_size,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = FourierGgswLevelRow<C>>
    where
        C: Split,
    {
        let row_count = self.row_count();
        self.data
            .split_into(row_count)
            .map(move |slice| FourierGgswLevelRow {
                data: slice,
                polynomial_size: self.polynomial_size,
                glwe_size: self.glwe_size,
                decomposition_level: self.decomposition_level,
            })
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn row_count(&self) -> usize {
        self.glwe_size.0
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<C: Container<Element = c64>> FourierGgswLevelRow<C> {
    pub fn new(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size.0
        );
        Self {
            data,
            glwe_size,
            polynomial_size,
            decomposition_level,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<'a> FourierGgswCiphertextView<'a> {
    /// Return an iterator over the level matrices.
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = FourierGgswLevelMatrixView<'a>> {
        let decomposition_level_count = self.decomposition_level_count.0;
        self.fourier
            .data
            .split_into(decomposition_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                FourierGgswLevelMatrixView::new(
                    slice,
                    self.glwe_size,
                    self.fourier.polynomial_size,
                    DecompositionLevel(decomposition_level_count - i),
                )
            })
    }
}

/// Return the required memory for [`FourierGgswCiphertextMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl FourierGgswCiphertextMutView<'_> {
    /// Fill a GGSW ciphertext with the Fourier transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_ggsw: GgswCiphertextView<'_, Scalar>,
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
type FourierGgswCiphertextOwned = FourierGgswCiphertext<ABox<[c64]>>;

impl FourierGgswCiphertext<ABox<[c64]>> {
    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * decomposition_level_count.0
        ]
        .into_boxed_slice();

        FourierGgswCiphertext::from_container(
            boxed,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct FourierGgswCiphertextList<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    glwe_size: GlweSize,
    decomposition_level_count: DecompositionLevelCount,
    decomposition_base_log: DecompositionBaseLog,
    count: usize,
}

pub type FourierGgswCiphertextListView<'a> = FourierGgswCiphertextList<&'a [c64]>;
pub type FourierGgswCiphertextListMutView<'a> = FourierGgswCiphertextList<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierGgswCiphertextList<C> {
    pub fn new(
        data: C,
        count: usize,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            count
                * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            count,
            glwe_size,
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

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    pub fn as_view(&self) -> FourierGgswCiphertextListView<'_> {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_ref(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierGgswCiphertextListView {
            fourier,
            count: self.count,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn as_mut_view(&mut self) -> FourierGgswCiphertextListMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        let fourier = FourierPolynomialList {
            data: self.fourier.data.as_mut(),
            polynomial_size: self.fourier.polynomial_size,
        };
        FourierGgswCiphertextListMutView {
            fourier,
            count: self.count,
            glwe_size: self.glwe_size,
            decomposition_level_count: self.decomposition_level_count,
            decomposition_base_log: self.decomposition_base_log,
        }
    }

    pub fn into_ggsw_iter(self) -> impl DoubleEndedIterator<Item = FourierGgswCiphertext<C>>
    where
        C: Split,
    {
        self.fourier.data.split_into(self.count).map(move |slice| {
            FourierGgswCiphertext::from_container(
                slice,
                self.glwe_size,
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
        let glwe_size = self.glwe_size;
        let decomposition_level_count = self.decomposition_level_count;
        let decomposition_base_log = self.decomposition_base_log;

        let (left, right) = self.fourier.data.split_at(
            mid * polynomial_size.to_fourier_polynomial_size().0
                * glwe_size.0
                * glwe_size.0
                * decomposition_level_count.0,
        );
        (
            Self::new(
                left,
                mid,
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
            Self::new(
                right,
                self.count - mid,
                glwe_size,
                polynomial_size,
                decomposition_base_log,
                decomposition_level_count,
            ),
        )
    }
}

/// Return the required memory for [`add_external_product_assign`].
pub fn add_external_product_assign_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, align)?;
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;
    let fourier_scratch =
        StackReq::try_new_aligned::<c64>(glwe_size.0 * fourier_polynomial_size, align)?;
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
pub fn add_external_product_assign<Scalar>(
    mut out: GlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierGgswCiphertextView<'_>,
    glwe: GlweCiphertextView<Scalar>,
    fft: FftView<'_>,
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
    let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposer::<Scalar>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );

    let (output_fft_buffer, substack0) =
        stack.make_aligned_raw::<c64>(fourier_poly_size * ggsw.glwe_size().0, align);
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
        ggsw.into_levels().for_each(|ggsw_decomp_matrix| {
            // We retrieve the decomposition of this level.
            let (glwe_level, glwe_decomp_term, substack2) =
                collect_next_term(&mut decomposition, substack1, align);
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
                let (fourier, substack3) =
                    substack2.make_aligned_raw::<c64>(fourier_poly_size, align);
                // We perform the forward fft transform for the glwe polynomial
                let fourier = fft
                    .forward_as_integer(
                        FourierPolynomialMutView { data: fourier },
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

pub(crate) fn update_with_fmadd_factor(
    output_fft_buffer: &mut [c64],
    lhs_polynomial_list: &[c64],
    fourier: &[c64],
    factor: c64,
    is_output_uninit: bool,
    fourier_poly_size: usize,
) {
    struct Impl<'a> {
        output_fft_buffer: &'a mut [c64],
        lhs_polynomial_list: &'a [c64],
        fourier: &'a [c64],
        factor: c64,
        is_output_uninit: bool,
        fourier_poly_size: usize,
    }

    impl pulp::WithSimd for Impl<'_> {
        type Output = ();

        #[inline(always)]
        fn with_simd<S: pulp::Simd>(self, simd: S) -> Self::Output {
            let factor = simd.splat_c64s(self.factor);

            for (output_fourier, ggsw_poly) in izip!(
                self.output_fft_buffer.into_chunks(self.fourier_poly_size),
                self.lhs_polynomial_list.into_chunks(self.fourier_poly_size)
            ) {
                let out = S::as_mut_simd_c64s(output_fourier).0;
                let lhs = S::as_simd_c64s(ggsw_poly).0;
                let rhs = S::as_simd_c64s(self.fourier).0;

                if self.is_output_uninit {
                    for (out, &lhs, &rhs) in izip!(out, lhs, rhs) {
                        // NOTE: factor * (lhs * rhs) is more efficient than (lhs * rhs) * factor
                        *out = simd.mul_c64s(factor, simd.mul_c64s(lhs, rhs));
                    }
                } else {
                    for (out, &lhs, &rhs) in izip!(out, lhs, rhs) {
                        // NOTE: see above
                        *out = simd.mul_add_c64s(factor, simd.mul_c64s(lhs, rhs), *out);
                    }
                }
            }
        }
    }

    pulp::Arch::new().dispatch(Impl {
        output_fft_buffer,
        lhs_polynomial_list,
        fourier,
        factor,
        is_output_uninit,
        fourier_poly_size,
    });
}

/// Return the required memory for [`cmux`].
pub fn cmux_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux<Scalar: UnsignedTorus>(
    ct0: GlweCiphertextMutView<'_, Scalar>,
    mut ct1: GlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierGgswCiphertextView<'_>,
    fft: FftView<'_>,
    stack: &mut PodStack,
) {
    izip!(ct1.as_mut(), ct0.as_ref()).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub(*c0);
    });
    add_external_product_assign(ct0, ggsw, ct1.as_view(), fft, stack);
}
