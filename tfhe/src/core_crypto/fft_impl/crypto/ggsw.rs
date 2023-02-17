use core::mem::MaybeUninit;

use super::super::math::decomposition::TensorSignedDecompositionLendingIter;
use super::super::math::fft::{FftView, FourierPolynomialList};
use super::super::math::polynomial::{FourierPolynomialUninitMutView, FourierPolynomialView};
use super::super::{as_mut_uninit, assume_init_mut};
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use concrete_fft::c64;
use dyn_stack::{DynStack, ReborrowMut, SizeOverflow, StackReq};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// A GGSW ciphertext in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
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
    row_count: usize,
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
        row_count: usize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size.0 * row_count
        );
        Self {
            data,
            polynomial_size,
            glwe_size,
            row_count,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = FourierGgswLevelRow<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.row_count)
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
        self.row_count
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
            polynomial_size,
            glwe_size,
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
        self.fourier
            .data
            .split_into(self.decomposition_level_count.0)
            .enumerate()
            .map(move |(i, slice)| {
                FourierGgswLevelMatrixView::new(
                    slice,
                    self.glwe_size,
                    self.fourier.polynomial_size,
                    self.glwe_size.0,
                    DecompositionLevel(i + 1),
                )
            })
    }
}

/// Return the required memory for [`FourierGgswCiphertextMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl<'a> FourierGgswCiphertextMutView<'a> {
    /// Fill a GGSW ciphertext with the Fourier transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar: UnsignedTorus>(
        self,
        coef_ggsw: GgswCiphertextView<'_, Scalar>,
        fft: FftView<'_>,
        mut stack: DynStack<'_>,
    ) {
        debug_assert_eq!(coef_ggsw.polynomial_size(), self.polynomial_size());
        let fourier_poly_size = coef_ggsw.polynomial_size().to_fourier_polynomial_size().0;

        for (fourier_poly, coef_poly) in izip!(
            self.data().into_chunks(fourier_poly_size),
            coef_ggsw.as_polynomial_list().iter()
        ) {
            // SAFETY: forward_as_torus doesn't write any uninitialized values into its output
            fft.forward_as_torus(
                FourierPolynomialUninitMutView {
                    data: unsafe { as_mut_uninit(fourier_poly) },
                },
                coef_poly,
                stack.rb_mut(),
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
    ) -> FourierGgswCiphertext<ABox<[c64]>> {
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
#[cfg_attr(__profiling, inline(never))]
pub fn add_external_product_assign<Scalar, InputGlweCont>(
    mut out: GlweCiphertextMutView<'_, Scalar>,
    ggsw: FourierGgswCiphertextView<'_>,
    glwe: GlweCiphertext<InputGlweCont>,
    fft: FftView<'_>,
    stack: DynStack<'_>,
) where
    Scalar: UnsignedTorus,
    InputGlweCont: Container<Element = Scalar>,
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

    let (mut output_fft_buffer, mut substack0) =
        stack.make_aligned_uninit::<c64>(fourier_poly_size * ggsw.glwe_size().0, align);
    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer = &mut *output_fft_buffer;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIter::new(
            glwe.as_ref()
                .iter()
                .map(|s| decomposer.closest_representable(*s)),
            DecompositionBaseLog(decomposer.base_log),
            DecompositionLevelCount(decomposer.level_count),
            substack0.rb_mut(),
        );

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        ggsw.into_levels().rev().for_each(|ggsw_decomp_matrix| {
            // We retrieve the decomposition of this level.
            let (glwe_level, glwe_decomp_term, mut substack2) =
                collect_next_term(&mut decomposition, &mut substack1, align);
            let glwe_decomp_term =
                GlweCiphertextView::from_container(&*glwe_decomp_term, ggsw.polynomial_size());
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
                let (mut fourier, substack3) = substack2
                    .rb_mut()
                    .make_aligned_uninit::<c64>(fourier_poly_size, align);
                // We perform the forward fft transform for the glwe polynomial
                let fourier = fft
                    .forward_as_integer(
                        FourierPolynomialUninitMutView { data: &mut fourier },
                        glwe_poly,
                        substack3,
                    )
                    .data;
                // Now we loop through the polynomials of the output, and add the
                // corresponding product of polynomials.

                // SAFETY: see comment above definition of `output_fft_buffer`
                unsafe {
                    update_with_fmadd(
                        output_fft_buffer,
                        ggsw_row,
                        fourier,
                        is_output_uninit,
                        fourier_poly_size,
                    )
                };

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
        // SAFETY: output_fft_buffer is initialized, since `is_output_uninit` is false
        let output_fft_buffer = &*unsafe { assume_init_mut(output_fft_buffer) };
        izip!(
            out.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer
                .into_chunks(fourier_poly_size)
                .map(|slice| FourierPolynomialView { data: slice }),
        )
        .for_each(|(out, fourier)| {
            fft.add_backward_as_torus(out, fourier, substack0.rb_mut());
        });
    }
}

#[cfg_attr(__profiling, inline(never))]
fn collect_next_term<'a, Scalar: UnsignedTorus>(
    decomposition: &mut TensorSignedDecompositionLendingIter<'_, Scalar>,
    substack1: &'a mut DynStack,
    align: usize,
) -> (
    DecompositionLevel,
    dyn_stack::DynArray<'a, Scalar>,
    DynStack<'a>,
) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.rb_mut().collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

/// # Note
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
///
/// # Safety
///
///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
///  - `is_x86_feature_detected!("avx512f")` must be true.
#[cfg(all(
    feature = "nightly-avx512",
    any(target_arch = "x86_64", target_arch = "x86")
))]
#[target_feature(enable = "avx512f")]
unsafe fn update_with_fmadd_avx512(
    output_fourier: &mut [MaybeUninit<c64>],
    ggsw_poly: &[c64],
    fourier: &[c64],
    is_output_uninit: bool,
) {
    let n = output_fourier.len();

    debug_assert_eq!(n, ggsw_poly.len());
    debug_assert_eq!(n, fourier.len());
    debug_assert_eq!(n % 4, 0);

    let out = output_fourier.as_mut_ptr();
    let lhs = ggsw_poly.as_ptr();
    let rhs = fourier.as_ptr();

    // 4×c64 per register

    if is_output_uninit {
        for i in 0..n / 4 {
            let i = 4 * i;
            let ab = _mm512_loadu_pd(lhs.add(i) as _);
            let xy = _mm512_loadu_pd(rhs.add(i) as _);
            let aa = _mm512_unpacklo_pd(ab, ab);
            let bb = _mm512_unpackhi_pd(ab, ab);
            let yx = _mm512_permute_pd::<0b01010101>(xy);
            _mm512_storeu_pd(
                out.add(i) as _,
                _mm512_fmaddsub_pd(aa, xy, _mm512_mul_pd(bb, yx)),
            );
        }
    } else {
        for i in 0..n / 4 {
            let i = 4 * i;
            let ab = _mm512_loadu_pd(lhs.add(i) as _);
            let xy = _mm512_loadu_pd(rhs.add(i) as _);
            let aa = _mm512_unpacklo_pd(ab, ab);
            let bb = _mm512_unpackhi_pd(ab, ab);
            let yx = _mm512_permute_pd::<0b01010101>(xy);
            _mm512_storeu_pd(
                out.add(i) as _,
                _mm512_fmaddsub_pd(
                    aa,
                    xy,
                    _mm512_fmaddsub_pd(bb, yx, _mm512_loadu_pd(out.add(i) as _)),
                ),
            );
        }
    }
}

/// # Note
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
///
/// # Safety
///
///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
///  - `is_x86_feature_detected!("fma")` must be true.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[target_feature(enable = "fma")]
unsafe fn update_with_fmadd_fma(
    output_fourier: &mut [MaybeUninit<c64>],
    ggsw_poly: &[c64],
    fourier: &[c64],
    is_output_uninit: bool,
) {
    let n = output_fourier.len();

    debug_assert_eq!(n, ggsw_poly.len());
    debug_assert_eq!(n, fourier.len());
    debug_assert_eq!(n % 4, 0);

    let out = output_fourier.as_mut_ptr();
    let lhs = ggsw_poly.as_ptr();
    let rhs = fourier.as_ptr();

    // 2×c64 per register

    if is_output_uninit {
        for i in 0..n / 2 {
            let i = 2 * i;
            let ab = _mm256_loadu_pd(lhs.add(i) as _);
            let xy = _mm256_loadu_pd(rhs.add(i) as _);
            let aa = _mm256_unpacklo_pd(ab, ab);
            let bb = _mm256_unpackhi_pd(ab, ab);
            let yx = _mm256_permute_pd::<0b0101>(xy);
            _mm256_storeu_pd(
                out.add(i) as _,
                _mm256_fmaddsub_pd(aa, xy, _mm256_mul_pd(bb, yx)),
            );
        }
    } else {
        for i in 0..n / 2 {
            let i = 2 * i;
            let ab = _mm256_loadu_pd(lhs.add(i) as _);
            let xy = _mm256_loadu_pd(rhs.add(i) as _);
            let aa = _mm256_unpacklo_pd(ab, ab);
            let bb = _mm256_unpackhi_pd(ab, ab);
            let yx = _mm256_permute_pd::<0b0101>(xy);
            _mm256_storeu_pd(
                out.add(i) as _,
                _mm256_fmaddsub_pd(
                    aa,
                    xy,
                    _mm256_fmaddsub_pd(bb, yx, _mm256_loadu_pd(out.add(i) as _)),
                ),
            );
        }
    }
}

/// # Note
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
///
/// # Safety
///
///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
unsafe fn update_with_fmadd_scalar(
    output_fourier: &mut [MaybeUninit<c64>],
    ggsw_poly: &[c64],
    fourier: &[c64],
    is_output_uninit: bool,
) {
    if is_output_uninit {
        // we're writing to output_fft_buffer for the first time
        // so its contents are uninitialized
        izip!(output_fourier, ggsw_poly, fourier).for_each(|(out_fourier, lhs, rhs)| {
            out_fourier.write(lhs * rhs);
        });
    } else {
        // we already wrote to output_fft_buffer, so we can assume its contents are
        // initialized.
        izip!(output_fourier, ggsw_poly, fourier).for_each(|(out_fourier, lhs, rhs)| {
            *{ out_fourier.assume_init_mut() } += lhs * rhs;
        });
    }
}

/// # Note
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
///
/// # Safety
///
///  - if `is_output_uninit` is false, `output_fourier` must not hold any uninitialized values.
#[cfg_attr(__profiling, inline(never))]
unsafe fn update_with_fmadd(
    output_fft_buffer: &mut [MaybeUninit<c64>],
    ggsw_row: FourierGgswLevelRowView,
    fourier: &[c64],
    is_output_uninit: bool,
    fourier_poly_size: usize,
) {
    #[allow(clippy::type_complexity)]
    let ptr_fn = || -> unsafe fn(&mut [MaybeUninit<c64>], &[c64], &[c64], bool) {
        #[cfg(all(
            feature = "nightly-avx512",
            any(target_arch = "x86_64", target_arch = "x86")
        ))]
        if is_x86_feature_detected!("avx512f") {
            return update_with_fmadd_avx512;
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        if is_x86_feature_detected!("fma") {
            return update_with_fmadd_fma;
        }

        update_with_fmadd_scalar
    };

    let ptr = ptr_fn();

    izip!(
        output_fft_buffer.into_chunks(fourier_poly_size),
        ggsw_row.data.into_chunks(fourier_poly_size)
    )
    .for_each(|(output_fourier, ggsw_poly)| {
        ptr(output_fourier, ggsw_poly, fourier, is_output_uninit);
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
    stack: DynStack<'_>,
) {
    izip!(ct1.as_mut(), ct0.as_ref(),).for_each(|(c1, c0)| {
        *c1 = c1.wrapping_sub(*c0);
    });
    add_external_product_assign(ct0, ggsw, ct1, fft, stack);
}
