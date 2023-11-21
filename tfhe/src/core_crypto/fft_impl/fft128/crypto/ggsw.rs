use super::super::math::fft::Fft128View;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, SignedDecomposer};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use crate::core_crypto::prelude::ContainerMut;
use aligned_vec::CACHELINE_ALIGN;
use concrete_fft::fft128::f128;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

/// A GGSW ciphertext in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Fourier128GgswCiphertext<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fourier128GgswLevelMatrix<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    row_count: usize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fourier128GgswLevelRow<C: Container<Element = f64>> {
    data_re0: C,
    data_re1: C,
    data_im0: C,
    data_im1: C,

    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_level: DecompositionLevel,
}

impl<C: Container<Element = f64>> Fourier128GgswCiphertext<C> {
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        let container_len = polynomial_size.to_fourier_polynomial_size().0
            * glwe_size.0
            * glwe_size.0
            * decomposition_level_count.0;
        assert_eq!(data_re0.container_len(), container_len);

        Self {
            data_re0,
            data_re1,
            data_im0,
            data_im1,
            polynomial_size,
            glwe_size,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
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

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }

    pub fn as_view(&self) -> Fourier128GgswCiphertext<&[C::Element]>
    where
        C: AsRef<[C::Element]>,
    {
        Fourier128GgswCiphertext {
            data_re0: self.data_re0.as_ref(),
            data_re1: self.data_re1.as_ref(),
            data_im0: self.data_im0.as_ref(),
            data_im1: self.data_im1.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> Fourier128GgswCiphertext<&mut [C::Element]>
    where
        C: AsMut<[C::Element]>,
    {
        Fourier128GgswCiphertext {
            data_re0: self.data_re0.as_mut(),
            data_re1: self.data_re1.as_mut(),
            data_im0: self.data_im0.as_mut(),
            data_im1: self.data_im1.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    /// Return an iterator over the level matrices.
    pub fn into_levels(self) -> impl DoubleEndedIterator<Item = Fourier128GgswLevelMatrix<C>>
    where
        C: Split,
    {
        izip!(
            self.data_re0.split_into(self.decomposition_level_count.0),
            self.data_re1.split_into(self.decomposition_level_count.0),
            self.data_im0.split_into(self.decomposition_level_count.0),
            self.data_im1.split_into(self.decomposition_level_count.0)
        )
        .enumerate()
        .map(move |(i, (data_re0, data_re1, data_im0, data_im1))| {
            Fourier128GgswLevelMatrix::from_container(
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                self.polynomial_size,
                self.glwe_size,
                self.glwe_size.0,
                DecompositionLevel(i + 1),
            )
        })
    }
}

impl<C: Container<Element = f64>> Fourier128GgswLevelMatrix<C> {
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        row_count: usize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        let container_len =
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size.0 * row_count;
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
            row_count,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = Fourier128GgswLevelRow<C>>
    where
        C: Split,
    {
        izip!(
            self.data_re0.split_into(self.row_count),
            self.data_re1.split_into(self.row_count),
            self.data_im0.split_into(self.row_count),
            self.data_im1.split_into(self.row_count)
        )
        .map(
            move |(data_re0, data_re1, data_im0, data_im1)| Fourier128GgswLevelRow {
                data_re0,
                data_re1,
                data_im0,
                data_im1,
                polynomial_size: self.polynomial_size,
                glwe_size: self.glwe_size,
                decomposition_level: self.decomposition_level,
            },
        )
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

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }
}

impl<C: Container<Element = f64>> Fourier128GgswLevelRow<C> {
    pub fn from_container(
        data_re0: C,
        data_re1: C,
        data_im0: C,
        data_im1: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(polynomial_size.0 % 2, 0);
        let container_len = polynomial_size.to_fourier_polynomial_size().0 * glwe_size.0;
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

    pub fn data(self) -> (C, C, C, C) {
        (self.data_re0, self.data_re1, self.data_im0, self.data_im1)
    }
}

impl<Cont> Fourier128GgswCiphertext<Cont>
where
    Cont: ContainerMut<Element = f64>,
{
    /// Fill a GGSW ciphertext with the Fourier transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_fourier<Scalar, ContGgsw>(
        &mut self,
        coef_ggsw: &GgswCiphertext<ContGgsw>,
        fft: Fft128View<'_>,
    ) where
        Scalar: UnsignedTorus,
        ContGgsw: Container<Element = Scalar>,
    {
        fn implementation<Scalar: UnsignedTorus>(
            this: Fourier128GgswCiphertext<&mut [f64]>,
            coef_ggsw: GgswCiphertext<&[Scalar]>,
            fft: Fft128View<'_>,
        ) {
            debug_assert_eq!(coef_ggsw.polynomial_size(), this.polynomial_size());
            let poly_size = coef_ggsw.polynomial_size().to_fourier_polynomial_size().0;

            let (data_re0, data_re1, data_im0, data_im1) = this.data();

            for (fourier_re0, fourier_re1, fourier_im0, fourier_im1, coef_poly) in izip!(
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

/// Return the required memory for [`add_external_product_assign`].
pub fn add_external_product_assign_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<Scalar>(glwe_size.0 * polynomial_size.0, align)?;
    let fourier_scratch = StackReq::try_new_aligned::<f64>(
        glwe_size.0 * polynomial_size.to_fourier_polynomial_size().0,
        align,
    )?;
    let fourier_scratch_single =
        StackReq::try_new_aligned::<f64>(polynomial_size.to_fourier_polynomial_size().0, align)?;

    let substack2 = StackReq::try_all_of([fourier_scratch_single; 4])?;
    let substack1 = substack2.try_and(standard_scratch)?;
    let substack0 = StackReq::try_any_of([
        substack1.try_and(standard_scratch)?,
        fft.backward_scratch()?,
    ])?;
    substack0.try_and(StackReq::try_all_of([fourier_scratch; 4])?)
}

#[cfg_attr(__profiling, inline(never))]
pub fn add_external_product_assign<Scalar, ContOut, ContGgsw, ContGlwe>(
    out: &mut GlweCiphertext<ContOut>,
    ggsw: &Fourier128GgswCiphertext<ContGgsw>,
    glwe: &GlweCiphertext<ContGlwe>,
    fft: Fft128View<'_>,
    stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus,
    ContOut: ContainerMut<Element = Scalar>,
    ContGgsw: Container<Element = f64>,
    ContGlwe: Container<Element = Scalar>,
{
    fn implementation<Scalar: UnsignedTorus>(
        mut out: GlweCiphertext<&mut [Scalar]>,
        ggsw: Fourier128GgswCiphertext<&[f64]>,
        glwe: GlweCiphertext<&[Scalar]>,
        fft: Fft128View<'_>,
        stack: PodStack<'_>,
    ) {
        // we check that the polynomial sizes match
        debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
        debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
        // we check that the glwe sizes match
        debug_assert_eq!(ggsw.glwe_size(), glwe.glwe_size());
        debug_assert_eq!(ggsw.glwe_size(), out.glwe_size());

        debug_assert_eq!(glwe.ciphertext_modulus(), out.ciphertext_modulus());

        let align = CACHELINE_ALIGN;
        let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;
        let ciphertext_modulus = glwe.ciphertext_modulus();

        // we round the input mask and body
        let decomposer = SignedDecomposer::<Scalar>::new(
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
        let mut is_output_uninit = true;

        {
            // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER
            // DOMAIN In this section, we perform the external product in the fourier
            // domain, and accumulate the result in the output_fft_buffer variable.
            let (mut decomposition, mut substack1) = TensorSignedDecompositionLendingIter::new(
                glwe.as_ref()
                    .iter()
                    .map(|s| decomposer.closest_representable(*s)),
                DecompositionBaseLog(decomposer.base_log),
                DecompositionLevelCount(decomposer.level_count),
                substack0.rb_mut(),
            );

            // We loop through the levels (we reverse to match the order of the decomposition
            // iterator.)
            for ggsw_decomp_matrix in ggsw.into_levels().rev() {
                // We retrieve the decomposition of this level.
                let (glwe_level, glwe_decomp_term, mut substack2) =
                    collect_next_term(&mut decomposition, &mut substack1, align);
                let glwe_decomp_term = GlweCiphertextView::from_container(
                    &*glwe_decomp_term,
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

                for (ggsw_row, glwe_poly) in izip!(
                    ggsw_decomp_matrix.into_rows(),
                    glwe_decomp_term.as_polynomial_list().iter()
                ) {
                    let len = fourier_poly_size;
                    let stack = substack2.rb_mut();
                    let (mut fourier_re0, stack) = stack.make_aligned_raw::<f64>(len, align);
                    let (mut fourier_re1, stack) = stack.make_aligned_raw::<f64>(len, align);
                    let (mut fourier_im0, stack) = stack.make_aligned_raw::<f64>(len, align);
                    let (mut fourier_im1, _) = stack.make_aligned_raw::<f64>(len, align);
                    // We perform the forward fft transform for the glwe polynomial
                    fft.forward_as_integer(
                        &mut fourier_re0,
                        &mut fourier_re1,
                        &mut fourier_im0,
                        &mut fourier_im1,
                        glwe_poly.as_ref(),
                    );
                    // Now we loop through the polynomials of the output, and add the
                    // corresponding product of polynomials.
                    update_with_fmadd(
                        &mut output_fft_buffer_re0,
                        &mut output_fft_buffer_re1,
                        &mut output_fft_buffer_im0,
                        &mut output_fft_buffer_im1,
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
            let output_fft_buffer_re0 = output_fft_buffer_re0;
            let output_fft_buffer_re1 = output_fft_buffer_re1;
            let output_fft_buffer_im0 = output_fft_buffer_im0;
            let output_fft_buffer_im1 = output_fft_buffer_im1;

            for (mut out, fourier_re0, fourier_re1, fourier_im0, fourier_im1) in izip!(
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
                    substack0.rb_mut(),
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

fn collect_next_term<'a, Scalar: UnsignedTorus>(
    decomposition: &mut TensorSignedDecompositionLendingIter<'_, Scalar>,
    substack1: &'a mut PodStack,
    align: usize,
) -> (
    DecompositionLevel,
    dyn_stack::DynArray<'a, Scalar>,
    PodStack<'a>,
) {
    let (glwe_level, _, glwe_decomp_term) = decomposition.next_term().unwrap();
    let (glwe_decomp_term, substack2) = substack1.rb_mut().collect_aligned(align, glwe_decomp_term);
    (glwe_level, glwe_decomp_term, substack2)
}

/// # Note
///
/// this function leaves all the elements of `output_fourier` in an initialized state.
#[inline(always)]
fn update_with_fmadd_scalar(
    output_fourier_re0: &mut [f64],
    output_fourier_re1: &mut [f64],
    output_fourier_im0: &mut [f64],
    output_fourier_im1: &mut [f64],
    ggsw_poly_re0: &[f64],
    ggsw_poly_re1: &[f64],
    ggsw_poly_im0: &[f64],
    ggsw_poly_im1: &[f64],
    fourier_re0: &[f64],
    fourier_re1: &[f64],
    fourier_im0: &[f64],
    fourier_im1: &[f64],
    is_output_uninit: bool,
) {
    if is_output_uninit {
        // we're writing to output_fft_buffer for the first time
        // so its contents are uninitialized
        for (
            out_fourier_re0,
            out_fourier_re1,
            out_fourier_im0,
            out_fourier_im1,
            lhs_re0,
            lhs_re1,
            lhs_im0,
            lhs_im1,
            rhs_re0,
            rhs_re1,
            rhs_im0,
            rhs_im1,
        ) in izip!(
            output_fourier_re0,
            output_fourier_re1,
            output_fourier_im0,
            output_fourier_im1,
            ggsw_poly_re0,
            ggsw_poly_re1,
            ggsw_poly_im0,
            ggsw_poly_im1,
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
        ) {
            let lhs_re = f128(*lhs_re0, *lhs_re1);
            let lhs_im = f128(*lhs_im0, *lhs_im1);
            let rhs_re = f128(*rhs_re0, *rhs_re1);
            let rhs_im = f128(*rhs_im0, *rhs_im1);

            let out_re = lhs_re * rhs_re - lhs_im * rhs_im;
            let out_im = lhs_im * rhs_re + lhs_re * rhs_im;

            *out_fourier_re0 = out_re.0;
            *out_fourier_re1 = out_re.1;
            *out_fourier_im0 = out_im.0;
            *out_fourier_im1 = out_im.1;
        }
    } else {
        // we already wrote to output_fft_buffer, so we can assume its contents are
        // initialized.
        for (
            out_fourier_re0,
            out_fourier_re1,
            out_fourier_im0,
            out_fourier_im1,
            lhs_re0,
            lhs_re1,
            lhs_im0,
            lhs_im1,
            rhs_re0,
            rhs_re1,
            rhs_im0,
            rhs_im1,
        ) in izip!(
            output_fourier_re0,
            output_fourier_re1,
            output_fourier_im0,
            output_fourier_im1,
            ggsw_poly_re0,
            ggsw_poly_re1,
            ggsw_poly_im0,
            ggsw_poly_im1,
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
        ) {
            let lhs_re = f128(*lhs_re0, *lhs_re1);
            let lhs_im = f128(*lhs_im0, *lhs_im1);
            let rhs_re = f128(*rhs_re0, *rhs_re1);
            let rhs_im = f128(*rhs_im0, *rhs_im1);

            let mut out_re = f128(*out_fourier_re0, *out_fourier_re1);
            let mut out_im = f128(*out_fourier_im0, *out_fourier_im1);

            out_re += lhs_re * rhs_re - lhs_im * rhs_im;
            out_im += lhs_im * rhs_re + lhs_re * rhs_im;

            *out_fourier_re0 = out_re.0;
            *out_fourier_re1 = out_re.1;
            *out_fourier_im0 = out_im.0;
            *out_fourier_im1 = out_im.1;
        }
    }
}

pub fn update_with_fmadd(
    output_fft_buffer_re0: &mut [f64],
    output_fft_buffer_re1: &mut [f64],
    output_fft_buffer_im0: &mut [f64],
    output_fft_buffer_im1: &mut [f64],
    ggsw_row: Fourier128GgswLevelRow<&[f64]>,
    fourier_re0: &[f64],
    fourier_re1: &[f64],
    fourier_im0: &[f64],
    fourier_im1: &[f64],
    is_output_uninit: bool,
    fourier_poly_size: usize,
) {
    let arch = pulp::Arch::new();
    for (
        output_fourier_re0,
        output_fourier_re1,
        output_fourier_im0,
        output_fourier_im1,
        ggsw_poly_re0,
        ggsw_poly_re1,
        ggsw_poly_im0,
        ggsw_poly_im1,
    ) in izip!(
        output_fft_buffer_re0.into_chunks(fourier_poly_size),
        output_fft_buffer_re1.into_chunks(fourier_poly_size),
        output_fft_buffer_im0.into_chunks(fourier_poly_size),
        output_fft_buffer_im1.into_chunks(fourier_poly_size),
        ggsw_row.data_re0.into_chunks(fourier_poly_size),
        ggsw_row.data_re1.into_chunks(fourier_poly_size),
        ggsw_row.data_im0.into_chunks(fourier_poly_size),
        ggsw_row.data_im1.into_chunks(fourier_poly_size),
    ) {
        struct Impl<'a> {
            output_fourier_re0: &'a mut [f64],
            output_fourier_re1: &'a mut [f64],
            output_fourier_im0: &'a mut [f64],
            output_fourier_im1: &'a mut [f64],
            ggsw_poly_re0: &'a [f64],
            ggsw_poly_re1: &'a [f64],
            ggsw_poly_im0: &'a [f64],
            ggsw_poly_im1: &'a [f64],
            fourier_re0: &'a [f64],
            fourier_re1: &'a [f64],
            fourier_im0: &'a [f64],
            fourier_im1: &'a [f64],
            is_output_uninit: bool,
        }
        impl pulp::WithSimd for Impl<'_> {
            type Output = ();

            #[inline(always)]
            fn with_simd<S: pulp::Simd>(self, simd: S) -> Self::Output {
                let Self {
                    output_fourier_re0,
                    output_fourier_re1,
                    output_fourier_im0,
                    output_fourier_im1,
                    ggsw_poly_re0,
                    ggsw_poly_re1,
                    ggsw_poly_im0,
                    ggsw_poly_im1,
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    is_output_uninit,
                } = self;

                // let the autovectorizer handle this
                let _ = simd;
                update_with_fmadd_scalar(
                    output_fourier_re0,
                    output_fourier_re1,
                    output_fourier_im0,
                    output_fourier_im1,
                    ggsw_poly_re0,
                    ggsw_poly_re1,
                    ggsw_poly_im0,
                    ggsw_poly_im1,
                    fourier_re0,
                    fourier_re1,
                    fourier_im0,
                    fourier_im1,
                    is_output_uninit,
                );
            }
        }

        arch.dispatch(Impl {
            output_fourier_re0,
            output_fourier_re1,
            output_fourier_im0,
            output_fourier_im1,
            ggsw_poly_re0,
            ggsw_poly_re1,
            ggsw_poly_im0,
            ggsw_poly_im1,
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            is_output_uninit,
        });
    }
}

/// Return the required memory for [`cmux`].
pub fn cmux_scratch<Scalar>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    fft: Fft128View<'_>,
) -> Result<StackReq, SizeOverflow> {
    add_external_product_assign_scratch::<Scalar>(glwe_size, polynomial_size, fft)
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux<Scalar, ContCt0, ContCt1, ContGgsw>(
    ct0: &mut GlweCiphertext<ContCt0>,
    ct1: &mut GlweCiphertext<ContCt1>,
    ggsw: &Fourier128GgswCiphertext<ContGgsw>,
    fft: Fft128View<'_>,
    stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus,
    ContCt0: ContainerMut<Element = Scalar>,
    ContCt1: ContainerMut<Element = Scalar>,
    ContGgsw: Container<Element = f64>,
{
    fn implementation<Scalar: UnsignedTorus>(
        mut ct0: GlweCiphertext<&mut [Scalar]>,
        mut ct1: GlweCiphertext<&mut [Scalar]>,
        ggsw: Fourier128GgswCiphertext<&[f64]>,
        fft: Fft128View<'_>,
        stack: PodStack<'_>,
    ) {
        for (c1, c0) in izip!(ct1.as_mut(), ct0.as_ref(),) {
            *c1 = c1.wrapping_sub(*c0);
        }
        add_external_product_assign(&mut ct0, &ggsw, &ct1, fft, stack);
    }

    implementation(
        ct0.as_mut_view(),
        ct1.as_mut_view(),
        ggsw.as_view(),
        fft,
        stack,
    );
}
