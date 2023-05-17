use super::super::math::decomposition::TensorSignedDecompositionLendingIter;
use super::super::math::fft::{FftView, FourierPolynomialList};
use super::super::math::polynomial::{FourierPolynomialMutView, FourierPolynomialView};
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
use crate::core_crypto::fft_impl::fft64::crypto::ggsw::{collect_next_term, update_with_fmadd};
use aligned_vec::{avec, ABox, CACHELINE_ALIGN};
use concrete_fft::c64;
use dyn_stack::{PodStack, ReborrowMut, SizeOverflow, StackReq};

/// A GGSW ciphertext in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct PseudoFourierGgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PseudoFourierGgswLevelMatrix<C: Container<Element = c64>> {
    data: C,
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    row_count: usize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PseudoFourierGgswLevelRow<C: Container<Element = c64>> {
    data: C,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

pub type PseudoFourierGgswCiphertextView<'a> = PseudoFourierGgswCiphertext<&'a [c64]>;
pub type PseudoFourierGgswCiphertextMutView<'a> = PseudoFourierGgswCiphertext<&'a mut [c64]>;
pub type PseudoFourierGgswLevelMatrixView<'a> = PseudoFourierGgswLevelMatrix<&'a [c64]>;
pub type PseudoFourierGgswLevelMatrixMutView<'a> = PseudoFourierGgswLevelMatrix<&'a mut [c64]>;
pub type PseudoFourierGgswLevelRowView<'a> = PseudoFourierGgswLevelRow<&'a [c64]>;
pub type PseudoFourierGgswLevelRowMutView<'a> = PseudoFourierGgswLevelRow<&'a mut [c64]>;

impl<C: Container<Element = c64>> PseudoFourierGgswCiphertext<C> {
    pub fn from_container(
        data: C,
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0
                * glwe_size_in.to_glwe_dimension().0
                * glwe_size_out.0
                * decomposition_level_count.0
        );

        Self {
            fourier: FourierPolynomialList {
                data,
                polynomial_size,
            },
            glwe_size_in,
            glwe_size_out,
            decomposition_base_log,
            decomposition_level_count,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.fourier.polynomial_size
    }

    pub fn glwe_size_in(&self) -> GlweSize {
        self.glwe_size_in
    }

    pub fn glwe_size_out(&self) -> GlweSize {
        // Le truc qui foire en k = 1 ? TODO
        self.glwe_size_out
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

    pub fn as_view(&self) -> PseudoFourierGgswCiphertextView<'_>
    where
        C: AsRef<[c64]>,
    {
        PseudoFourierGgswCiphertextView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_ref(),
                polynomial_size: self.fourier.polynomial_size,
            },
            glwe_size_in: self.glwe_size_in,
            glwe_size_out: self.glwe_size_out,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    pub fn as_mut_view(&mut self) -> PseudoFourierGgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        PseudoFourierGgswCiphertextMutView {
            fourier: FourierPolynomialList {
                data: self.fourier.data.as_mut(),
                polynomial_size: self.fourier.polynomial_size,
            },
            glwe_size_in: self.glwe_size_in,
            glwe_size_out: self.glwe_size_out,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<C: Container<Element = c64>> PseudoFourierGgswLevelMatrix<C> {
    pub fn new(
        data: C,
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        row_count: usize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size_out.0 * row_count
        );
        Self {
            data,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            row_count,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = PseudoFourierGgswLevelRow<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.row_count)
            .map(move |slice| PseudoFourierGgswLevelRow {
                data: slice,
                polynomial_size: self.polynomial_size,
                glwe_size_out: self.glwe_size_out,
                decomposition_level: self.decomposition_level,
            })
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size_in(&self) -> GlweSize {
        self.glwe_size_in
    }

    pub fn glwe_size_out(&self) -> GlweSize {
        self.glwe_size_out
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

impl<C: Container<Element = c64>> PseudoFourierGgswLevelRow<C> {
    pub fn new(
        data: C,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size_out.0
        );
        Self {
            data,
            glwe_size_out,
            polynomial_size,
            decomposition_level,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size_out(&self) -> GlweSize {
        self.glwe_size_out
    }

    pub fn decomposition_level(&self) -> DecompositionLevel {
        self.decomposition_level
    }

    pub fn data(self) -> C {
        self.data
    }
}

impl<'a> PseudoFourierGgswCiphertextView<'a> {
    /// Return an iterator over the level matrices.
    pub fn into_levels(
        self,
    ) -> impl DoubleEndedIterator<Item = PseudoFourierGgswLevelMatrixView<'a>> {
        self.fourier
            .data
            .split_into(self.decomposition_level_count.0)
            .enumerate()
            .map(move |(i, slice)| {
                PseudoFourierGgswLevelMatrixView::new(
                    slice,
                    self.glwe_size_in,
                    self.glwe_size_out,
                    self.fourier.polynomial_size,
                    self.glwe_size_in.to_glwe_dimension().0,
                    DecompositionLevel(i + 1),
                )
            })
    }
}

/// Return the required memory for
/// [`PseudoFourierGgswCiphertextMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl<'a> PseudoFourierGgswCiphertextMutView<'a> {
    /// Fill a GGSW ciphertext with the Fourier transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_fourier<
        Scalar: UnsignedTorus,
        InputCont: Container<Element = Scalar>,
    >(
        self,
        coef_ggsw: &PseudoGgswCiphertext<InputCont>,
        fft: FftView<'_>,
        mut stack: PodStack<'_>,
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
                stack.rb_mut(),
            );
        }
    }
}

#[allow(unused)]
type PseudoFourierGgswCiphertextOwned = PseudoFourierGgswCiphertext<ABox<[c64]>>;

impl PseudoFourierGgswCiphertext<ABox<[c64]>> {
    pub fn new(
        glwe_size_in: GlweSize,
        glwe_size_out: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            c64::default();
            polynomial_size.to_fourier_polynomial_size().0
                * glwe_size_in.to_glwe_dimension().0
                * glwe_size_out.0
                * decomposition_level_count.0
        ]
        .into_boxed_slice();

        Self::from_container(
            boxed,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

/// Return the required memory for [`add_external_product_pseudo_ggsw_assign`].
pub fn add_external_product_pseudo_ggsw_assign_scratch<Scalar>(
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) -> Result<StackReq, SizeOverflow> {
    let align = CACHELINE_ALIGN;
    let standard_scratch =
        StackReq::try_new_aligned::<Scalar>(glwe_size_out.0 * polynomial_size.0, align)?;
    let fourier_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;
    let fourier_scratch =
        StackReq::try_new_aligned::<c64>(glwe_size_out.0 * fourier_polynomial_size, align)?;
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
pub fn add_external_product_pseudo_ggsw_assign<Scalar, InputGlweCont>(
    mut out: GlweCiphertextMutView<'_, Scalar>,
    ggsw: PseudoFourierGgswCiphertextView<'_>,
    glwe: &GlweCiphertext<InputGlweCont>,
    fft: FftView<'_>,
    stack: PodStack<'_>,
) where
    Scalar: UnsignedTorus,
    InputGlweCont: Container<Element = Scalar>,
{
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_size_out(), out.glwe_size());

    //println!("%%%%%% INSIDE EXTERNAL PRODUCT %%%%%%%%%%");

    let align = CACHELINE_ALIGN;
    let fourier_poly_size = ggsw.polynomial_size().to_fourier_polynomial_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposer::<Scalar>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );
    // println!("going in first substack");

    let (mut output_fft_buffer, mut substack0) =
        stack.make_aligned_raw::<c64>(fourier_poly_size * ggsw.glwe_size_out().0, align);
    // println!("First substack done");
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

            // println!("ggsw_decomp_matrix.into_rows() = {:?}\n ",ggsw_decomp_matrix);
            // println!("glwe_decomp_term.as_poly = {:?}\n",glwe_decomp_term.as_polynomial_list());

            izip!(
                ggsw_decomp_matrix.into_rows(),
                glwe_decomp_term.get_mask().as_polynomial_list().iter()
            )
            .for_each(|(ggsw_row, glwe_poly)| {
                // println!("GGSW_ROW = {:?}\n", ggsw_row);
                // println!("GLWE_POLY = {:?}\n", glwe_poly);

                let (mut fourier, substack3) = substack2
                    .rb_mut()
                    .make_aligned_raw::<c64>(fourier_poly_size, align);
                //println!("Second substack done");

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

                //println!("GLWE_POLY FOURIER = {:?}\n", fourier);

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

    //println!("Ouput FFT Buffer = {:?}\n", output_fft_buffer);

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
                .map(|slice| FourierPolynomialView { data: slice }),
        )
        .for_each(|(out, fourier)| {
            fft.add_backward_as_torus(out, fourier, substack0.rb_mut());
        });
    }
    //We copy the body
    //as_mut().copy_from_slice(glwe.get_body().as_ref());

    for (dst, src) in out
        .get_mut_body()
        .as_mut_polynomial()
        .iter_mut()
        .zip(glwe.get_body().as_polynomial().iter())
    {
        *dst = dst.wrapping_add(*src);
    }
}
