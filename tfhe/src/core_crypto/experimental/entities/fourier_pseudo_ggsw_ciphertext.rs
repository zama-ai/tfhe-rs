use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::experimental::entities::PseudoGgswCiphertext;
use crate::core_crypto::fft_impl::fft64::math::decomposition::DecompositionLevel;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView, FourierPolynomialList};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use aligned_vec::{avec, ABox};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use tfhe_fft::c64;

/// A pseudo GGSW ciphertext in the Fourier domain.
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
        decomposition_level: DecompositionLevel,
    ) -> Self {
        let row_count = glwe_size_in.to_glwe_dimension().0;
        assert_eq!(
            data.container_len(),
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size_out.0 * row_count
        );
        Self {
            data,
            glwe_size_in,
            glwe_size_out,
            polynomial_size,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = PseudoFourierGgswLevelRow<C>>
    where
        C: Split,
    {
        let row_count = self.row_count();
        self.data
            .split_into(row_count)
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
        self.glwe_size_in.to_glwe_dimension().0
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
        let decomposition_level_count = self.decomposition_level_count.0;
        self.fourier
            .data
            .split_into(decomposition_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                PseudoFourierGgswLevelMatrixView::new(
                    slice,
                    self.glwe_size_in,
                    self.glwe_size_out,
                    self.fourier.polynomial_size,
                    DecompositionLevel(decomposition_level_count - i),
                )
            })
    }
}

/// Return the required memory for
/// [`PseudoFourierGgswCiphertextMutView::fill_with_forward_fourier`].
pub fn fill_with_forward_fourier_scratch(fft: FftView<'_>) -> Result<StackReq, SizeOverflow> {
    fft.forward_scratch()
}

impl PseudoFourierGgswCiphertextMutView<'_> {
    /// Fill a GGSW ciphertext with the Fourier transform of a GGSW ciphertext in the standard
    /// domain.
    pub fn fill_with_forward_fourier<
        Scalar: UnsignedTorus,
        InputCont: Container<Element = Scalar>,
    >(
        self,
        coef_ggsw: &PseudoGgswCiphertext<InputCont>,
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
pub type PseudoFourierGgswCiphertextOwned = PseudoFourierGgswCiphertext<ABox<[c64]>>;

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
