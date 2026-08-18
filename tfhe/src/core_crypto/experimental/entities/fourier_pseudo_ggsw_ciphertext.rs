use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{
    Container, ContiguousEntityContainer, IntoContainerOwned, Split,
};
use crate::core_crypto::commons::utils::izip_eq;
use crate::core_crypto::experimental::entities::PseudoGgswCiphertext;
use crate::core_crypto::fft_impl::fft64::math::decomposition::DecompositionLevel;
use crate::core_crypto::fft_impl::fft64::math::fft::{FftView, FourierPolynomialList};
use crate::core_crypto::fft_impl::fft64::math::polynomial::FourierPolynomialMutView;
use aligned_vec::{avec, ABox};
use dyn_stack::PodStack;
use tfhe_fft::c64;

/// A pseudo GGSW ciphertext in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierPseudoGgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

/// A matrix containing a single level of gadget decomposition, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierPseudoGgswLevelMatrix<C: Container<Element = c64>> {
    data: C,
    glwe_size_in: GlweSize,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

/// A row of a GGSW level matrix, in the Fourier domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierPseudoGgswLevelRow<C: Container<Element = c64>> {
    data: C,
    glwe_size_out: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

pub type FourierPseudoGgswCiphertextView<'a> = FourierPseudoGgswCiphertext<&'a [c64]>;
pub type FourierPseudoGgswCiphertextMutView<'a> = FourierPseudoGgswCiphertext<&'a mut [c64]>;
pub type FourierPseudoGgswLevelMatrixView<'a> = FourierPseudoGgswLevelMatrix<&'a [c64]>;
pub type FourierPseudoGgswLevelMatrixMutView<'a> = FourierPseudoGgswLevelMatrix<&'a mut [c64]>;
pub type FourierPseudoGgswLevelRowView<'a> = FourierPseudoGgswLevelRow<&'a [c64]>;
pub type FourierPseudoGgswLevelRowMutView<'a> = FourierPseudoGgswLevelRow<&'a mut [c64]>;

impl<C: Container<Element = c64>> FourierPseudoGgswCiphertext<C> {
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

    pub fn as_view(&self) -> FourierPseudoGgswCiphertextView<'_>
    where
        C: AsRef<[c64]>,
    {
        FourierPseudoGgswCiphertextView {
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

    pub fn as_mut_view(&mut self) -> FourierPseudoGgswCiphertextMutView<'_>
    where
        C: AsMut<[c64]>,
    {
        FourierPseudoGgswCiphertextMutView {
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

impl<C: Container<Element = c64>> FourierPseudoGgswLevelMatrix<C> {
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
    pub fn into_rows(
        self,
    ) -> impl DoubleEndedIterator<Item = FourierPseudoGgswLevelRow<C>>
           + ExactSizeIterator<Item = FourierPseudoGgswLevelRow<C>>
    where
        C: Split,
    {
        let row_count = self.row_count();
        self.data
            .split_into(row_count)
            .map(move |slice| FourierPseudoGgswLevelRow {
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

impl<C: Container<Element = c64>> FourierPseudoGgswLevelRow<C> {
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

impl<'a> FourierPseudoGgswCiphertextView<'a> {
    /// Return an iterator over the level matrices.
    pub fn into_levels(
        self,
    ) -> impl DoubleEndedIterator<Item = FourierPseudoGgswLevelMatrixView<'a>> {
        let decomposition_level_count = self.decomposition_level_count.0;
        self.fourier
            .data
            .split_into(decomposition_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                FourierPseudoGgswLevelMatrixView::new(
                    slice,
                    self.glwe_size_in,
                    self.glwe_size_out,
                    self.fourier.polynomial_size,
                    DecompositionLevel(decomposition_level_count - i),
                )
            })
    }
}

impl FourierPseudoGgswCiphertextMutView<'_> {
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

        for (fourier_poly, coef_poly) in izip_eq!(
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
pub type FourierPseudoGgswCiphertextOwned = FourierPseudoGgswCiphertext<ABox<[c64]>>;

impl FourierPseudoGgswCiphertext<ABox<[c64]>> {
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
