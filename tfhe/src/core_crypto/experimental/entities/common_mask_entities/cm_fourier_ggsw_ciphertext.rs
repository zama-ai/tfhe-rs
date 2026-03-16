use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, IntoContainerOwned, Split};
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::fft_impl::fft64::math;
use crate::core_crypto::prelude::ContiguousEntityContainer;
use aligned_vec::{avec, ABox};
use dyn_stack::PodStack;
use itertools::izip;
use math::fft::{FftView, FourierPolynomialList};
use math::polynomial::FourierPolynomialMutView;
use tfhe_fft::c64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
pub struct FourierCmGgswCiphertext<C: Container<Element = c64>> {
    fourier: FourierPolynomialList<C>,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierCmGgswLevelMatrix<C: Container<Element = c64>> {
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

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

impl FourierCmGgswCiphertextMutView<'_> {
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
