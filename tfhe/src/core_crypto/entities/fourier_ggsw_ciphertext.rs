use super::fourier_polynomial_list::FourierPolynomialList;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, Split};
use crate::core_crypto::prelude::IntoContainerOwned;
use aligned_vec::{avec, ABox};
use concrete_fft::c64;

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
pub type FourierGgswCiphertextOwned = FourierGgswCiphertext<ABox<[c64]>>;

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
            polynomial_size.to_fourier_polynomial_size().0 * glwe_size.0 * glwe_size.0
        );
        Self {
            data,
            polynomial_size,
            glwe_size,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = FourierGgswLevelRow<C>>
    where
        C: Split,
    {
        self.data
            .split_into(self.glwe_size.0)
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
                    DecompositionLevel(i + 1),
                )
            })
    }
}

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
