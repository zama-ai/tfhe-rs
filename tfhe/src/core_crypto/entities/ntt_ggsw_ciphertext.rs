use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};
use crate::core_crypto::commons::traits::{Container, ContainerMut, Split};
pub use crate::core_crypto::entities::ggsw_ciphertext::{
    ggsw_ciphertext_size, ggsw_level_matrix_size,
};
pub use crate::core_crypto::entities::glwe_ciphertext::glwe_ciphertext_size;
use aligned_vec::{avec, ABox};

/// A GGSW ciphertext in the Ntt domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NttGgswCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    decomposition_base_log: DecompositionBaseLog,
    decomposition_level_count: DecompositionLevelCount,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttGgswCiphertext<C> {
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            ggsw_ciphertext_size(glwe_size, polynomial_size, decomposition_level_count)
        );

        Self {
            data,
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

    pub fn data(self) -> C {
        self.data
    }

    pub fn as_view(&self) -> NttGgswCiphertextView<'_, Scalar> {
        NttGgswCiphertextView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    /// Return an iterator over the level matrices.
    pub fn into_levels(
        &self,
    ) -> impl DoubleEndedIterator<Item = NttGgswLevelMatrixView<'_, Scalar>> {
        self.data
            .as_ref()
            .split_into(self.decomposition_level_count.0)
            .enumerate()
            .map(move |(i, slice)| {
                NttGgswLevelMatrixView::from_container(
                    slice,
                    self.glwe_size,
                    self.polynomial_size,
                    DecompositionLevel(i + 1),
                )
            })
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NttGgswCiphertext<C> {
    pub fn as_mut_view(&mut self) -> NttGgswCiphertextMutView<'_, Scalar> {
        NttGgswCiphertextMutView {
            data: self.data.as_mut(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }
}

impl<Scalar: UnsignedInteger> NttGgswCiphertext<ABox<[Scalar]>> {
    pub fn new(
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
    ) -> Self {
        let boxed = avec![
            Scalar::ZERO;
            ggsw_ciphertext_size(glwe_size, polynomial_size, decomposition_level_count)
        ]
        .into_boxed_slice();

        NttGgswCiphertext::from_container(
            boxed,
            glwe_size,
            polynomial_size,
            decomposition_base_log,
            decomposition_level_count,
        )
    }
}

pub type NttGgswCiphertextOwned<Scalar> = NttGgswCiphertext<ABox<[Scalar]>>;
pub type NttGgswCiphertextView<'data, Scalar> = NttGgswCiphertext<&'data [Scalar]>;
pub type NttGgswCiphertextMutView<'data, Scalar> = NttGgswCiphertext<&'data mut [Scalar]>;

/// A matrix containing a single level of gadget decomposition, in the Ntt domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NttGgswLevelMatrix<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttGgswLevelMatrix<C> {
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            container.container_len(),
            ggsw_level_matrix_size(glwe_size, polynomial_size)
        );
        Self {
            data: container,
            glwe_size,
            polynomial_size,
            decomposition_level,
        }
    }

    /// Return an iterator over the rows of the level matrices.
    pub fn into_rows(self) -> impl DoubleEndedIterator<Item = NttGgswLevelRow<C>>
    where
        C: Split,
    {
        let row_count = self.row_count();
        self.data
            .split_into(row_count)
            .map(move |slice| NttGgswLevelRow {
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

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type NttGgswLevelMatrixView<'data, Scalar> = NttGgswLevelMatrix<&'data [Scalar]>;
pub type NttGgswLevelMatrixMutView<'data, Scalar> = NttGgswLevelMatrix<&'data mut [Scalar]>;

/// A row of a GGSW level matrix, in the Ntt domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NttGgswLevelRow<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level: DecompositionLevel,
}

impl<C: Container<Element = u64>> NttGgswLevelRow<C> {
    pub fn from_container(
        data: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomposition_level: DecompositionLevel,
    ) -> Self {
        assert_eq!(
            data.container_len(),
            glwe_ciphertext_size(glwe_size, polynomial_size)
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

pub type NttGgswLevelRowView<'data, Scalar> = NttGgswLevelRow<&'data [Scalar]>;
pub type NttGgswLevelRowMutView<'data, Scalar> = NttGgswLevelRow<&'data mut [Scalar]>;
