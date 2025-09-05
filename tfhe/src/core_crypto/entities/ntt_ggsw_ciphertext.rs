use crate::core_crypto::backward_compatibility::entities::ntt_ggsw_ciphertext::NttGgswCiphertextVersions;
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
use tfhe_versionable::Versionize;

/// A [`GGSW ciphertext in the Ntt domain`](`crate::core_crypto::entities::GgswCiphertext`).
///
/// See [`the formal definition of a GGSW
/// ciphertext`](`crate::core_crypto::entities::GgswCiphertext#formal-definition`)
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(NttGgswCiphertextVersions)]
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NttGgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NttGgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> NttGgswCiphertext<C> {
    /// Create a [`NttGgswCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`NttGgswCiphertext`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for NttGgswCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::try_new((1 << 64) - (1 << 32) + 1).unwrap();
    ///
    /// // Create a new GgswCiphertext
    /// let ggsw = GgswCiphertext::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.ggsw_level_matrix_size(),
    ///     ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let ggsw = GgswCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.ggsw_level_matrix_size(),
    ///     ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    /// ```
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

    /// Return the [`PolynomialSize`] of the [`NttGgswCiphertext`].
    ///
    /// See [`NttGgswCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweSize`] of the [`NttGgswCiphertext`].
    ///
    /// See [`NttGgswCiphertext::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`DecompositionBaseLog`] of the [`NttGgswCiphertext`].
    ///
    /// See [`NttGgswCiphertext::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomposition_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`NttGgswCiphertext`].
    ///
    /// See [`NttGgswCiphertext::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomposition_level_count
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`NttGgswCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return a view of the [`NttGgswCiphertext`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> NttGgswCiphertextView<'_, Scalar> {
        NttGgswCiphertextView {
            data: self.data.as_ref(),
            polynomial_size: self.polynomial_size,
            glwe_size: self.glwe_size,
            decomposition_base_log: self.decomposition_base_log,
            decomposition_level_count: self.decomposition_level_count,
        }
    }

    /// Return an iterator over the contiguous [`NttGgswLevelMatrix`]. This consumes the entity,
    /// consider calling [`NttGgswCiphertext::as_view`] or [`NttGgswCiphertext::as_mut_view`] first
    /// to have an iterator over borrowed contents instead of consuming the original entity.
    pub fn into_levels(
        &self,
    ) -> impl DoubleEndedIterator<Item = NttGgswLevelMatrixView<'_, Scalar>> {
        let decomposition_level_count = self.decomposition_level_count.0;
        self.data
            .as_ref()
            .split_into(decomposition_level_count)
            .enumerate()
            .map(move |(i, slice)| {
                NttGgswLevelMatrixView::from_container(
                    slice,
                    self.glwe_size,
                    self.polynomial_size,
                    DecompositionLevel(decomposition_level_count - i),
                )
            })
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> NttGgswCiphertext<C> {
    /// Mutable variant of [`NttGgswCiphertext::as_view`].
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
    /// Allocate memory and create a new owned [`NttGgswCiphertext`].
    ///
    /// # Note
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to have useful data in the [`NttGgswCiphertext`] you will first need to
    /// convert it from a standard
    /// [`GgswCiphertext`](`crate::core_crypto::entities::GgswCiphertext`).
    ///
    /// See [`NttGgswCiphertext::from_container`] for usage.
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NttGgswLevelMatrix<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NttGgswLevelMatrix<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for NttGgswLevelRow<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for NttGgswLevelRow<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
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

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type NttGgswLevelRowView<'data, Scalar> = NttGgswLevelRow<&'data [Scalar]>;
pub type NttGgswLevelRowMutView<'data, Scalar> = NttGgswLevelRow<&'data mut [Scalar]>;
