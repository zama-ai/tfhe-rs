//! Module containing the definition of the SeededGgswCiphertext.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded GGSW Ciphertext`](`SeededGgswCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeededGgswCiphertext<C: Container> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    compression_seed: CompressionSeed,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for SeededGgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in a [`SeededGgswCiphertext`] given a [`GlweSize`],
/// [`PolynomialSize`] and [`DecompositionLevelCount`].
pub fn seeded_ggsw_ciphertext_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0 * seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)
}

/// Return the number of elements in a [`SeededGgswLevelMatrix`] given a [`GlweSize`] and
/// [`PolynomialSize`].
pub fn seeded_ggsw_level_matrix_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    glwe_size.0 * polynomial_size.0
}

impl<Scalar, C: Container<Element = Scalar>> SeededGgswCiphertext<C> {
    /// Create a [`SeededGgswCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its
    /// parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] using
    /// this ciphertext as output.
    ///
    /// This docstring exhibits [`SeededGgswCiphertext`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGgswCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededGgswCiphertext
    /// let ggsw = SeededGgswCiphertext::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     seeder.seed().into(),
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(
    ///     ggsw.seeded_ggsw_level_matrix_size(),
    ///     seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    ///
    /// let compression_seed = ggsw.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let ggsw = SeededGgswCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(
    ///     ggsw.seeded_ggsw_level_matrix_size(),
    ///     seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    ///
    /// let ggsw = ggsw.decompress_into_ggsw_ciphertext();
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(
    ///     ggsw.ggsw_level_matrix_size(),
    ///     ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        compression_seed: CompressionSeed,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a SeededGgswCiphertext"
        );
        assert!(
            container.container_len() % (glwe_size.0 * polynomial_size.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by glwe_size * polynomial_size: {}. \
        Got container length: {} and glwe_size: {glwe_size:?}, \
        polynomial_size: {polynomial_size:?}.",
            glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        SeededGgswCiphertext {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
        }
    }

    /// Return the [`PolynomialSize`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweSize`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`DecompositionBaseLog`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.container_len() / self.seeded_ggsw_level_matrix_size())
    }

    /// Return the [`CompressionSeed`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Return the size in number of elements of a single [`SeededGgswLevelMatrix`] of the current
    /// [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn seeded_ggsw_level_matrix_size(&self) -> usize {
        // GlweSize SeededGlweCiphertext(glwe_size, polynomial_size) per level
        seeded_ggsw_level_matrix_size(self.glwe_size, self.polynomial_size)
    }

    /// Interpret the [`SeededGgswCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Interpret the [`SeededGgswCiphertext`] as a [`SeededGlweCiphertextList`].
    pub fn as_seeded_glwe_list(&self) -> SeededGlweCiphertextListView<'_, Scalar> {
        SeededGlweCiphertextListView::from_container(
            self.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.compression_seed,
        )
    }

    /// Return a view of the [`SeededGgswCiphertext`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> SeededGgswCiphertextView<'_, Scalar> {
        SeededGgswCiphertextView::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.compression_seed(),
        )
    }

    /// Consume the [`SeededGgswCiphertext`] and decompress it into a standard
    /// [`GgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn decompress_into_ggsw_ciphertext(self) -> GgswCiphertextOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_ct = GgswCiphertextOwned::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
        );
        decompress_seeded_ggsw_ciphertext::<_, _, _, ActivatedRandomGenerator>(
            &mut decompressed_ct,
            &self,
        );
        decompressed_ct
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> SeededGgswCiphertext<C> {
    /// Mutable variant of [`SeededGgswCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`SeededGgswCiphertext::as_seeded_glwe_list`].
    pub fn as_mut_seeded_glwe_list(&mut self) -> SeededGlweCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;
        let compression_seed = self.compression_seed;
        SeededGlweCiphertextListMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            compression_seed,
        )
    }

    /// Mutable variant of [`SeededGgswCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> SeededGgswCiphertextMutView<'_, Scalar> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let compression_seed = self.compression_seed();
        SeededGgswCiphertextMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
        )
    }
}

/// A [`SeededGgswCiphertext`] owning the memory for its own storage.
pub type SeededGgswCiphertextOwned<Scalar> = SeededGgswCiphertext<Vec<Scalar>>;
/// A [`SeededGgswCiphertext`] immutably borrowing memory for its own storage.
pub type SeededGgswCiphertextView<'data, Scalar> = SeededGgswCiphertext<&'data [Scalar]>;
/// A [`SeededGgswCiphertext`] immutably borrowing memory for its own storage.
pub type SeededGgswCiphertextMutView<'data, Scalar> = SeededGgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: Copy> SeededGgswCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededGgswCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`]
    /// using this ciphertext as output.
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        compression_seed: CompressionSeed,
    ) -> SeededGgswCiphertextOwned<Scalar> {
        SeededGgswCiphertextOwned::from_container(
            vec![
                fill_with;
                seeded_ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGgswCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct SeededGgswCiphertextCreationMetadata(
    pub GlweSize,
    pub PolynomialSize,
    pub DecompositionBaseLog,
    pub CompressionSeed,
);

impl<C: Container> CreateFrom<C> for SeededGgswCiphertext<C> {
    type Metadata = SeededGgswCiphertextCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> SeededGgswCiphertext<C> {
        let SeededGgswCiphertextCreationMetadata(
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
        ) = meta;
        SeededGgswCiphertext::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
        )
    }
}

/// A convenience structure to more easily write iterators on a [`SeededGgswCiphertext`] levels.
pub struct SeededGgswLevelMatrix<C: Container> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    compression_seed: CompressionSeed,
}

impl<Scalar, C: Container<Element = Scalar>> SeededGgswLevelMatrix<C> {
    /// Create a [`SeededGgswLevelMatrix`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`SeededGgswLevelMatrix`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGgswLevelMatrix creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// let container = vec![0u64; seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)];
    ///
    /// // Create a new SeededGgswLevelMatrix
    /// let ggsw_level_matrix = SeededGgswLevelMatrix::from_container(
    ///     container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     seeder.seed().into(),
    /// );
    ///
    /// assert_eq!(ggsw_level_matrix.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_level_matrix.polynomial_size(), polynomial_size);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
    ) -> SeededGgswLevelMatrix<C> {
        assert!(
            container.container_len() == seeded_ggsw_level_matrix_size(glwe_size, polynomial_size),
            "The provided container length is not valid. \
            Expected length of {} (glwe_size * polynomial_size), got {}",
            seeded_ggsw_level_matrix_size(glwe_size, polynomial_size),
            container.container_len(),
        );

        SeededGgswLevelMatrix {
            data: container,
            glwe_size,
            polynomial_size,
            compression_seed,
        }
    }

    /// Return the [`GlweSize`] of the [`SeededGgswLevelMatrix`].
    ///
    /// See [`SeededGgswLevelMatrix::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`SeededGgswLevelMatrix`].
    ///
    /// See [`SeededGgswLevelMatrix::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Interpret the [`SeededGgswLevelMatrix`] as a [`SeededGlweCiphertextList`].
    pub fn as_seeded_glwe_list(&self) -> SeededGlweCiphertextListView<'_, Scalar> {
        SeededGlweCiphertextListView::from_container(
            self.data.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.compression_seed,
        )
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> SeededGgswLevelMatrix<C> {
    /// Mutable variant of [`SeededGgswLevelMatrix::as_seeded_glwe_list`]
    pub fn as_mut_seeded_glwe_list(&mut self) -> SeededGlweCiphertextListMutView<'_, Scalar> {
        SeededGlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            self.glwe_size,
            self.polynomial_size,
            self.compression_seed,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGgswLevelMatrix`] entities.
#[derive(Clone, Copy)]
pub struct SeededGgswLevelMatrixCreationMetadata(
    pub GlweSize,
    pub PolynomialSize,
    pub CompressionSeed,
);

impl<C: Container> CreateFrom<C> for SeededGgswLevelMatrix<C> {
    type Metadata = SeededGgswLevelMatrixCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> SeededGgswLevelMatrix<C> {
        let SeededGgswLevelMatrixCreationMetadata(glwe_size, polynomial_size, compression_seed) =
            meta;
        SeededGgswLevelMatrix::from_container(from, glwe_size, polynomial_size, compression_seed)
    }
}

impl<C: Container> ContiguousEntityContainer for SeededGgswCiphertext<C> {
    type Element = C::Element;

    type EntityViewMetadata = SeededGgswLevelMatrixCreationMetadata;

    type EntityView<'this> = SeededGgswLevelMatrix<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        SeededGgswLevelMatrixCreationMetadata(
            self.glwe_size,
            self.polynomial_size,
            self.compression_seed,
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.seeded_ggsw_level_matrix_size()
    }

    /// Unimplemented for [`SeededGgswCiphertext`]. At the moment it does not make sense to
    /// return "sub" SeededGgswCiphertext.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededGgswCiphertext. \
        At the moment it does not make sense to return 'sub' SeededGgswCiphertext."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for SeededGgswCiphertext<C> {
    type EntityMutView<'this> = SeededGgswLevelMatrix<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
