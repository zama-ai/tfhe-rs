//! Module containing the definition of the GgswCiphertextList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`GGSW ciphertexts`](`crate::core_crypto::entities::GgswCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GgswCiphertextList<C: Container> {
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GgswCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GgswCiphertextList<C> {
    /// Create a [`GgswCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data in
    /// the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its
    /// parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] on the
    /// individual ciphertexts in the list.
    ///
    /// This docstring exhibits [`GgswCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GgswCiphertextList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_count = GgswCiphertextCount(2);
    ///
    /// // Create a new GgswCiphertextList
    /// let ggsw_list = GgswCiphertextList::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_count,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let ggsw_list = GgswCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> GgswCiphertextList<C> {
        assert!(
            container.container_len()
                % (decomp_level_count.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0)
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * glwe_size * glwe_size * polynomial_size: \
        {}.Got container length: {} and decomp_level_count: {decomp_level_count:?},  \
        glwe_size: {glwe_size:?}, polynomial_size: {polynomial_size:?}",
            decomp_level_count.0 * glwe_size.0 * glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        GgswCiphertextList {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        }
    }

    /// Return the [`GlweSize`] of the [`GgswCiphertext`] stored in the list.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`GgswCiphertext`] in the list.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`DecompositionBaseLog`] of the [`GgswCiphertext`] in the list.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`GgswCiphertext`] in the list.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`GgswCiphertextCount`] of the [`GgswCiphertextList`].
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount {
        GgswCiphertextCount(
            self.data.container_len()
                / ggsw_ciphertext_size(
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomp_level_count,
                ),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

/// A [`GgswCiphertextList`] owning the memory for its own storage.
pub type GgswCiphertextListOwned<Scalar> = GgswCiphertextList<Vec<Scalar>>;
/// A [`GgswCiphertextList`] immutably borrowing memory for its own storage.
pub type GgswCiphertextListView<'data, Scalar> = GgswCiphertextList<&'data [Scalar]>;
/// A [`GgswCiphertextList`] mutably borrowing memory for its own storage.
pub type GgswCiphertextListMutView<'data, Scalar> = GgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> GgswCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`GgswCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data in the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] on
    /// the individual ciphertexts in the list.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: GgswCiphertextCount,
    ) -> GgswCiphertextListOwned<Scalar> {
        GgswCiphertextList::from_container(
            vec![
                fill_with;
                ciphertext_count.0
                    * ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GgswCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct GgswCiphertextListCreationMetadata(
    pub GlweSize,
    pub PolynomialSize,
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
);

impl<C: Container> CreateFrom<C> for GgswCiphertextList<C> {
    type Metadata = GgswCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GgswCiphertextList<C> {
        let GgswCiphertextListCreationMetadata(
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        ) = meta;
        GgswCiphertextList::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        )
    }
}

impl<C: Container> ContiguousEntityContainer for GgswCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = GgswCiphertextCreationMetadata;

    type EntityView<'this> = GgswCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = GgswCiphertextListCreationMetadata;

    type SelfView<'this> = GgswCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> GgswCiphertextCreationMetadata {
        GgswCiphertextCreationMetadata(self.glwe_size, self.polynomial_size, self.decomp_base_log)
    }

    fn get_entity_view_pod_size(&self) -> usize {
        ggsw_ciphertext_size(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_level_count,
        )
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        GgswCiphertextListCreationMetadata(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_base_log,
            self.decomp_level_count,
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for GgswCiphertextList<C> {
    type EntityMutView<'this> = GgswCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = GgswCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
