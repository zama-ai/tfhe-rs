//! Module containing the definition of the GgswCiphertextList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`GGSW ciphertexts`](`crate::core_crypto::entities::GgswCiphertext`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GgswCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GgswCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn ggsw_ciphertext_list_size(
    ciphertext_count: GgswCiphertextCount,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    ciphertext_count.0 * ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GgswCiphertextList<C> {
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
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GgswCiphertextList
    /// let ggsw_list = GgswCiphertextList::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
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
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
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

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
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

    /// Return the [`CiphertextModulus`] of the [`GgswCiphertextList`].
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(self.as_ref(), self.polynomial_size())
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GgswCiphertextList<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size();
        PolynomialList::from_container(self.as_mut(), polynomial_size)
    }
}

/// A [`GgswCiphertextList`] owning the memory for its own storage.
pub type GgswCiphertextListOwned<Scalar> = GgswCiphertextList<Vec<Scalar>>;
/// A [`GgswCiphertextList`] immutably borrowing memory for its own storage.
pub type GgswCiphertextListView<'data, Scalar> = GgswCiphertextList<&'data [Scalar]>;
/// A [`GgswCiphertextList`] mutably borrowing memory for its own storage.
pub type GgswCiphertextListMutView<'data, Scalar> = GgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> GgswCiphertextListOwned<Scalar> {
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
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                ggsw_ciphertext_list_size(
                    ciphertext_count,
                    glwe_size,
                    polynomial_size,
                    decomp_level_count
                )
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GgswCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct GgswCiphertextListCreationMetadata<Scalar: UnsignedInteger>(
    pub GlweSize,
    pub PolynomialSize,
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for GgswCiphertextList<C>
{
    type Metadata = GgswCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GgswCiphertextListCreationMetadata(
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for GgswCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GgswCiphertextCreationMetadata<Scalar>;

    type EntityView<'this> = GgswCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = GgswCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this> = GgswCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GgswCiphertextCreationMetadata(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_base_log,
            self.ciphertext_modulus,
        )
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
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for GgswCiphertextList<C>
{
    type EntityMutView<'this> = GgswCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = GgswCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
