//! Module containing the definition of the GlweCiphertextList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`GLWE ciphertexts`](`crate::core_crypto::entities::GlweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweCiphertextList<C> {
    /// Create a [`GlweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data in
    /// the list you need to use [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list`] or
    /// a variant working on a single ciphertext at a time
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] on the individual
    /// ciphertexts in the list.
    ///
    /// This docstring exhibits [`GlweCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweCiphertextList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_count = GlweCiphertextCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GlweCiphertextList
    /// let glwe_list = GlweCiphertextList::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_list.glwe_size(), glwe_size);
    /// assert_eq!(glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_list.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(glwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let glwe_list = GlweCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_list.glwe_size(), glwe_size);
    /// assert_eq!(glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_list.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(glwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % glwe_ciphertext_size(glwe_size, polynomial_size) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by glwe_size * polynomial_size. \
        Got container length: {}, glwe_size: {glwe_size:?}, polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`GlweCiphertext`] stored in the list.
    ///
    /// See [`GlweCiphertextList::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`GlweCiphertext`] stored in the list.
    ///
    /// See [`GlweCiphertextList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweCiphertextCount`] of the [`GlweCiphertextList`].
    ///
    /// See [`GlweCiphertextList::from_container`] for usage.
    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(
            self.data.container_len() / glwe_ciphertext_size(self.glwe_size, self.polynomial_size),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GlweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`GlweCiphertextList`].
    ///
    /// See [`GlweCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

/// A [`GlweCiphertextList`] owning the memory for its own storage.
pub type GlweCiphertextListOwned<Scalar> = GlweCiphertextList<Vec<Scalar>>;
/// A [`GlweCiphertextList`] immutably borrowing memory for its own storage.
pub type GlweCiphertextListView<'data, Scalar> = GlweCiphertextList<&'data [Scalar]>;
/// A [`GlweCiphertextList`] mutably borrowing memory for its own storage.
pub type GlweCiphertextListMutView<'data, Scalar> = GlweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> GlweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`GlweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data in the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list`] or a variant working on
    /// a single ciphertext at a time [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] on
    /// the individual ciphertexts in the list.
    ///
    /// See [`GlweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_count: GlweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; glwe_ciphertext_size(glwe_size, polynomial_size) * ciphertext_count.0],
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GlweCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct GlweCiphertextListCreationMetadata<Scalar: UnsignedInteger>(
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for GlweCiphertextList<C>
{
    type Metadata = GlweCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GlweCiphertextListCreationMetadata(glwe_size, polynomial_size, ciphertext_modulus) =
            meta;
        Self::from_container(from, glwe_size, polynomial_size, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for GlweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this> = GlweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = GlweCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextCreationMetadata(self.polynomial_size(), self.ciphertext_modulus())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        glwe_ciphertext_size(self.glwe_size(), self.polynomial_size())
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        GlweCiphertextListCreationMetadata(
            self.glwe_size(),
            self.polynomial_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for GlweCiphertextList<C>
{
    type EntityMutView<'this> = GlweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
