//! Module containing the definition of the CmGlweCiphertextList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`GLWE ciphertexts`](`crate::core_crypto::entities::GlweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
// Versionize
// #[versionize(CmGlweCiphertextListVersions)]
pub struct CmGlweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmGlweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmGlweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGlweCiphertextList<C> {
    /// Create a [`CmGlweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data in
    /// the list you need to use [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list`] or
    /// a variant working on a single ciphertext at a time
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] on the individual
    /// ciphertexts in the list.
    ///
    /// This docstring exhibits [`CmGlweCiphertextList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CmGlweCiphertextList creation
    /// let glwe_dimension = GlweDimension(2);
    /// let cm_dimension = CmDimension(2);
    /// let cm_dimension = CmDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_count = GlweCiphertextCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new CmGlweCiphertextList and fill it using copies of a single element
    /// let glwe_list = CmGlweCiphertextList::new(
    ///     0u64,
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_list.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_list.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(glwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Alternatively, create a new CmGlweCiphertextList and fill it using a function
    /// let glwe_list = CmGlweCiphertextList::from_fn(
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     ciphertext_count,
    ///     ciphertext_modulus,
    ///     |i, j| {
    ///         // The `i` value represents the index in the list being filled;
    ///         // The `j` value represents the index in the ciphertext being filled;
    ///         // In this example, for every index pair `(i, j)`, we fill the
    ///         // corresponding value using the formula `i + j`
    ///         (i + j) as u64
    ///     },
    /// );
    ///
    /// assert_eq!(glwe_list.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_list.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(glwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let glwe_list = CmGlweCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_list.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_list.polynomial_size(), polynomial_size);
    /// assert_eq!(glwe_list.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(glwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() %  cm_glwe_ciphertext_size(
                glwe_dimension,
                cm_dimension,
                polynomial_size,
            ) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by (glwe_dimension + cm_dimension) * polynomial_size. \
        Got container length: {}, glwe_dimension: {glwe_dimension:?}, cm_dimension: {cm_dimension:?}, polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            polynomial_size,
            ciphertext_modulus,
            glwe_dimension,
            cm_dimension,
        }
    }

    /// Return the [`GlweDimension`] of the [`GlweCiphertext`] stored in the list.
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    /// Return the [`PolynomialSize`] of the [`GlweCiphertext`] stored in the list.
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweCiphertextCount`] of the [`CmGlweCiphertextList`].
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(
            self.data.container_len()
                / cm_glwe_ciphertext_size(
                    self.glwe_dimension,
                    self.cm_dimension,
                    self.polynomial_size,
                ),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`CmGlweCiphertextList`].
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

/// A [`CmGlweCiphertextList`] owning the memory for its own storage.
pub type CmGlweCiphertextListOwned<Scalar> = CmGlweCiphertextList<Vec<Scalar>>;
/// A [`CmGlweCiphertextList`] immutably borrowing memory for its own storage.
pub type CmGlweCiphertextListView<'data, Scalar> = CmGlweCiphertextList<&'data [Scalar]>;
/// A [`CmGlweCiphertextList`] mutably borrowing memory for its own storage.
pub type CmGlweCiphertextListMutView<'data, Scalar> = CmGlweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGlweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`CmGlweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data in the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list`] or a variant working on
    /// a single ciphertext at a time [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] on
    /// the individual ciphertexts in the list.
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_count: GlweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size)
                    * ciphertext_count.0
            ],
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Allocate memory and create a new owned [`LweCiphertextList`], where each element
    /// is provided by the `fill_with` function, invoked for each consecutive index.
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data in the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list`] or a variant working on
    /// a single ciphertext at a time [`crate::core_crypto::algorithms::encrypt_glwe_ciphertext`] on
    /// the individual ciphertexts in the list.
    ///
    /// See [`CmGlweCiphertextList::from_container`] for usage.
    pub fn from_fn<F>(
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_count: GlweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        mut fill_with: F,
    ) -> Self
    where
        F: FnMut(usize, usize) -> Scalar,
    {
        let ciphertext_size =
            cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size);
        let container: Vec<_> = (0..ciphertext_count.0)
            .flat_map(move |i| (0..ciphertext_size).map(move |j| (i, j)))
            .map(|(i, j)| fill_with(i, j))
            .collect();
        Self::from_container(
            container,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`CmGlweCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct CmGlweCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGlweCiphertextList<C>
{
    type Metadata = CmGlweCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGlweCiphertextListCreationMetadata {
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmGlweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmGlweCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmGlweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmGlweCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmGlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmGlweCiphertextCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        cm_glwe_ciphertext_size(
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size(),
        )
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmGlweCiphertextListCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmGlweCiphertextList<C>
{
    type EntityMutView<'this>
        = CmGlweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmGlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
