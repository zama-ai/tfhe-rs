//! Module containing the definition of the [`CmLweCiphertextList`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

use self::cm_lwe_ciphertext::{
    CmLweCiphertextCreationMetadata, CmLweCiphertextMutView, CmLweCiphertextView,
};

/// A contiguous list containing
/// [`LWE ciphertexts`](`crate::core_crypto::entities::CmLweCiphertext`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_dimension: LweDimension,
    cm_dimension: CmDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweCiphertextList<C> {
    /// Create an [`CmLweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its
    /// parallel variant [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using
    /// this list as output.
    ///
    /// This docstring exhibits [`CmLweCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CmLweCiphertextList creation
    /// let lwe_dimension = LweDimension(600);
    /// let cm_dimension = CmDimension(2);
    /// let cm_lwe_ciphertext_count = CmLweCiphertextCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new CmLweCiphertextList
    /// let lwe_list = CmLweCiphertextList::new(
    ///     0u64,
    ///     lwe_dimension,
    ///     cm_dimension,
    ///     cm_lwe_ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_list.lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe_list.cm_dimension(), cm_dimension);
    /// assert_eq!(lwe_list.cm_lwe_ciphertext_count(), cm_lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let lwe_list = CmLweCiphertextList::from_container(
    ///     underlying_container,
    ///     lwe_dimension,
    ///     cm_dimension,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_list.lwe_dimension(), lwe_dimension);
    /// assert_eq!(lwe_list.cm_dimension(), cm_dimension);
    /// assert_eq!(lwe_list.cm_lwe_ciphertext_count(), cm_lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() % (lwe_dimension.0 + cm_dimension.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by lwe_dimension + cm_dimension. \
        Got container length: {} and lwe_dimension + cm_dimension: {}.",
            container.container_len(),
            lwe_dimension.0 + cm_dimension.0
        );
        Self {
            data: container,
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        }
    }

    /// Return the [`LweDimension`] of the [`CmLweCiphertext`] stored in the list.
    ///
    /// See [`CmLweCiphertextList::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    /// Return the [`CmDimension`] of the [`CmLweCiphertext`] stored in the list.
    ///
    /// See [`CmLweCiphertextList::from_container`] for usage.
    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    /// Return the [`CmLweCiphertextCount`] of the [`CmLweCiphertextList`].
    ///
    /// See [`CmLweCiphertextList::from_container`] fosr usage.
    pub fn cm_lwe_ciphertext_count(&self) -> CmLweCiphertextCount {
        CmLweCiphertextCount(
            self.data.container_len() / (self.lwe_dimension.0 + self.cm_dimension.0),
        )
    }

    /// Return a view of the [`CmLweCiphertextList`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> CmLweCiphertextListView<'_, Scalar> {
        CmLweCiphertextListView::from_container(
            self.as_ref(),
            self.lwe_dimension,
            self.cm_dimension,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CmLweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`CmLweCiphertextList`].
    ///
    /// See [`CmLweCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweCiphertextList<C> {
    /// Mutable variant of [`CmLweCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> CmLweCiphertextListMutView<'_, Scalar> {
        let lwe_dimension = self.lwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();
        let cm_dimension = self.cm_dimension;

        CmLweCiphertextListMutView::from_container(
            self.as_mut(),
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

/// An [`CmLweCiphertextList`] owning the memory for its own storage.
pub type CmLweCiphertextListOwned<Scalar> = CmLweCiphertextList<Vec<Scalar>>;
/// An [`CmLweCiphertextList`] immutably borrowing memory for its own storage.
pub type CmLweCiphertextListView<'data, Scalar> = CmLweCiphertextList<&'data [Scalar]>;
/// An [`CmLweCiphertextList`] mutably borrowing memory for its own storage.
pub type CmLweCiphertextListMutView<'data, Scalar> = CmLweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`CmLweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its parallel variant
    /// [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using this list as
    /// output.
    ///
    /// See [`CmLweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_count: CmLweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; (lwe_dimension.0 + cm_dimension.0) * ciphertext_count.0],
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`CmLweCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct CmLweCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmLweCiphertextList<C>
{
    type Metadata = CmLweCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweCiphertextListCreationMetadata {
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, lwe_dimension, cm_dimension, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmLweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLweCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLweCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmLweCiphertextCreationMetadata {
            ciphertext_modulus: self.ciphertext_modulus,
            lwe_dimension: self.lwe_dimension,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_dimension().0 + self.cm_dimension().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmLweCiphertextListCreationMetadata {
            lwe_dimension: self.lwe_dimension,
            cm_dimension: self.cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLweCiphertextList<C>
{
    type EntityMutView<'this>
        = CmLweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
