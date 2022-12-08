use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweCiphertextList<C: Container> {
    data: C,
    lwe_size: LweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweCiphertextList<C> {
    /// Create a [`LweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its
    /// parallel variant [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using
    /// this list as output.
    ///
    /// This docstring exhibits [`LweCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // Define parameters for LweCiphertextList creation
    /// let lwe_size = LweSize(601);
    /// let lwe_ciphertext_count = LweCiphertextCount(3);
    ///
    /// // Create a new LweCiphertextList
    /// let lwe_list = LweCiphertextList::new(0u64, lwe_size, lwe_ciphertext_count);
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_size);
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_list.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let lwe_list = LweCiphertextList::from_container(underlying_container, lwe_size);
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_size);
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// ```
    pub fn from_container(container: C, lwe_size: LweSize) -> LweCiphertextList<C> {
        assert!(
            container.container_len() % lwe_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by lwe_size. \
        Got container length: {} and lwe_size: {lwe_size:?}.",
            container.container_len()
        );
        LweCiphertextList {
            data: container,
            lwe_size,
        }
    }

    /// Return the [`LweSize`] of the [`LweCiphertext`] stored in the list.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`LweCiphertextCount`] of the [`LweCiphertextList`].
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.data.container_len() / self.lwe_size.0)
    }

    /// Return a view of the [`LweCiphertextList`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweCiphertextListView<'_, Scalar> {
        LweCiphertextListView::from_container(self.as_ref(), self.lwe_size)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweCiphertextList<C> {
    /// Mutable variant of [`LweCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> LweCiphertextListMutView<'_, Scalar> {
        let lwe_size = self.lwe_size;
        LweCiphertextListMutView::from_container(self.as_mut(), lwe_size)
    }
}

/// A [`LweCiphertextList`] owning the memory for its own storage.
pub type LweCiphertextListOwned<Scalar> = LweCiphertextList<Vec<Scalar>>;
/// A [`LweCiphertextList`] immutably borrowing memory for its own storage.
pub type LweCiphertextListView<'data, Scalar> = LweCiphertextList<&'data [Scalar]>;
/// A [`LweCiphertextList`] mutably borrowing memory for its own storage.
pub type LweCiphertextListMutView<'data, Scalar> = LweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> LweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext_list`] or its parallel variant
    /// [`crate::core_crypto::algorithms::par_encrypt_lwe_ciphertext_list`] using this list as
    /// output.
    ///
    /// See [`LweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
    ) -> LweCiphertextListOwned<Scalar> {
        LweCiphertextListOwned::from_container(
            vec![fill_with; lwe_size.0 * ciphertext_count.0],
            lwe_size,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`LweCiphertextList`] entities.
#[derive(Clone, Copy)]
pub struct LweCiphertextListCreationMetadata(pub LweSize);

impl<C: Container> CreateFrom<C> for LweCiphertextList<C> {
    type Metadata = LweCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> LweCiphertextList<C> {
        let lwe_size = meta.0;
        LweCiphertextList::from_container(from, lwe_size)
    }
}

impl<C: Container> ContiguousEntityContainer for LweCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextCreationMetadata;

    type EntityView<'this> = LweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LweCiphertextListCreationMetadata;

    type SelfView<'this> = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> LweCiphertextCreationMetadata {
        LweCiphertextCreationMetadata()
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_size.0
    }

    fn get_self_view_creation_metadata(&self) -> LweCiphertextListCreationMetadata {
        LweCiphertextListCreationMetadata(self.lwe_size)
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for LweCiphertextList<C> {
    type EntityMutView<'this> = LweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
