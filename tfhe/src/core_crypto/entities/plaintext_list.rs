//! Module containing the definition of the PlaintextList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing [`plaintexts`](`crate::core_crypto::entities::Plaintext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlaintextList<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for PlaintextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> AsMut<[Scalar]> for PlaintextList<C> {
    fn as_mut(&mut self) -> &mut [Scalar] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> PlaintextList<C> {
    /// Create a [`PlaintextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type.
    ///
    /// This docstring exhibits [`PlaintextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // Define parameters for PlaintextList creation
    /// let plaintext_count = PlaintextCount(1024);
    ///
    /// // Create a new PlaintextList
    /// let plaintext_list = PlaintextList::new(0u64, plaintext_count);
    ///
    /// assert_eq!(plaintext_list.plaintext_count(), plaintext_count);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = plaintext_list.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let plaintext_list = PlaintextList::from_container(underlying_container);
    ///
    /// assert_eq!(plaintext_list.plaintext_count(), plaintext_count);
    /// ```
    pub fn from_container(container: C) -> Self {
        Self { data: container }
    }

    /// Return the [`PlaintextCount`] of the [`PlaintextList`].
    ///
    /// See [`PlaintextList::from_container`] for usage.
    pub fn plaintext_count(&self) -> PlaintextCount {
        PlaintextCount(self.data.container_len())
    }

    /// Interpret the [`PlaintextList`] as a [`Polynomial`].
    pub fn as_polynomial(&self) -> PolynomialView<'_, Scalar> {
        PolynomialView::from_container(self.as_ref())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`PlaintextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return a view of the [`PlaintextList`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> PlaintextListView<'_, Scalar> {
        PlaintextListView::from_container(self.as_ref())
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> PlaintextList<C> {
    /// Mutable variant of [`PlaintextList::as_polynomial`].
    pub fn as_mut_polynomial(&mut self) -> PolynomialMutView<'_, Scalar> {
        PolynomialMutView::from_container(self.as_mut())
    }

    /// Mutable variant of [`PlaintextList::as_view`].
    pub fn as_mut_view(&mut self) -> PlaintextListMutView<'_, Scalar> {
        PlaintextListMutView::from_container(self.as_mut())
    }
}

/// A [`PlaintextList`] owning the memory for its own storage.
pub type PlaintextListOwned<Scalar> = PlaintextList<Vec<Scalar>>;
/// A [`PlaintextList`] immutably borrowing memory for its own storage.
pub type PlaintextListView<'data, Scalar> = PlaintextList<&'data [Scalar]>;
/// A [`PlaintextList`] mutably borrowing memory for its own storage.
pub type PlaintextListMutView<'data, Scalar> = PlaintextList<&'data mut [Scalar]>;

impl<Scalar> PlaintextListOwned<Scalar>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new owned [`PlaintextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type.
    ///
    /// See [`PlaintextList::from_container`] for usage.
    pub fn new(fill_with: Scalar, count: PlaintextCount) -> Self {
        Self::from_container(vec![fill_with; count.0])
    }
}

impl<C: Container> CreateFrom<C> for PlaintextList<C> {
    type Metadata = ();

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> Self {
        Self::from_container(from)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for PlaintextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = ();

    type EntityView<'this> = PlaintextRef<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = PlaintextList<&'this [Self::Element]>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {}

    fn get_entity_view_pod_size(&self) -> usize {
        1
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {}
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for PlaintextList<C>
{
    type EntityMutView<'this>= PlaintextRefMut<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>= PlaintextList<&'this mut [Self::Element]>
    where
        Self: 'this;
}
