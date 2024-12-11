//! Module containing the definition of the PolynomialList.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::polynomial_list::PolynomialListVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing
/// [`polynomials`](`crate::core_crypto::entities::Polynomial`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(PolynomialListVersions)]
pub struct PolynomialList<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for PolynomialList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for PolynomialList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> PolynomialList<C> {
    /// Create an [`PolynomialList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type.
    ///
    /// This docstring exhibits [`PolynomialList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for PolynomialList creation
    /// let polynomial_size = PolynomialSize(1024);
    /// let polynomial_count = PolynomialCount(3);
    ///
    /// // Create a new PolynomialList
    /// let polynomial_list = PolynomialList::new(0u64, polynomial_size, polynomial_count);
    ///
    /// assert_eq!(polynomial_list.polynomial_size(), polynomial_size);
    /// assert_eq!(polynomial_list.polynomial_count(), polynomial_count);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = polynomial_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let polynomial_list = PolynomialList::from_container(underlying_container, polynomial_size);
    ///
    /// assert_eq!(polynomial_list.polynomial_size(), polynomial_size);
    /// assert_eq!(polynomial_list.polynomial_count(), polynomial_count);
    /// ```
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> Self {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            polynomial_size,
        }
    }

    /// Return the [`PolynomialSize`] of the [`Polynomial`] stored in the list.
    ///
    /// See [`PolynomialList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`PolynomialCount`] of the [`PolynomialList`] stored in the list.
    ///
    /// See [`PolynomialList::from_container`] for usage.
    pub fn polynomial_count(&self) -> PolynomialCount {
        PolynomialCount(self.data.container_len() / self.polynomial_size.0)
    }

    /// Return a view of the [`PolynomialList`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`PolynomialList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> PolynomialList<C> {
    /// Mutable variant of [`PolynomialList::as_view`].
    pub fn as_mut_view(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size();
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }
}

/// A [`PolynomialList`] owning the memory for its own storage.
pub type PolynomialListOwned<Scalar> = PolynomialList<Vec<Scalar>>;
/// A [`PolynomialList`] immutably borrowing memory for its own storage.
pub type PolynomialListView<'data, Scalar> = PolynomialList<&'data [Scalar]>;
/// A [`PolynomialList`] mutably borrowing memory for its own storage.
pub type PolynomialListMutView<'data, Scalar> = PolynomialList<&'data mut [Scalar]>;

impl<Scalar: Copy> PolynomialListOwned<Scalar> {
    /// Allocate memory and create a new owned [`PolynomialList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type.
    ///
    /// See [`PolynomialList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        polynomial_count: PolynomialCount,
    ) -> Self {
        Self::from_container(
            vec![fill_with; polynomial_size.0 * polynomial_count.0],
            polynomial_size,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`PolynomialList`] entities.
#[derive(Clone, Copy)]
pub struct PolynomialListCreationMetadata {
    pub polynomial_size: PolynomialSize,
}

impl<C: Container> CreateFrom<C> for PolynomialList<C> {
    type Metadata = PolynomialListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let PolynomialListCreationMetadata { polynomial_size } = meta;
        Self::from_container(from, polynomial_size)
    }
}

impl<C: Container> ContiguousEntityContainer for PolynomialList<C> {
    type Element = C::Element;

    type EntityViewMetadata = PolynomialCreationMetadata;

    type EntityView<'this>
        = PolynomialView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = PolynomialListCreationMetadata;

    type SelfView<'this>
        = PolynomialListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        PolynomialCreationMetadata {}
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        PolynomialListCreationMetadata {
            polynomial_size: self.polynomial_size(),
        }
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for PolynomialList<C> {
    type EntityMutView<'this>
        = PolynomialMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = PolynomialListMutView<'this, Self::Element>
    where
        Self: 'this;
}
