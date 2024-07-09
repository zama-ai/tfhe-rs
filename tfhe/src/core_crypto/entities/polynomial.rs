//! Module containing the definition of the Polynomial.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::polynomial::PolynomialVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use std::ops::{Index, IndexMut};

/// A [`polynomial`](`Polynomial`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(PolynomialVersions)]
pub struct Polynomial<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for Polynomial<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for Polynomial<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<C: Container, I: std::slice::SliceIndex<[C::Element]>> Index<I> for Polynomial<C> {
    type Output = <[C::Element] as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        self.as_ref().index(index)
    }
}

impl<C: ContainerMut, I: std::slice::SliceIndex<[C::Element]>> IndexMut<I> for Polynomial<C> {
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.as_mut().index_mut(index)
    }
}

impl<Scalar, C: Container<Element = Scalar>> Polynomial<C> {
    /// Create a [`Polynomial`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type.
    ///
    /// This docstring exhibits [`Polynomial`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for Polynomial creation
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Create a new Polynomial
    /// let polynomial = Polynomial::new(0u64, polynomial_size);
    ///
    /// assert_eq!(polynomial.polynomial_size(), polynomial_size);
    /// assert_eq!(polynomial.degree(), polynomial_size.0 - 1);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = polynomial.into_container();
    ///
    /// // Recreate a polynomial using from_container
    /// let polynomial = Polynomial::from_container(underlying_container);
    ///
    /// assert_eq!(polynomial.polynomial_size(), polynomial_size);
    /// assert_eq!(polynomial.degree(), polynomial_size.0 - 1);
    /// ```
    pub fn from_container(container: C) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a Polynomial"
        );
        Self { data: container }
    }

    /// Return the [`PolynomialSize`] of the [`Polynomial`].
    ///
    /// See [`Polynomial::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len())
    }

    /// Return the degree of the [`Polynomial`] as a usize.
    ///
    /// degree == [`PolynomialSize`] - 1
    ///
    /// See [`Polynomial::from_container`] for usage.
    pub fn degree(&self) -> usize {
        self.polynomial_size().0 - 1
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`Polynomial::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return a view of the [`Polynomial`]. This is useful if an algorithm takes a view by value.
    pub fn as_view(&self) -> PolynomialView<'_, Scalar> {
        PolynomialView::from_container(self.as_ref())
    }
}

impl<'a, Scalar: 'a, C: Container<Element = Scalar>> Polynomial<C> {
    /// Iterate on the elements of the [`Polynomial`].
    pub fn iter(&'a self) -> impl Iterator<Item = &'a Scalar> {
        self.as_ref().iter()
    }
}

impl<'a, Scalar: 'a, C: ContainerMut<Element = Scalar>> Polynomial<C> {
    /// Mutable variant of [`Polynomial::as_view`].
    pub fn as_mut_view(&mut self) -> PolynomialMutView<'_, Scalar> {
        PolynomialMutView::from_container(self.as_mut())
    }

    /// Iterate on the elements of the [`Polynomial`] allowing to modify them.
    pub fn iter_mut(&'a mut self) -> impl Iterator<Item = &'a mut Scalar> {
        self.as_mut().iter_mut()
    }
}

/// A [`Polynomial`] owning the memory for its own storage.
pub type PolynomialOwned<Scalar> = Polynomial<Vec<Scalar>>;
/// A [`Polynomial`] immutably borrowing memory for its own storage.
pub type PolynomialView<'data, Scalar> = Polynomial<&'data [Scalar]>;
/// A [`Polynomial`] mutably borrowing memory for its own storage.
pub type PolynomialMutView<'data, Scalar> = Polynomial<&'data mut [Scalar]>;

impl<Scalar> PolynomialOwned<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new owned [`Polynomial`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type.
    ///
    /// See [`Polynomial::from_container`] for usage.
    pub fn new(fill_with: Scalar, polynomial_size: PolynomialSize) -> PolynomialOwned<Scalar> {
        PolynomialOwned::from_container(vec![fill_with; polynomial_size.0])
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`Polynomial`] entities.
#[derive(Clone, Copy)]
pub struct PolynomialCreationMetadata {}

impl<C: Container> CreateFrom<C> for Polynomial<C> {
    type Metadata = PolynomialCreationMetadata;

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> Self {
        Self::from_container(from)
    }
}
