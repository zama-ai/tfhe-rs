use crate::core_crypto::commons::traits::*;
use crate::core_crypto::specification::parameters::*;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug)]
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

impl<Scalar, C: Container<Element = Scalar>> Polynomial<C> {
    pub fn from_container(container: C) -> Polynomial<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a Polynomial"
        );
        Polynomial { data: container }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len())
    }

    pub fn degree(&self) -> usize {
        self.polynomial_size().0 - 1
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_view(&self) -> PolynomialView<'_, Scalar> {
        PolynomialView::from_container(self.as_ref())
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> Polynomial<C> {
    pub fn as_mut_view(&mut self) -> PolynomialMutView<'_, Scalar> {
        PolynomialMutView::from_container(self.as_mut())
    }
}

pub type PolynomialOwned<Scalar> = Polynomial<Vec<Scalar>>;
pub type PolynomialView<'data, Scalar> = Polynomial<&'data [Scalar]>;
pub type PolynomialMutView<'data, Scalar> = Polynomial<&'data mut [Scalar]>;

impl<Scalar> PolynomialOwned<Vec<Scalar>>
where
    Scalar: Copy,
{
    pub fn new(fill_with: Scalar, polynomial_size: PolynomialSize) -> PolynomialOwned<Scalar> {
        PolynomialOwned::from_container(vec![fill_with; polynomial_size.0])
    }
}

impl<C: Container> Deref for Polynomial<C> {
    type Target = [C::Element];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<C: ContainerMut> DerefMut for Polynomial<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

#[derive(Clone, Copy)]
pub struct PolynomialCreationMetadata();

impl<C: Container> CreateFrom<C> for Polynomial<C> {
    type Metadata = PolynomialCreationMetadata;

    fn create_from(from: C, _: Self::Metadata) -> Polynomial<C> {
        Polynomial::from_container(from)
    }
}
