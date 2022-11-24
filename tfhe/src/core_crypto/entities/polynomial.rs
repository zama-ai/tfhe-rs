use crate::core_crypto::commons::traits::*;
use crate::core_crypto::specification::parameters::*;
use std::ops::{Deref, DerefMut};

pub struct PolynomialBase<C: Container> {
    data: C,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for PolynomialBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for PolynomialBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> PolynomialBase<C> {
    pub fn from_container(container: C) -> PolynomialBase<C> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a Polynomial"
        );
        PolynomialBase { data: container }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        PolynomialSize(self.data.container_len())
    }

    pub fn degree(&self) -> usize {
        self.polynomial_size().0 - 1
    }
}

pub type Polynomial<Scalar> = PolynomialBase<Vec<Scalar>>;
pub type PolynomialView<'data, Scalar> = PolynomialBase<&'data [Scalar]>;
pub type PolynomialMutView<'data, Scalar> = PolynomialBase<&'data mut [Scalar]>;

impl<Scalar> Polynomial<Vec<Scalar>>
where
    Scalar: Copy,
{
    pub fn new(fill_with: Scalar, polynomial_size: PolynomialSize) -> Polynomial<Scalar> {
        Polynomial::from_container(vec![fill_with; polynomial_size.0])
    }
}

impl<C: Container> Deref for PolynomialBase<C> {
    type Target = [C::Element];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<C: ContainerMut> DerefMut for PolynomialBase<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

#[derive(Clone, Copy)]
pub struct PolynomialCreationMetadata();

impl<C: Container> CreateFrom<C> for PolynomialBase<C> {
    type Metadata = PolynomialCreationMetadata;

    fn create_from(from: C, _: Self::Metadata) -> PolynomialBase<C> {
        PolynomialBase::from_container(from)
    }
}
