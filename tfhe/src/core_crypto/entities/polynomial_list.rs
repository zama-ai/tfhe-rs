use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

pub struct PolynomialListBase<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for PolynomialListBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for PolynomialListBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> PolynomialListBase<C> {
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> PolynomialListBase<C> {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        PolynomialListBase {
            data: container,
            polynomial_size,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn polynomial_count(&self) -> PolynomialCount {
        PolynomialCount(self.data.container_len())
    }
}

pub type PolynomialList<Scalar> = PolynomialListBase<Vec<Scalar>>;
pub type PolynomialListView<'data, Scalar> = PolynomialListBase<&'data [Scalar]>;
pub type PolynomialListMutView<'data, Scalar> = PolynomialListBase<&'data mut [Scalar]>;

impl<Scalar: Copy> PolynomialList<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        polynomial_count: PolynomialCount,
    ) -> PolynomialList<Scalar> {
        PolynomialList::from_container(
            vec![fill_with; polynomial_size.0 * polynomial_count.0],
            polynomial_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct PolynomialListCreationMetadata(pub PolynomialSize);

impl<C: Container> CreateFrom<C> for PolynomialListBase<C> {
    type Metadata = PolynomialListCreationMetadata;

    fn create_from(from: C, meta: Self::Metadata) -> PolynomialListBase<C> {
        let PolynomialListCreationMetadata(polynomial_size) = meta;
        PolynomialListBase::from_container(from, polynomial_size)
    }
}

impl<C: Container> ContiguousEntityContainer for PolynomialListBase<C> {
    type PODElement = C::Element;

    type ElementViewMetadata = PolynomialCreationMetadata;

    type ElementView<'this> = PolynomialView<'this, Self::PODElement>
    where
        Self: 'this;

    type SelfViewMetadata = PolynomialListCreationMetadata;

    type SelfView<'this> = PolynomialListView<'this, Self::PODElement>
    where
        Self: 'this;

    fn get_element_view_creation_metadata(&self) -> Self::ElementViewMetadata {
        PolynomialCreationMetadata()
    }

    fn get_element_view_pod_size(&self) -> usize {
        self.polynomial_size().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        PolynomialListCreationMetadata(self.polynomial_size())
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for PolynomialListBase<C> {
    type ElementMutView<'this> = PolynomialMutView<'this, Self::PODElement>
    where
        Self: 'this;

    type SelfMutView<'this> = PolynomialListMutView<'this, Self::PODElement>
    where
        Self: 'this;
}
