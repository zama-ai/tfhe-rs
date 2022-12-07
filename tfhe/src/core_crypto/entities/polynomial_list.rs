use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> PolynomialList<C> {
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        PolynomialList {
            data: container,
            polynomial_size,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn polynomial_count(&self) -> PolynomialCount {
        PolynomialCount(self.data.container_len() / self.polynomial_size.0)
    }

    pub fn as_view(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size())
    }

    /// Consumes the entity and return its underlying container.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> PolynomialList<C> {
    pub fn as_mut_view(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size();
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }
}

pub type PolynomialListOwned<Scalar> = PolynomialList<Vec<Scalar>>;
pub type PolynomialListView<'data, Scalar> = PolynomialList<&'data [Scalar]>;
pub type PolynomialListMutView<'data, Scalar> = PolynomialList<&'data mut [Scalar]>;

impl<Scalar: Copy> PolynomialListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        polynomial_count: PolynomialCount,
    ) -> PolynomialListOwned<Scalar> {
        PolynomialListOwned::from_container(
            vec![fill_with; polynomial_size.0 * polynomial_count.0],
            polynomial_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct PolynomialListCreationMetadata(pub PolynomialSize);

impl<C: Container> CreateFrom<C> for PolynomialList<C> {
    type Metadata = PolynomialListCreationMetadata;

    fn create_from(from: C, meta: Self::Metadata) -> PolynomialList<C> {
        let PolynomialListCreationMetadata(polynomial_size) = meta;
        PolynomialList::from_container(from, polynomial_size)
    }
}

impl<C: Container> ContiguousEntityContainer for PolynomialList<C> {
    type Element = C::Element;

    type EntityViewMetadata = PolynomialCreationMetadata;

    type EntityView<'this> = PolynomialView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = PolynomialListCreationMetadata;

    type SelfView<'this> = PolynomialListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        PolynomialCreationMetadata()
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.polynomial_size().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        PolynomialListCreationMetadata(self.polynomial_size())
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for PolynomialList<C> {
    type EntityMutView<'this> = PolynomialMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = PolynomialListMutView<'this, Self::Element>
    where
        Self: 'this;
}
