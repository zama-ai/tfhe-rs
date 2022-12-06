use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
    pub fn from_container(container: C) -> PlaintextList<C> {
        PlaintextList { data: container }
    }

    pub fn plaintext_count(&self) -> PlaintextCount {
        PlaintextCount(self.data.container_len())
    }

    pub fn as_polynomial(&self) -> PolynomialView<'_, Scalar> {
        PolynomialView::from_container(self.as_ref())
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_view(&self) -> PlaintextListView<'_, Scalar> {
        PlaintextListView::from_container(self.as_ref())
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> PlaintextList<C> {
    pub fn as_mut_polynomial(&mut self) -> PolynomialMutView<'_, Scalar> {
        PolynomialMutView::from_container(self.as_mut())
    }

    pub fn as_mut_view(&mut self) -> PlaintextListMutView<'_, Scalar> {
        PlaintextListMutView::from_container(self.as_mut())
    }
}

pub type PlaintextListOwned<Scalar> = PlaintextList<Vec<Scalar>>;
pub type PlaintextListView<'data, Scalar> = PlaintextList<&'data [Scalar]>;
pub type PlaintextListMutView<'data, Scalar> = PlaintextList<&'data mut [Scalar]>;

impl<Scalar> PlaintextListOwned<Scalar>
where
    Scalar: Copy,
{
    pub fn new(fill_with: Scalar, count: PlaintextCount) -> PlaintextListOwned<Scalar> {
        PlaintextListOwned::from_container(vec![fill_with; count.0])
    }
}

impl<C: Container> CreateFrom<C> for PlaintextList<C> {
    type Metadata = ();

    #[inline]
    fn create_from(from: C, _: Self::Metadata) -> PlaintextList<C> {
        PlaintextList::from_container(from)
    }
}

impl<C: Container> ContiguousEntityContainer for PlaintextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = ();

    type EntityView<'this> = Plaintext<&'this Self::Element>
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

impl<C: ContainerMut> ContiguousEntityContainerMut for PlaintextList<C> {
    type EntityMutView<'this>= Plaintext<&'this mut  Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>= PlaintextList<&'this mut [Self::Element]>
    where
        Self: 'this;
}
