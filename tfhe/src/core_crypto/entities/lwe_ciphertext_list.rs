use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

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

    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.data.container_len() / self.lwe_size.0)
    }

    pub fn as_view(&self) -> LweCiphertextListView<'_, Scalar> {
        LweCiphertextListView::from_container(self.as_ref(), self.lwe_size)
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweCiphertextList<C> {
    pub fn as_mut_view(&mut self) -> LweCiphertextListMutView<'_, Scalar> {
        let lwe_size = self.lwe_size;
        LweCiphertextListMutView::from_container(self.as_mut(), lwe_size)
    }
}

pub type LweCiphertextListOwned<Scalar> = LweCiphertextList<Vec<Scalar>>;
pub type LweCiphertextListView<'data, Scalar> = LweCiphertextList<&'data [Scalar]>;
pub type LweCiphertextListMutView<'data, Scalar> = LweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> LweCiphertextListOwned<Scalar> {
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
