use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

pub struct LweCiphertextListBase<C: Container> {
    data: C,
    lwe_size: LweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweCiphertextListBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweCiphertextListBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweCiphertextListBase<C> {
    pub fn from_container(container: C, lwe_size: LweSize) -> LweCiphertextListBase<C> {
        assert!(
            container.container_len() % lwe_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by lwe_size. \
        Got container length: {} and lwe_size: {lwe_size:?}.",
            container.container_len()
        );
        LweCiphertextListBase {
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
}

pub type LweCiphertextList<Scalar> = LweCiphertextListBase<Vec<Scalar>>;
pub type LweCiphertextListView<'data, Scalar> = LweCiphertextListBase<&'data [Scalar]>;
pub type LweCiphertextListMutView<'data, Scalar> = LweCiphertextListBase<&'data mut [Scalar]>;

impl<Scalar: Copy> LweCiphertextList<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
    ) -> LweCiphertextList<Scalar> {
        LweCiphertextList::from_container(
            vec![fill_with; lwe_size.0 * ciphertext_count.0],
            lwe_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct LweCiphertextListCreationMetadata(pub LweSize);

impl<C: Container> CreateFrom<C> for LweCiphertextListBase<C> {
    type Metadata = LweCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> LweCiphertextListBase<C> {
        let lwe_size = meta.0;
        LweCiphertextListBase::from_container(from, lwe_size)
    }
}

impl<C: Container> ContiguousEntityContainer for LweCiphertextListBase<C> {
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

impl<C: ContainerMut> ContiguousEntityContainerMut for LweCiphertextListBase<C> {
    type EntityMutView<'this> = LweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
