use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlweCiphertextList<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GlweCiphertextList<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> GlweCiphertextList<C> {
        assert!(
            container.container_len() % glwe_ciphertext_size(polynomial_size, glwe_size) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size * glwe_size. \
        Got container length: {}, polynomial_size: {polynomial_size:?} glwe_size: {glwe_size:?}.",
            container.container_len()
        );
        GlweCiphertextList {
            data: container,
            polynomial_size,
            glwe_size,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(
            self.data.container_len() / glwe_ciphertext_size(self.polynomial_size, self.glwe_size),
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

pub type GlweCiphertextListOwned<Scalar> = GlweCiphertextList<Vec<Scalar>>;
pub type GlweCiphertextListView<'data, Scalar> = GlweCiphertextList<&'data [Scalar]>;
pub type GlweCiphertextListMutView<'data, Scalar> = GlweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: Copy> GlweCiphertextListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        ciphertext_count: GlweCiphertextCount,
    ) -> GlweCiphertextListOwned<Scalar> {
        GlweCiphertextListOwned::from_container(
            vec![fill_with; glwe_ciphertext_size(polynomial_size, glwe_size) * ciphertext_count.0],
            polynomial_size,
            glwe_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct GlweCiphertextListCreationMetadata(pub PolynomialSize, pub GlweSize);

impl<C: Container> CreateFrom<C> for GlweCiphertextList<C> {
    type Metadata = GlweCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GlweCiphertextList<C> {
        let GlweCiphertextListCreationMetadata(polynomial_size, glwe_size) = meta;
        GlweCiphertextList::from_container(from, polynomial_size, glwe_size)
    }
}

impl<C: Container> ContiguousEntityContainer for GlweCiphertextList<C> {
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextCreationMetadata;

    type EntityView<'this> = GlweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = GlweCiphertextListCreationMetadata;

    type SelfView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> GlweCiphertextCreationMetadata {
        GlweCiphertextCreationMetadata(self.polynomial_size())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        glwe_ciphertext_size(self.polynomial_size(), self.glwe_size())
    }

    fn get_self_view_creation_metadata(&self) -> GlweCiphertextListCreationMetadata {
        GlweCiphertextListCreationMetadata(self.polynomial_size(), self.glwe_size())
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for GlweCiphertextList<C> {
    type EntityMutView<'this> = GlweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
