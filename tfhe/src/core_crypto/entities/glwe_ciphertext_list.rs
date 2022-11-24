use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::parameters::*;

pub struct GlweCiphertextListBase<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweCiphertextListBase<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweCiphertextListBase<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GlweCiphertextListBase<C> {
    pub fn from_container(
        container: C,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
    ) -> GlweCiphertextListBase<C> {
        assert!(
            container.container_len() % glwe_ciphertext_size(polynomial_size, glwe_size) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size * glwe_size. \
        Got container length: {}, polynomial_size: {polynomial_size:?} glwe_size: {glwe_size:?}.",
            container.container_len()
        );
        GlweCiphertextListBase {
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
}

pub type GlweCiphertextList<Scalar> = GlweCiphertextListBase<Vec<Scalar>>;
pub type GlweCiphertextListView<'data, Scalar> = GlweCiphertextListBase<&'data [Scalar]>;
pub type GlweCiphertextListMutView<'data, Scalar> = GlweCiphertextListBase<&'data mut [Scalar]>;

impl<Scalar: Copy> GlweCiphertextList<Scalar> {
    pub fn new(
        fill_with: Scalar,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        ciphertext_count: GlweCiphertextCount,
    ) -> GlweCiphertextList<Scalar> {
        GlweCiphertextList::from_container(
            vec![fill_with; glwe_ciphertext_size(polynomial_size, glwe_size) * ciphertext_count.0],
            polynomial_size,
            glwe_size,
        )
    }
}

#[derive(Clone, Copy)]
pub struct GlweCiphertextListCreationMetadata(pub PolynomialSize, pub GlweSize);

impl<C: Container> CreateFrom<C> for GlweCiphertextListBase<C> {
    type Metadata = GlweCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> GlweCiphertextListBase<C> {
        let GlweCiphertextListCreationMetadata(polynomial_size, glwe_size) = meta;
        GlweCiphertextListBase::from_container(from, polynomial_size, glwe_size)
    }
}

impl<C: Container> ContiguousEntityContainer for GlweCiphertextListBase<C> {
    type PODElement = C::Element;

    type ElementViewMetadata = GlweCiphertextCreationMetadata;

    type ElementView<'this> = GlweCiphertextView<'this, Self::PODElement>
    where
        Self: 'this;

    type SelfViewMetadata = GlweCiphertextListCreationMetadata;

    type SelfView<'this> = GlweCiphertextListView<'this, Self::PODElement>
    where
        Self: 'this;

    fn get_element_view_creation_metadata(&self) -> GlweCiphertextCreationMetadata {
        GlweCiphertextCreationMetadata(self.polynomial_size())
    }

    fn get_element_view_pod_size(&self) -> usize {
        glwe_ciphertext_size(self.polynomial_size(), self.glwe_size())
    }

    fn get_self_view_creation_metadata(&self) -> GlweCiphertextListCreationMetadata {
        GlweCiphertextListCreationMetadata(self.polynomial_size(), self.glwe_size())
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for GlweCiphertextListBase<C> {
    type ElementMutView<'this> = GlweCiphertextMutView<'this, Self::PODElement>
    where
        Self: 'this;

    type SelfMutView<'this> = GlweCiphertextListMutView<'this, Self::PODElement>
    where
        Self: 'this;
}
