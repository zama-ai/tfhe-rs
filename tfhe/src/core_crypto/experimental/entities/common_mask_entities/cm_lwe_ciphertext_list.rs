//! Module containing the definition of the [`CmLweCiphertextList`].

use super::cm_lwe_ciphertext::{
    CmLweCiphertextCreationMetadata, CmLweCiphertextMutView, CmLweCiphertextView,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_dimension: LweDimension,
    cm_dimension: CmDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweCiphertextList<C> {
    pub fn from_container(
        container: C,
        lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container
                .container_len()
                .is_multiple_of(lwe_dimension.0 + cm_dimension.0),
            "The provided container length is not valid. \
        It needs to be dividable by lwe_dimension + cm_dimension. \
        Got container length: {} and lwe_dimension + cm_dimension: {}.",
            container.container_len(),
            lwe_dimension.0 + cm_dimension.0
        );
        Self {
            data: container,
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn cm_lwe_ciphertext_count(&self) -> CmLweCiphertextCount {
        CmLweCiphertextCount(
            self.data.container_len() / (self.lwe_dimension.0 + self.cm_dimension.0),
        )
    }

    pub fn as_view(&self) -> CmLweCiphertextListView<'_, Scalar> {
        CmLweCiphertextListView::from_container(
            self.as_ref(),
            self.lwe_dimension,
            self.cm_dimension,
            self.ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweCiphertextList<C> {
    pub fn as_mut_view(&mut self) -> CmLweCiphertextListMutView<'_, Scalar> {
        let lwe_dimension = self.lwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();
        let cm_dimension = self.cm_dimension;

        CmLweCiphertextListMutView::from_container(
            self.as_mut(),
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

pub type CmLweCiphertextListOwned<Scalar> = CmLweCiphertextList<Vec<Scalar>>;

pub type CmLweCiphertextListView<'data, Scalar> = CmLweCiphertextList<&'data [Scalar]>;

pub type CmLweCiphertextListMutView<'data, Scalar> = CmLweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLweCiphertextListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_count: CmLweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; (lwe_dimension.0 + cm_dimension.0) * ciphertext_count.0],
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmLweCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmLweCiphertextList<C>
{
    type Metadata = CmLweCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweCiphertextListCreationMetadata {
            lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, lwe_dimension, cm_dimension, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmLweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLweCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLweCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmLweCiphertextCreationMetadata {
            ciphertext_modulus: self.ciphertext_modulus,
            lwe_dimension: self.lwe_dimension,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_dimension().0 + self.cm_dimension().0
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmLweCiphertextListCreationMetadata {
            lwe_dimension: self.lwe_dimension,
            cm_dimension: self.cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLweCiphertextList<C>
{
    type EntityMutView<'this>
        = CmLweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
