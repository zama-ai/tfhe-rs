//! Module containing the definition of the CmGlweCiphertextList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmGlweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmGlweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmGlweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGlweCiphertextList<C> {
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len().is_multiple_of(cm_glwe_ciphertext_size(
                glwe_dimension,
                cm_dimension,
                polynomial_size,
            )),
            "The provided container length is not valid. \
        It needs to be dividable by (glwe_dimension + cm_dimension) * polynomial_size. \
        Got container length: {}, glwe_dimension: {glwe_dimension:?}, cm_dimension: {cm_dimension:?}, polynomial_size: {polynomial_size:?}.",
            container.container_len()
        );
        Self {
            data: container,
            polynomial_size,
            ciphertext_modulus,
            glwe_dimension,
            cm_dimension,
        }
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(
            self.data.container_len()
                / cm_glwe_ciphertext_size(
                    self.glwe_dimension,
                    self.cm_dimension,
                    self.polynomial_size,
                ),
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

pub type CmGlweCiphertextListOwned<Scalar> = CmGlweCiphertextList<Vec<Scalar>>;

pub type CmGlweCiphertextListView<'data, Scalar> = CmGlweCiphertextList<&'data [Scalar]>;

pub type CmGlweCiphertextListMutView<'data, Scalar> = CmGlweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGlweCiphertextListOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_count: GlweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size)
                    * ciphertext_count.0
            ],
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn from_fn<F>(
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_count: GlweCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        mut fill_with: F,
    ) -> Self
    where
        F: FnMut(usize, usize) -> Scalar,
    {
        let ciphertext_size =
            cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size);
        let container: Vec<_> = (0..ciphertext_count.0)
            .flat_map(move |i| (0..ciphertext_size).map(move |j| (i, j)))
            .map(|(i, j)| fill_with(i, j))
            .collect();
        Self::from_container(
            container,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmGlweCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGlweCiphertextList<C>
{
    type Metadata = CmGlweCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGlweCiphertextListCreationMetadata {
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmGlweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmGlweCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmGlweCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmGlweCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmGlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmGlweCiphertextCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        cm_glwe_ciphertext_size(
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size(),
        )
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmGlweCiphertextListCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmGlweCiphertextList<C>
{
    type EntityMutView<'this>
        = CmGlweCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmGlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
