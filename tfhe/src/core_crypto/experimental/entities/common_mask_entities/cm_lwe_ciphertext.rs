//! Module containing the definition of the [`CmLweCiphertext`].

use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmLweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_dimension: LweDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweCiphertext<C> {
    pub fn from_container(
        container: C,
        lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an CmLweCiphertext"
        );
        Self {
            data: container,
            ciphertext_modulus,
            lwe_dimension,
        }
    }

    pub fn lwe_dimension(&self) -> LweDimension {
        self.lwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        CmDimension(self.data.container_len() - self.lwe_dimension.0)
    }

    pub fn get_mask_and_bodies(&self) -> (LweMask<&[Scalar]>, LweBodyList<&[Scalar]>) {
        let (mask, bodies) = self.data.as_ref().split_at(self.lwe_dimension.0);

        let ciphertext_modulus = self.ciphertext_modulus();
        (
            LweMask::from_container(mask, ciphertext_modulus),
            LweBodyList::from_container(bodies, ciphertext_modulus),
        )
    }

    pub fn get_bodies(&self) -> LweBodyList<&[Scalar]> {
        self.get_mask_and_bodies().1
    }

    pub fn get_mask(&self) -> LweMask<&[Scalar]> {
        self.get_mask_and_bodies().0
    }

    pub fn as_view(&self) -> CmLweCiphertextView<'_, Scalar> {
        CmLweCiphertextView::from_container(
            self.as_ref(),
            self.lwe_dimension,
            self.ciphertext_modulus(),
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn extract_lwe_ciphertext(&self, index: usize) -> LweCiphertextOwned<Scalar> {
        let mut extracted_lwe = self.get_mask().into_container().to_vec();

        extracted_lwe.push(self.get_bodies().into_container()[index]);

        LweCiphertext::from_container(extracted_lwe, self.ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweCiphertext<C> {
    pub fn get_mut_mask_and_bodies(
        &mut self,
    ) -> (LweMask<&mut [Scalar]>, LweBodyList<&mut [Scalar]>) {
        let ciphertext_modulus = self.ciphertext_modulus();
        let (mask, bodies) = self.data.as_mut().split_at(self.lwe_dimension.0);

        (
            LweMask::from_container(mask, ciphertext_modulus),
            LweBodyList::from_container(bodies, ciphertext_modulus),
        )
    }

    pub fn get_mut_bodies(&mut self) -> LweBodyList<&mut [Scalar]> {
        self.get_mut_mask_and_bodies().1
    }

    pub fn get_mut_mask(&mut self) -> LweMask<&mut [Scalar]> {
        self.get_mut_mask_and_bodies().0
    }

    pub fn as_mut_view(&mut self) -> CmLweCiphertextMutView<'_, Scalar> {
        let ciphertext_modulus = self.ciphertext_modulus();
        let lwe_dimension = self.lwe_dimension;

        CmLweCiphertextMutView::from_container(self.as_mut(), lwe_dimension, ciphertext_modulus)
    }
}

pub type CmLweCiphertextOwned<Scalar> = CmLweCiphertext<Vec<Scalar>>;

pub type CmLweCiphertextView<'data, Scalar> = CmLweCiphertext<&'data [Scalar]>;

pub type CmLweCiphertextMutView<'data, Scalar> = CmLweCiphertext<&'data mut [Scalar]>;

#[derive(Copy, Clone)]
pub struct CmLweCiphertextParameters<T: UnsignedInteger> {
    pub lwe_dim: LweDimension,
    pub ct_modulus: CiphertextModulus<T>,
}

impl<Scalar: UnsignedInteger> CmLweCiphertextOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; lwe_dimension.0 + cm_dimension.0],
            lwe_dimension,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmLweCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for CmLweCiphertext<C> {
    type Metadata = CmLweCiphertextCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweCiphertextCreationMetadata {
            lwe_dimension,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, lwe_dimension, ciphertext_modulus)
    }
}
