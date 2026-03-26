//! Module containing the definition of the CmGlweCiphertext.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::prelude::*;

pub fn cm_glwe_ciphertext_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0
}

pub fn cm_glwe_ciphertext_mask_size(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    glwe_dimension
        .to_equivalent_lwe_dimension(polynomial_size)
        .0
}

pub fn cm_glwe_ciphertext_encryption_mask_sample_count(
    glwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionMaskSampleCount {
    EncryptionMaskSampleCount(cm_glwe_ciphertext_mask_size(
        glwe_dimension,
        polynomial_size,
    ))
}

pub fn cm_glwe_ciphertext_encryption_noise_sample_count(
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionNoiseSampleCount {
    EncryptionNoiseSampleCount(cm_dimension.0 * polynomial_size.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
// Versionize
// #[versionize(CmGlweCiphertextVersions)]
pub struct CmGlweCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmGlweCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmGlweCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGlweCiphertext<C> {
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert_eq!(
            container.container_len(),
            (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0
        );

        Self {
            data: container,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
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

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn get_mask_and_bodies(&self) -> (GlweMask<&[Scalar]>, GlweBodyList<&[Scalar]>) {
        let (mask, bodies) = self.data.as_ref().split_at(cm_glwe_ciphertext_mask_size(
            self.glwe_dimension(),
            self.polynomial_size,
        ));

        (
            GlweMask::from_container(mask, self.polynomial_size, self.ciphertext_modulus),
            GlweBodyList::from_container(bodies, self.polynomial_size, self.ciphertext_modulus),
        )
    }

    pub fn get_bodies(&self) -> GlweBodyList<&[Scalar]> {
        let bodies = &self.data.as_ref()
            [cm_glwe_ciphertext_mask_size(self.glwe_dimension(), self.polynomial_size)..];

        GlweBodyList::from_container(bodies, self.polynomial_size, self.ciphertext_modulus)
    }

    pub fn get_mask(&self) -> GlweMask<&[Scalar]> {
        GlweMask::from_container(
            &self.as_ref()
                [0..cm_glwe_ciphertext_mask_size(self.glwe_dimension(), self.polynomial_size)],
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_polynomial_list(&self) -> PolynomialList<&'_ [Scalar]> {
        PolynomialList::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn as_view(&self) -> CmGlweCiphertext<&'_ [Scalar]> {
        CmGlweCiphertext {
            data: self.data.as_ref(),
            glwe_dimension: self.glwe_dimension,
            polynomial_size: self.polynomial_size,
            cm_dimension: self.cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmGlweCiphertext<C> {
    pub fn get_mut_mask_and_bodies(
        &mut self,
    ) -> (GlweMask<&mut [Scalar]>, GlweBodyList<&mut [Scalar]>) {
        let glwe_dimension = self.glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let (mask, bodies) = self
            .data
            .as_mut()
            .split_at_mut(cm_glwe_ciphertext_mask_size(
                glwe_dimension,
                polynomial_size,
            ));

        (
            GlweMask::from_container(mask, polynomial_size, ciphertext_modulus),
            GlweBodyList::from_container(bodies, polynomial_size, ciphertext_modulus),
        )
    }

    pub fn get_mut_bodies(&mut self) -> GlweBodyList<&mut [Scalar]> {
        let glwe_dimension = self.glwe_dimension();
        let polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();

        let bodies = &mut self.data.as_mut()
            [cm_glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)..];

        GlweBodyList::from_container(bodies, polynomial_size, ciphertext_modulus)
    }

    pub fn get_mut_mask(&mut self) -> GlweMask<&mut [Scalar]> {
        let polynomial_size = self.polynomial_size();
        let glwe_dimension = self.glwe_dimension();
        let ciphertext_modulus = self.ciphertext_modulus();

        GlweMask::from_container(
            &mut self.as_mut()[0..cm_glwe_ciphertext_mask_size(glwe_dimension, polynomial_size)],
            polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_polynomial_list(&mut self) -> PolynomialList<&'_ mut [Scalar]> {
        let polynomial_size = self.polynomial_size;
        PolynomialList::from_container(self.as_mut(), polynomial_size)
    }

    pub fn as_mut_view(&mut self) -> CmGlweCiphertext<&'_ mut [Scalar]> {
        CmGlweCiphertext {
            data: self.data.as_mut(),
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

pub type CmGlweCiphertextOwned<Scalar> = CmGlweCiphertext<Vec<Scalar>>;

pub type CmGlweCiphertextView<'data, Scalar> = CmGlweCiphertext<&'data [Scalar]>;

pub type CmGlweCiphertextMutView<'data, Scalar> = CmGlweCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGlweCiphertextOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size)],
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmGlweCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGlweCiphertext<C>
{
    type Metadata = CmGlweCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGlweCiphertextCreationMetadata {
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
