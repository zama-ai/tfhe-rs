//! Module containing the definition of the CmGgswCiphertext.

use super::cm_glwe_ciphertext::cm_glwe_ciphertext_encryption_mask_sample_count;
use super::cm_glwe_ciphertext_list::{CmGlweCiphertextListMutView, CmGlweCiphertextListView};
use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::prelude::{
    glwe_ciphertext_encryption_mask_sample_count, glwe_ciphertext_encryption_noise_sample_count,
    PolynomialListMutView, PolynomialListView,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmGgswCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmGgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmGgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn cm_ggsw_ciphertext_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0 * cm_ggsw_level_matrix_size(glwe_dimension, cm_dimension, polynomial_size)
}

pub fn cm_ggsw_level_matrix_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> usize {
    (glwe_dimension.0 + cm_dimension.0)
        * cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size)
}

pub fn fourier_cm_ggsw_ciphertext_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    fourier_polynomial_size: FourierPolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0
        * fourier_cm_ggsw_level_matrix_size(glwe_dimension, cm_dimension, fourier_polynomial_size)
}

pub fn fourier_cm_ggsw_level_matrix_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    fourier_polynomial_size: FourierPolynomialSize,
) -> usize {
    (glwe_dimension.0 + cm_dimension.0)
        * cm_glwe_ciphertext_fourier_size(glwe_dimension, cm_dimension, fourier_polynomial_size)
}

pub fn cm_ggsw_ciphertext_encryption_mask_sample_count(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> EncryptionMaskSampleCount {
    decomp_level_count.0
        * cm_ggsw_level_matrix_encryption_mask_sample_count(
            glwe_dimension,
            cm_dimension,
            polynomial_size,
        )
}

pub fn cm_ggsw_level_matrix_encryption_mask_sample_count(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionMaskSampleCount {
    (glwe_dimension.0 + cm_dimension.0)
        * cm_glwe_ciphertext_encryption_mask_sample_count(glwe_dimension, polynomial_size)
}

pub fn cm_ggsw_ciphertext_encryption_noise_sample_count(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> EncryptionNoiseSampleCount {
    decomp_level_count.0
        * cm_ggsw_level_matrix_encryption_noise_sample_count(
            glwe_dimension,
            cm_dimension,
            polynomial_size,
        )
}

pub fn cm_ggsw_level_matrix_encryption_noise_sample_count(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
) -> EncryptionNoiseSampleCount {
    (glwe_dimension.0 + cm_dimension.0)
        * glwe_ciphertext_encryption_noise_sample_count(polynomial_size)
}

pub fn cm_ggsw_ciphertext_encryption_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomposition_level_count: DecompositionLevelCount,
    mask_distribution: MaskDistribution,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> EncryptionRandomGeneratorForkConfig
where
    Scalar: UnsignedInteger
        + RandomGenerable<MaskDistribution, CustomModulus = Scalar>
        + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
{
    let ggsw_level_matrix_mask_sample_count = cm_ggsw_level_matrix_encryption_mask_sample_count(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
    );
    let ggsw_level_matrix_noise_sample_count = cm_ggsw_level_matrix_encryption_noise_sample_count(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
    );

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        decomposition_level_count.0,
        ggsw_level_matrix_mask_sample_count,
        mask_distribution,
        ggsw_level_matrix_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

pub fn cm_ggsw_level_matrix_encryption_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    mask_distribution: MaskDistribution,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> EncryptionRandomGeneratorForkConfig
where
    Scalar: UnsignedInteger
        + RandomGenerable<MaskDistribution, CustomModulus = Scalar>
        + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
{
    let glwe_ciphertext_mask_sample_count =
        glwe_ciphertext_encryption_mask_sample_count(glwe_dimension, polynomial_size);
    let glwe_ciphertext_noise_sample_count =
        glwe_ciphertext_encryption_noise_sample_count(polynomial_size);

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        glwe_dimension.0 + cm_dimension.0,
        glwe_ciphertext_mask_sample_count,
        mask_distribution,
        glwe_ciphertext_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGgswCiphertext<C> {
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a CmGgswCiphertext"
        );

        let matrix_size = (glwe_dimension.0 + cm_dimension.0)
            * cm_glwe_ciphertext_size(glwe_dimension, cm_dimension, polynomial_size);

        assert!(
            container.container_len().is_multiple_of(matrix_size),
            "The provided container length is not valid. \
            It needs to be dividable by glwe_dimension * glwe_dimension * polynomial_size: {}. \
            Got container length: {} and glwe_dimension: {glwe_dimension:?}, \
            cm_dimension: {cm_dimension:?}, polynomial_size: {polynomial_size:?}.",
            matrix_size,
            container.container_len()
        );

        Self {
            data: container,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.container_len() / self.ggsw_level_matrix_size())
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn ggsw_level_matrix_size(&self) -> usize {
        // GlweDimension GlweCiphertext(glwe_dimension,cm_dimension,polynomial_size) per level
        cm_ggsw_level_matrix_size(self.glwe_dimension, self.cm_dimension, self.polynomial_size)
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn as_cm_glwe_list(&self) -> CmGlweCiphertextListView<'_, Scalar> {
        CmGlweCiphertextListView::from_container(
            self.as_ref(),
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn as_view(&self) -> CmGgswCiphertextView<'_, Scalar> {
        CmGgswCiphertextView::from_container(
            self.as_ref(),
            self.glwe_dimension(),
            self.cm_dimension,
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.ciphertext_modulus(),
        )
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn encryption_fork_config<MaskDistribution, NoiseDistribution>(
        &self,
        mask_distribution: MaskDistribution,
        noise_distribution: NoiseDistribution,
    ) -> EncryptionRandomGeneratorForkConfig
    where
        MaskDistribution: Distribution,
        NoiseDistribution: Distribution,
        Scalar: RandomGenerable<MaskDistribution, CustomModulus = Scalar>
            + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {
        cm_ggsw_ciphertext_encryption_fork_config(
            self.glwe_dimension(),
            self.cm_dimension,
            self.polynomial_size(),
            self.decomposition_level_count(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmGgswCiphertext<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }

    pub fn as_mut_cm_glwe_list(&mut self) -> CmGlweCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let glwe_dimension = self.glwe_dimension;
        let cm_dimension = self.cm_dimension;
        let ciphertext_modulus: CiphertextModulus<Scalar> = self.ciphertext_modulus;
        CmGlweCiphertextListMutView::from_container(
            self.as_mut(),
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_view(&mut self) -> CmGgswCiphertextMutView<'_, Scalar> {
        let glwe_dimension = self.glwe_dimension;
        let cm_dimension = self.cm_dimension;
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let ciphertext_modulus = self.ciphertext_modulus;
        CmGgswCiphertextMutView::from_container(
            self.as_mut(),
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

pub type CmGgswCiphertextOwned<Scalar> = CmGgswCiphertext<Vec<Scalar>>;

pub type CmGgswCiphertextView<'data, Scalar> = CmGgswCiphertext<&'data [Scalar]>;

pub type CmGgswCiphertextMutView<'data, Scalar> = CmGgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGgswCiphertextOwned<Scalar> {
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                cm_ggsw_ciphertext_size(
                    glwe_dimension,
                    cm_dimension,
                    polynomial_size,
                    decomp_level_count
                )
            ],
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmGgswCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGgswCiphertext<C>
{
    type Metadata = CmGgswCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGgswCiphertextCreationMetadata {
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

pub struct CmGgswLevelMatrix<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGgswLevelMatrix<C> {
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len()
                == cm_ggsw_level_matrix_size(glwe_dimension, cm_dimension, polynomial_size),
            "The provided container length is not valid. \
            Expected length of {} (glwe_dimension * glwe_dimension * polynomial_size), got {}",
            cm_ggsw_level_matrix_size(glwe_dimension, cm_dimension, polynomial_size),
            container.container_len(),
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

    pub fn as_cm_glwe_list(&self) -> CmGlweCiphertextListView<'_, C::Element> {
        CmGlweCiphertextListView::from_container(
            self.data.as_ref(),
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    pub fn encryption_fork_config<MaskDistribution, NoiseDistribution>(
        &self,
        mask_distribution: MaskDistribution,
        noise_distribution: NoiseDistribution,
    ) -> EncryptionRandomGeneratorForkConfig
    where
        MaskDistribution: Distribution,
        NoiseDistribution: Distribution,
        Scalar: RandomGenerable<MaskDistribution, CustomModulus = Scalar>
            + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {
        cm_ggsw_level_matrix_encryption_fork_config(
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmGgswLevelMatrix<C> {
    pub fn as_mut_cm_glwe_list(&mut self) -> CmGlweCiphertextListMutView<'_, C::Element> {
        CmGlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

pub fn cm_fourier_ggsw_level_matrix_size(
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    fourier_polynomial_size: FourierPolynomialSize,
) -> usize {
    (glwe_dimension.0 + cm_dimension.0)
        * cm_glwe_ciphertext_fourier_size(glwe_dimension, cm_dimension, fourier_polynomial_size)
}

#[derive(Clone, Copy)]
pub struct CmGgswLevelMatrixCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGgswLevelMatrix<C>
{
    type Metadata = CmGgswLevelMatrixCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGgswLevelMatrixCreationMetadata {
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
    for CmGgswCiphertext<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmGgswLevelMatrixCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmGgswLevelMatrix<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this>
        = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmGgswLevelMatrixCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.ggsw_level_matrix_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for CmGgswCiphertext. \
        At the moment it does not make sense to return 'sub' CmGgswCiphertext."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmGgswCiphertext<C>
{
    type EntityMutView<'this>
        = CmGgswLevelMatrix<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this>
        = DummyCreateFrom
    where
        Self: 'this;
}
