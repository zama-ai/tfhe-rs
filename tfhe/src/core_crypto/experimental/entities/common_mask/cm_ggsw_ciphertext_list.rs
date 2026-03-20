//! Module containing the definition of the GgswCiphertextList.

use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::prelude::*;
use cm_ggsw_ciphertext::{
    cm_ggsw_ciphertext_encryption_mask_sample_count,
    cm_ggsw_ciphertext_encryption_noise_sample_count, cm_ggsw_ciphertext_size,
    CmGgswCiphertextCreationMetadata, CmGgswCiphertextMutView, CmGgswCiphertextView,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
// Versionize
// #[versionize(GgswCiphertextListVersions)]
pub struct CmGgswCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmGgswCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmGgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

pub fn cm_ggsw_ciphertext_list_size(
    ciphertext_count: GgswCiphertextCount,
    glwe_dimension: GlweDimension,
    cm_dimension: CmDimension,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    ciphertext_count.0
        * cm_ggsw_ciphertext_size(
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_level_count,
        )
}

#[allow(clippy::too_many_arguments)]
pub fn cm_ggsw_ciphertext_list_encryption_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
    ggsw_ciphertext_count: GgswCiphertextCount,
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
    let ggsw_mask_sample_count = cm_ggsw_ciphertext_encryption_mask_sample_count(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        decomposition_level_count,
    );
    let ggsw_noise_sample_count = cm_ggsw_ciphertext_encryption_noise_sample_count(
        glwe_dimension,
        cm_dimension,
        polynomial_size,
        decomposition_level_count,
    );

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        ggsw_ciphertext_count.0,
        ggsw_mask_sample_count,
        mask_distribution,
        ggsw_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmGgswCiphertextList<C> {
    pub fn from_container(
        container: C,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len().is_multiple_of(decomp_level_count.0
                    * (glwe_dimension.0 + cm_dimension.0)
                    * (glwe_dimension.0 + cm_dimension.0) * polynomial_size.0),
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * glwe_dimension * glwe_dimension * polynomial_size: \
        {}.Got container length: {} and decomp_level_count: {decomp_level_count:?},  \
        glwe_dimension: {glwe_dimension:?}, cm_dimension: {cm_dimension:?} polynomial_size: {polynomial_size:?}",
            decomp_level_count.0
                * (glwe_dimension.0 + cm_dimension.0)
                * (glwe_dimension.0 + cm_dimension.0)
                * polynomial_size.0,
            container.container_len()
        );

        Self {
            data: container,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
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

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    pub fn cm_ggsw_ciphertext_count(&self) -> GgswCiphertextCount {
        GgswCiphertextCount(
            self.data.container_len()
                / cm_ggsw_ciphertext_size(
                    self.glwe_dimension,
                    self.cm_dimension,
                    self.polynomial_size,
                    self.decomp_level_count,
                ),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialList::from_container(self.as_ref(), self.polynomial_size())
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
        cm_ggsw_ciphertext_list_encryption_fork_config(
            self.cm_ggsw_ciphertext_count(),
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

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmGgswCiphertextList<C> {
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size();
        PolynomialList::from_container(self.as_mut(), polynomial_size)
    }
}

pub type CmGgswCiphertextListOwned<Scalar> = CmGgswCiphertextList<Vec<Scalar>>;

pub type CmGgswCiphertextListView<'data, Scalar> = CmGgswCiphertextList<&'data [Scalar]>;

pub type CmGgswCiphertextListMutView<'data, Scalar> = CmGgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGgswCiphertextListOwned<Scalar> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        glwe_dimension: GlweDimension,
        cm_dimension: CmDimension,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: GgswCiphertextCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                cm_ggsw_ciphertext_list_size(
                    ciphertext_count,
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
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmGgswCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_dimension: GlweDimension,
    pub cm_dimension: CmDimension,
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmGgswCiphertextList<C>
{
    type Metadata = CmGgswCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmGgswCiphertextListCreationMetadata {
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_dimension,
            cm_dimension,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmGgswCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmGgswCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmGgswCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmGgswCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmGgswCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmGgswCiphertextCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        cm_ggsw_ciphertext_size(
            self.glwe_dimension,
            self.cm_dimension,
            self.polynomial_size,
            self.decomp_level_count,
        )
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmGgswCiphertextListCreationMetadata {
            glwe_dimension: self.glwe_dimension,
            cm_dimension: self.cm_dimension,
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmGgswCiphertextList<C>
{
    type EntityMutView<'this>
        = CmGgswCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmGgswCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}
