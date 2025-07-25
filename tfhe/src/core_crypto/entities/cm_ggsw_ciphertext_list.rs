//! Module containing the definition of the GgswCiphertextList.

use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use cm_ggsw_ciphertext::{
    cm_ggsw_ciphertext_encryption_mask_sample_count,
    cm_ggsw_ciphertext_encryption_noise_sample_count, cm_ggsw_ciphertext_size,
    CmGgswCiphertextCreationMetadata, CmGgswCiphertextMutView, CmGgswCiphertextView,
};

/// A contiguous list containing
/// [`GGSW ciphertexts`](`crate::core_crypto::entities::GgswCiphertext`).
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
    /// Create a [`GgswCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data in
    /// the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its
    /// parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] on the
    /// individual ciphertexts in the list.
    ///
    /// This docstring exhibits [`GgswCiphertextList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GgswCiphertextList creation
    /// let glwe_dimension = GlweDimension(2);
    /// let cm_dimension = CmDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_count = GgswCiphertextCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GgswCiphertextList
    /// let ggsw_list = CmGgswCiphertextList::new(
    ///     0u64,
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.cm_ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let ggsw_list = CmGgswCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_dimension,
    ///     cm_dimension,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.cm_ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
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
            container.container_len()
                % (decomp_level_count.0
                    * (glwe_dimension.0 + cm_dimension.0)
                    * (glwe_dimension.0 + cm_dimension.0)
                    * polynomial_size.0)
                == 0,
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

    /// Return the [`CiphertextModulus`] of the [`GgswCiphertextList`].
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
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

/// A [`GgswCiphertextList`] owning the memory for its own storage.
pub type CmGgswCiphertextListOwned<Scalar> = CmGgswCiphertextList<Vec<Scalar>>;
/// A [`GgswCiphertextList`] immutably borrowing memory for its own storage.
pub type CmGgswCiphertextListView<'data, Scalar> = CmGgswCiphertextList<&'data [Scalar]>;
/// A [`GgswCiphertextList`] mutably borrowing memory for its own storage.
pub type CmGgswCiphertextListMutView<'data, Scalar> = CmGgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmGgswCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`GgswCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data in the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] on
    /// the individual ciphertexts in the list.
    ///
    /// See [`GgswCiphertextList::from_container`] for usage.
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

/// Metadata used in the [`CreateFrom`] implementation to create [`GgswCiphertextList`] entities.
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
