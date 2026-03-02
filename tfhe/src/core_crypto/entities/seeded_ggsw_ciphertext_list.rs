//! Module containing the definition of the SeededGgswCiphertextList.

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_ggsw_ciphertext_list::SeededGgswCiphertextListVersions;
use crate::core_crypto::commons::generators::{
    EncryptionRandomGeneratorForkConfig, MaskRandomGeneratorForkConfig,
};
use crate::core_crypto::commons::math::random::{
    CompressionSeed, DefaultRandomGenerator, Distribution, RandomGenerable,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::LweBootstrapKeyConformanceParams;
use tfhe_versionable::Versionize;

/// A contiguous list containing
/// [`seeded GGSW ciphertexts`](`crate::core_crypto::entities::SeededGgswCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededGgswCiphertextListVersions)]
pub struct SeededGgswCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededGgswCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGgswCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededGgswCiphertextList<C> {
    /// Create a [`SeededGgswCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data in
    /// the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_seeded_ggsw_ciphertext`]
    /// or its parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_seeded_ggsw_ciphertext`] on the
    /// individual ciphertexts in the list.
    ///
    /// This docstring exhibits [`SeededGgswCiphertextList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGgswCiphertextList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_count = GgswCiphertextCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededGgswCiphertextList
    /// let ggsw_list = SeededGgswCiphertextList::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_count,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let compression_seed = ggsw_list.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let ggsw_list = SeededGgswCiphertextList::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Decompress the list
    /// let ggsw_list = ggsw_list.decompress_into_ggsw_ciphertext_list();
    ///
    /// assert_eq!(ggsw_list.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_list.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw_list.ggsw_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ggsw_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container
                .container_len()
                .is_multiple_of(decomp_level_count.0 * glwe_size.0 * polynomial_size.0),
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * glwe_size * polynomial_size: \
        {}.Got container length: {} and decomp_level_count: {decomp_level_count:?},  \
        glwe_size: {glwe_size:?}, polynomial_size: {polynomial_size:?}",
            decomp_level_count.0 * glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`SeededGgswCiphertext`] stored in the list.
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`SeededGgswCiphertext`] in the list.
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`DecompositionBaseLog`] of the [`SeededGgswCiphertext`] in the list.
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededGgswCiphertext`] in the list.
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`CompressionSeed`] of the [`SeededGgswCiphertextList`].
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the [`CiphertextModulus`] of the [`SeededGgswCiphertextList`].
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return the [`GgswCiphertextCount`] of the [`SeededGgswCiphertextList`].
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn ggsw_ciphertext_count(&self) -> GgswCiphertextCount {
        GgswCiphertextCount(
            self.data.container_len()
                / seeded_ggsw_ciphertext_size(
                    self.glwe_size,
                    self.polynomial_size,
                    self.decomp_level_count,
                ),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededGgswCiphertextList`] and decompress it into a standard
    /// [`GgswCiphertextList`].
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    pub fn decompress_into_ggsw_ciphertext_list(self) -> GgswCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_list = GgswCiphertextListOwned::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ggsw_ciphertext_count(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_ggsw_ciphertext_list::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }

    /// Parallel variant of
    /// [`decompress_into_ggsw_ciphertext_list`](`Self::decompress_into_ggsw_ciphertext_list`).
    pub fn par_decompress_into_ggsw_ciphertext_list(self) -> GgswCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedTorus + Send + Sync,
    {
        let mut decompressed_list = GgswCiphertextListOwned::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ggsw_ciphertext_count(),
            self.ciphertext_modulus(),
        );
        par_decompress_seeded_ggsw_ciphertext_list::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
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
        ggsw_ciphertext_list_encryption_fork_config(
            self.ggsw_ciphertext_count(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_level_count(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }

    pub fn decompression_fork_config<MaskDistribution>(
        &self,
        mask_distribution: MaskDistribution,
    ) -> MaskRandomGeneratorForkConfig
    where
        MaskDistribution: Distribution,
        Scalar: RandomGenerable<MaskDistribution, CustomModulus = Scalar>,
    {
        let ggsw_count = self.ggsw_ciphertext_count().0;
        let ggsw_mask_sample_count = ggsw_ciphertext_encryption_mask_sample_count(
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_level_count(),
        );

        let ciphertext_modulus = self.ciphertext_modulus();
        let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

        MaskRandomGeneratorForkConfig::new(
            ggsw_count,
            ggsw_mask_sample_count,
            mask_distribution,
            modulus,
        )
    }
}

/// A [`SeededGgswCiphertextList`] owning the memory for its own storage.
pub type SeededGgswCiphertextListOwned<Scalar> = SeededGgswCiphertextList<Vec<Scalar>>;
/// A [`SeededGgswCiphertextList`] immutably borrowing memory for its own storage.
pub type SeededGgswCiphertextListView<'data, Scalar> = SeededGgswCiphertextList<&'data [Scalar]>;
/// A [`SeededGgswCiphertextList`] mutably borrowing memory for its own storage.
pub type SeededGgswCiphertextListMutView<'data, Scalar> =
    SeededGgswCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> SeededGgswCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededGgswCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data in the list you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_seeded_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_seeded_ggsw_ciphertext`]
    /// on the individual ciphertexts in the list.
    ///
    /// See [`SeededGgswCiphertextList::from_container`] for usage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_count: GgswCiphertextCount,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                ciphertext_count.0
                    * seeded_ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGgswCiphertextList`]
/// entities.
#[derive(Clone)]
pub struct SeededGgswCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub compression_seed: CompressionSeed,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for SeededGgswCiphertextList<C>
{
    type Metadata = SeededGgswCiphertextListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let SeededGgswCiphertextListCreationMetadata {
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for SeededGgswCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = SeededGgswCiphertextCreationMetadata<Self::Element>;

    type EntityView<'this>
        = SeededGgswCiphertextView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = SeededGgswCiphertextListCreationMetadata<Self::Element>;

    type SelfView<'this>
        = SeededGgswCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        SeededGgswCiphertextCreationMetadata {
            glwe_size: self.glwe_size,
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            compression_seed: self.compression_seed.clone(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        seeded_ggsw_ciphertext_size(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_level_count,
        )
    }

    /// Unimplemented for [`SeededGgswCiphertextList`]. At the moment it does not make sense to
    /// return "sub" seeded lists.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        SeededGgswCiphertextListCreationMetadata {
            glwe_size: self.glwe_size,
            polynomial_size: self.polynomial_size,
            decomp_base_log: self.decomp_base_log,
            decomp_level_count: self.decomp_level_count,
            compression_seed: self.compression_seed.clone(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for SeededGgswCiphertextList<C>
{
    type EntityMutView<'this>
        = SeededGgswCiphertextMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = SeededGgswCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;
}

pub struct GgswCiphertextListConformanceParams<Scalar: UnsignedInteger> {
    pub len: usize,
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger> TryFrom<&MultiBitBootstrapKeyConformanceParams<Scalar>>
    for GgswCiphertextListConformanceParams<Scalar>
{
    type Error = ();

    fn try_from(value: &MultiBitBootstrapKeyConformanceParams<Scalar>) -> Result<Self, ()> {
        if !value
            .input_lwe_dimension
            .0
            .is_multiple_of(value.grouping_factor.0)
        {
            return Err(());
        }

        let group_count = value.input_lwe_dimension.0 / value.grouping_factor.0;

        Ok(Self {
            len: group_count * value.grouping_factor.ggsw_per_multi_bit_element().0,
            glwe_size: value.output_glwe_size,
            polynomial_size: value.polynomial_size,
            decomp_base_log: value.decomp_base_log,
            decomp_level_count: value.decomp_level_count,
            ciphertext_modulus: value.ciphertext_modulus,
        })
    }
}

impl<Scalar: UnsignedInteger> From<&LweBootstrapKeyConformanceParams<Scalar>>
    for GgswCiphertextListConformanceParams<Scalar>
{
    fn from(value: &LweBootstrapKeyConformanceParams<Scalar>) -> Self {
        Self {
            len: value.input_lwe_dimension.0,
            glwe_size: value.output_glwe_size,
            polynomial_size: value.polynomial_size,
            decomp_base_log: value.decomp_base_log,
            decomp_level_count: value.decomp_level_count,
            ciphertext_modulus: value.ciphertext_modulus,
        }
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ParameterSetConformant
    for SeededGgswCiphertextList<C>
{
    type ParameterSet = GgswCiphertextListConformanceParams<Scalar>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            compression_seed: _,
            ciphertext_modulus,
        } = self;

        data.container_len()
            == parameter_set.len
                * seeded_ggsw_ciphertext_size(*glwe_size, *polynomial_size, *decomp_level_count)
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *glwe_size == parameter_set.glwe_size
            && *polynomial_size == parameter_set.polynomial_size
            && *ciphertext_modulus == parameter_set.ciphertext_modulus
    }
}
