//! Module containing the definition of the [`SeededLweCiphertextList`].

use tfhe_versionable::Versionize;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_lwe_ciphertext_list::SeededLweCiphertextListVersions;
use crate::core_crypto::commons::generators::{
    EncryptionRandomGeneratorForkConfig, MaskRandomGeneratorForkConfig,
};
use crate::core_crypto::commons::math::random::{
    CompressionSeed, DefaultRandomGenerator, Distribution, RandomGenerable,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A seeded list containing
/// [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLweCiphertextListVersions)]
pub struct SeededLweCiphertextList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    lwe_size: LweSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededLweCiphertextList<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for SeededLweCiphertextList<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededLweCiphertextList<C> {
    /// Create a [`SeededLweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext_list`] or
    /// [`crate::core_crypto::algorithms::par_encrypt_seeded_lwe_ciphertext_list`] using
    /// this list as output.
    ///
    /// This docstring exhibits [`SeededLweCiphertextList`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweCiphertextList creation
    /// let lwe_dimension = LweDimension(742);
    /// let lwe_ciphertext_count = LweCiphertextCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweCiphertextList
    /// let seeded_lwe_list = SeededLweCiphertextList::new(
    ///     0u64,
    ///     lwe_dimension.to_lwe_size(),
    ///     lwe_ciphertext_count,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(seeded_lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(seeded_lwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let compression_seed = seeded_lwe_list.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = seeded_lwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let seeded_lwe_list = SeededLweCiphertextList::from_container(
    ///     underlying_container,
    ///     lwe_dimension.to_lwe_size(),
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(seeded_lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(seeded_lwe_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Decompress the list
    /// let lwe_list = seeded_lwe_list.decompress_into_lwe_ciphertext_list();
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        Self {
            data: container,
            lwe_size,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`LweSize`] of the compressed [`LweCiphertext`] stored in the list.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`CompressionSeed`] of the [`SeededLweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the [`LweCiphertextCount`] of the [`SeededLweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.data.container_len())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededLweCiphertextList`] and decompress it into a standard
    /// [`LweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn decompress_into_lwe_ciphertext_list(self) -> LweCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_list = LweCiphertextList::new(
            Scalar::ZERO,
            self.lwe_size(),
            self.lwe_ciphertext_count(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_lwe_ciphertext_list::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }

    /// Parallel variant of
    /// [`decompress_into_lwe_ciphertext_list`](`Self::decompress_into_lwe_ciphertext_list`)
    pub fn par_decompress_into_lwe_ciphertext_list(self) -> LweCiphertextListOwned<Scalar>
    where
        Scalar: UnsignedTorus + Send + Sync,
    {
        let mut decompressed_list = LweCiphertextList::new(
            Scalar::ZERO,
            self.lwe_size(),
            self.lwe_ciphertext_count(),
            self.ciphertext_modulus(),
        );
        par_decompress_seeded_lwe_ciphertext_list::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }

    /// Return a view of the [`SeededLweCiphertextList`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> SeededLweCiphertextList<&'_ [Scalar]> {
        SeededLweCiphertextList::from_container(
            self.as_ref(),
            self.lwe_size(),
            self.compression_seed(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
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
        lwe_ciphertext_list_encryption_fork_config(
            self.lwe_ciphertext_count(),
            self.lwe_size().to_lwe_dimension(),
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
        let lwe_count = self.lwe_ciphertext_count().0;
        let lwe_mask_sample_count =
            lwe_ciphertext_encryption_mask_sample_count(self.lwe_size().to_lwe_dimension());

        let ciphertext_modulus = self.ciphertext_modulus();
        let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

        MaskRandomGeneratorForkConfig::new(
            lwe_count,
            lwe_mask_sample_count,
            mask_distribution,
            modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededLweCiphertextList<C> {
    /// Mutable variant of [`SeededLweCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLweCiphertextList<&'_ mut [Scalar]> {
        let lwe_size = self.lwe_size();
        let compression_seed = self.compression_seed();
        let ciphertext_modulus = self.ciphertext_modulus();
        SeededLweCiphertextList::from_container(
            self.as_mut(),
            lwe_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// A [`SeededLweCiphertextList`] owning the memory for its own storage.
pub type SeededLweCiphertextListOwned<Scalar> = SeededLweCiphertextList<Vec<Scalar>>;
/// A [`SeededLweCiphertextList`] immutably borrowing memory for its own storage.
pub type SeededLweCiphertextListView<'data, Scalar> = SeededLweCiphertextList<&'data [Scalar]>;
/// A [`SeededLweCiphertextList`] mutably borrowing memory for its own storage.
pub type SeededLweCiphertextListMutView<'data, Scalar> =
    SeededLweCiphertextList<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> SeededLweCiphertextListOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededLweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext_list`] or
    /// [`crate::core_crypto::algorithms::par_encrypt_seeded_lwe_ciphertext_list`]  using this list
    /// as output.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; ciphertext_count.0],
            lwe_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededLweCiphertextList`]
/// entities.
#[derive(Clone)]
pub struct SeededLweCiphertextListCreationMetadata<Scalar: UnsignedInteger> {
    pub lwe_size: LweSize,
    pub compression_seed: CompressionSeed,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for SeededLweCiphertextList<C>
{
    type Metadata = SeededLweCiphertextListCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let SeededLweCiphertextListCreationMetadata {
            lwe_size,
            compression_seed,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, lwe_size, compression_seed, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for SeededLweCiphertextList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LweBodyCreationMetadata<Self::Element>;

    type EntityView<'this>
        = LweBodyRef<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this>
        = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LweBodyCreationMetadata {
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        1
    }

    /// Unimplemented for [`SeededLweCiphertextList`]. At the moment it does not make sense to
    /// return "sub" seeded lists.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededLweCiphertextList. \
        At the moment it does not make sense to return 'sub' seeded lists."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for SeededLweCiphertextList<C>
{
    type EntityMutView<'this>
        = LweBodyRefMut<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = DummyCreateFrom
    where
        Self: 'this;
}
