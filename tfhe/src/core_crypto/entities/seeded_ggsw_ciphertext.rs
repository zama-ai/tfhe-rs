//! Module containing the definition of the SeededGgswCiphertext.

use tfhe_versionable::Versionize;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_ggsw_ciphertext::SeededGgswCiphertextVersions;
use crate::core_crypto::commons::generators::{
    EncryptionRandomGeneratorForkConfig, MaskRandomGeneratorForkConfig,
};
use crate::core_crypto::commons::math::random::{
    CompressionSeed, DefaultRandomGenerator, Distribution, RandomGenerable,
};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded GGSW Ciphertext`](`SeededGgswCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededGgswCiphertextVersions)]
pub struct SeededGgswCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededGgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in a [`SeededGgswCiphertext`] given a [`GlweSize`],
/// [`PolynomialSize`] and [`DecompositionLevelCount`].
pub fn seeded_ggsw_ciphertext_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0 * seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)
}

/// Return the number of elements in a [`SeededGgswLevelMatrix`] given a [`GlweSize`] and
/// [`PolynomialSize`].
pub fn seeded_ggsw_level_matrix_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    glwe_size.0 * polynomial_size.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededGgswCiphertext<C> {
    /// Create a [`SeededGgswCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its
    /// parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] using
    /// this ciphertext as output.
    ///
    /// This docstring exhibits [`SeededGgswCiphertext`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGgswCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededGgswCiphertext
    /// let ggsw = SeededGgswCiphertext::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.seeded_ggsw_level_matrix_size(),
    ///     seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    ///
    /// let compression_seed = ggsw.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let ggsw = SeededGgswCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.seeded_ggsw_level_matrix_size(),
    ///     seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    ///
    /// let ggsw = ggsw.decompress_into_ggsw_ciphertext();
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.ggsw_level_matrix_size(),
    ///     ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container.container_len() > 0,
            "Got an empty container to create a SeededGgswCiphertext"
        );
        assert!(
            container
                .container_len()
                .is_multiple_of(glwe_size.0 * polynomial_size.0),
            "The provided container length is not valid. \
        It needs to be dividable by glwe_size * polynomial_size: {}. \
        Got container length: {} and glwe_size: {glwe_size:?}, \
        polynomial_size: {polynomial_size:?}.",
            glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`PolynomialSize`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweSize`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`DecompositionBaseLog`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.container_len() / self.seeded_ggsw_level_matrix_size())
    }

    /// Return the [`CompressionSeed`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the [`CiphertextModulus`] of the [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return the size in number of elements of a single [`SeededGgswLevelMatrix`] of the current
    /// [`SeededGgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn seeded_ggsw_level_matrix_size(&self) -> usize {
        // GlweSize SeededGlweCiphertext(glwe_size, polynomial_size) per level
        seeded_ggsw_level_matrix_size(self.glwe_size, self.polynomial_size)
    }

    /// Interpret the [`SeededGgswCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Interpret the [`SeededGgswCiphertext`] as a [`SeededGlweCiphertextList`].
    pub fn as_seeded_glwe_list(&self) -> SeededGlweCiphertextListView<'_, Scalar> {
        SeededGlweCiphertextListView::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.compression_seed(),
            self.ciphertext_modulus(),
        )
    }

    /// Return a view of the [`SeededGgswCiphertext`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> SeededGgswCiphertextView<'_, Scalar> {
        SeededGgswCiphertextView::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.compression_seed(),
            self.ciphertext_modulus(),
        )
    }

    /// Consume the [`SeededGgswCiphertext`] and decompress it into a standard
    /// [`GgswCiphertext`].
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn decompress_into_ggsw_ciphertext(self) -> GgswCiphertextOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_ct = GgswCiphertextOwned::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_ggsw_ciphertext::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_ct,
            &self,
        );
        decompressed_ct
    }

    /// Parllel variant of
    /// [`decompress_into_ggsw_ciphertext`](`Self::decompress_into_ggsw_ciphertext`)
    pub fn par_decompress_into_ggsw_ciphertext(self) -> GgswCiphertextOwned<Scalar>
    where
        Scalar: UnsignedTorus + Send + Sync,
    {
        let mut decompressed_ct = GgswCiphertextOwned::new(
            Scalar::ZERO,
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ciphertext_modulus(),
        );
        par_decompress_seeded_ggsw_ciphertext::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_ct,
            &self,
        );
        decompressed_ct
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
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
        ggsw_ciphertext_encryption_fork_config(
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
        let decomposition_level_count = self.decomposition_level_count();
        let ggsw_level_matrix_mask_sample_count = ggsw_level_matrix_encryption_mask_sample_count(
            self.glwe_size(),
            self.polynomial_size(),
        );

        let ciphertext_modulus = self.ciphertext_modulus();
        let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

        MaskRandomGeneratorForkConfig::new(
            decomposition_level_count.0,
            ggsw_level_matrix_mask_sample_count,
            mask_distribution,
            modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededGgswCiphertext<C> {
    /// Mutable variant of [`SeededGgswCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`SeededGgswCiphertext::as_seeded_glwe_list`].
    pub fn as_mut_seeded_glwe_list(&mut self) -> SeededGlweCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size();
        let glwe_size = self.glwe_size();
        let compression_seed = self.compression_seed();
        let ciphertext_modulus = self.ciphertext_modulus();
        SeededGlweCiphertextListMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            compression_seed,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`SeededGgswCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> SeededGgswCiphertextMutView<'_, Scalar> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let compression_seed = self.compression_seed();
        let ciphertext_modulus = self.ciphertext_modulus();
        SeededGgswCiphertextMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// A [`SeededGgswCiphertext`] owning the memory for its own storage.
pub type SeededGgswCiphertextOwned<Scalar> = SeededGgswCiphertext<Vec<Scalar>>;
/// A [`SeededGgswCiphertext`] immutably borrowing memory for its own storage.
pub type SeededGgswCiphertextView<'data, Scalar> = SeededGgswCiphertext<&'data [Scalar]>;
/// A [`SeededGgswCiphertext`] immutably borrowing memory for its own storage.
pub type SeededGgswCiphertextMutView<'data, Scalar> = SeededGgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> SeededGgswCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededGgswCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`]
    /// using this ciphertext as output.
    ///
    /// See [`SeededGgswCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                seeded_ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGgswCiphertext`] entities.
#[derive(Clone)]
pub struct SeededGgswCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub compression_seed: CompressionSeed,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for SeededGgswCiphertext<C>
{
    type Metadata = SeededGgswCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let SeededGgswCiphertextCreationMetadata {
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// A convenience structure to more easily write iterators on a [`SeededGgswCiphertext`] levels.
pub struct SeededGgswLevelMatrix<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededGgswLevelMatrix<C> {
    /// Create a [`SeededGgswLevelMatrix`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`SeededGgswLevelMatrix`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededGgswLevelMatrix creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// let container = vec![0u64; seeded_ggsw_level_matrix_size(glwe_size, polynomial_size)];
    ///
    /// // Create a new SeededGgswLevelMatrix
    /// let ggsw_level_matrix = SeededGgswLevelMatrix::from_container(
    ///     container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw_level_matrix.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_level_matrix.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_level_matrix.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container.container_len() == seeded_ggsw_level_matrix_size(glwe_size, polynomial_size),
            "The provided container length is not valid. \
            Expected length of {} (glwe_size * polynomial_size), got {}",
            seeded_ggsw_level_matrix_size(glwe_size, polynomial_size),
            container.container_len(),
        );

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`SeededGgswLevelMatrix`].
    ///
    /// See [`SeededGgswLevelMatrix::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`SeededGgswLevelMatrix`].
    ///
    /// See [`SeededGgswLevelMatrix::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`SeededGgswLevelMatrix`].
    ///
    /// See [`SeededGgswLevelMatrix::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`SeededGgswLevelMatrix`] as a [`SeededGlweCiphertextList`].
    pub fn as_seeded_glwe_list(&self) -> SeededGlweCiphertextListView<'_, Scalar> {
        SeededGlweCiphertextListView::from_container(
            self.data.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.compression_seed.clone(),
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
        ggsw_level_matrix_encryption_fork_config(
            self.glwe_size(),
            self.polynomial_size(),
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
        let glwe_size = self.glwe_size();
        let glwe_ciphertext_mask_sample_count = glwe_ciphertext_encryption_mask_sample_count(
            glwe_size.to_glwe_dimension(),
            self.polynomial_size(),
        );

        let ciphertext_modulus = self.ciphertext_modulus();
        let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

        MaskRandomGeneratorForkConfig::new(
            glwe_size.0,
            glwe_ciphertext_mask_sample_count,
            mask_distribution,
            modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededGgswLevelMatrix<C> {
    /// Mutable variant of [`SeededGgswLevelMatrix::as_seeded_glwe_list`]
    pub fn as_mut_seeded_glwe_list(&mut self) -> SeededGlweCiphertextListMutView<'_, Scalar> {
        SeededGlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            self.glwe_size,
            self.polynomial_size,
            self.compression_seed.clone(),
            self.ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededGgswLevelMatrix`] entities.
#[derive(Clone)]
pub struct SeededGgswLevelMatrixCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub compression_seed: CompressionSeed,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for SeededGgswLevelMatrix<C>
{
    type Metadata = SeededGgswLevelMatrixCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let SeededGgswLevelMatrixCreationMetadata {
            glwe_size,
            polynomial_size,
            compression_seed,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_size,
            polynomial_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for SeededGgswCiphertext<C>
{
    type Element = C::Element;

    type EntityViewMetadata = SeededGgswLevelMatrixCreationMetadata<Self::Element>;

    type EntityView<'this>
        = SeededGgswLevelMatrix<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this>
        = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        SeededGgswLevelMatrixCreationMetadata {
            glwe_size: self.glwe_size,
            polynomial_size: self.polynomial_size,
            compression_seed: self.compression_seed.clone(),
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.seeded_ggsw_level_matrix_size()
    }

    /// Unimplemented for [`SeededGgswCiphertext`]. At the moment it does not make sense to
    /// return "sub" SeededGgswCiphertext.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededGgswCiphertext. \
        At the moment it does not make sense to return 'sub' SeededGgswCiphertext."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for SeededGgswCiphertext<C>
{
    type EntityMutView<'this>
        = SeededGgswLevelMatrix<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this>
        = DummyCreateFrom
    where
        Self: 'this;
}
