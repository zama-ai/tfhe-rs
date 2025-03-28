//! Module containing the definition of the SeededLweBootstrapKeyChunk.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::seeded_lwe_bootstrap_key_chunk::SeededLweBootstrapKeyChunkVersions;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::named::Named;

/// A [`seeded LWE bootstrap key chunk`](`SeededLweBootstrapKeyChunk`).
///
/// This is a wrapper type of [`SeededGgswCiphertextList`], [`std::ops::Deref`] and
/// [`std::ops::DerefMut`] are implemented to dereference to the underlying
/// [`SeededGgswCiphertextList`] for ease of use. See [`SeededGgswCiphertextList`] for additional
/// methods.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLweBootstrapKeyChunkVersions)]
pub struct SeededLweBootstrapKeyChunk<C: Container>
where
    C::Element: UnsignedInteger,
{
    // An SeededLweBootstrapKeyChunk is literally a SeededGgswCiphertextList, so we wrap a
    // GgswCiphertextList and use Deref to have access to all the primitives of the
    // SeededGgswCiphertextList easily
    ggsw_list: SeededGgswCiphertextList<C>,
}

impl<C: Container> Named for SeededLweBootstrapKeyChunk<C>
where
    C::Element: UnsignedInteger,
{
    const NAME: &'static str = "core_crypto::SeededLweBootstrapKeyChunk";
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> std::ops::Deref
    for SeededLweBootstrapKeyChunk<C>
{
    type Target = SeededGgswCiphertextList<C>;

    fn deref(&self) -> &SeededGgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> std::ops::DerefMut
    for SeededLweBootstrapKeyChunk<C>
{
    fn deref_mut(&mut self) -> &mut SeededGgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededLweBootstrapKeyChunk<C> {
    /// Create a [`SeededLweBootstrapKeyChunk`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an LWE
    /// bootstrap key chunk you need to use
    /// [`crate::core_crypto::algorithms::generate_chunked_seeded_lwe_bootstrap_key`] or its
    /// parallel equivalent
    /// [`crate::core_crypto::algorithms::par_generate_chunked_seeded_lwe_bootstrap_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`SeededLweBootstrapKeyChunk`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweBootstrapKeyChunk creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let chunk_size = ChunkSize(10);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweBootstrapKeyChunk
    /// let bsk_chunk = SeededLweBootstrapKeyChunk::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     chunk_size,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// // These methods are "inherited" from SeededGgswCiphertextList and are accessed through the
    /// // Deref trait
    /// assert_eq!(bsk_chunk.glwe_size(), glwe_size);
    /// assert_eq!(bsk_chunk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk_chunk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk_chunk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk_chunk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // These methods are specific to the SeededLweBootstrapKeyChunk
    /// assert_eq!(bsk_chunk.chunk_size(), chunk_size);
    /// assert_eq!(
    ///     bsk_chunk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    ///
    /// let global_compression_seed = bsk_chunk.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = bsk_chunk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let bsk_chunk = SeededLweBootstrapKeyChunk::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     global_compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(bsk_chunk.glwe_size(), glwe_size);
    /// assert_eq!(bsk_chunk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk_chunk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk_chunk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk_chunk.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(bsk_chunk.chunk_size(), chunk_size);
    /// assert_eq!(
    ///     bsk_chunk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        global_compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        Self {
            ggsw_list: SeededGgswCiphertextList::from_container(
                container,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                global_compression_seed,
                ciphertext_modulus,
            ),
        }
    }

    /// Return the [`ChunkSize`] of the input [`SeededLweBootstrapKeyChunk`].
    ///
    /// See [`SeededLweBootstrapKeyChunk::from_container`] for usage.
    pub fn chunk_size(&self) -> ChunkSize {
        ChunkSize(self.ggsw_ciphertext_count().0)
    }

    /// Return the [`CompressionSeed`] of the global [`SeededGgswCiphertextList`].
    ///
    /// This is the seed of the global key, not just a single chunk.
    ///
    /// See [`SeededLweBootstrapKeyChunk::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.ggsw_list.compression_seed()
    }

    /// Return the [`LweDimension`] of the equivalent output [`LweSecretKey`].
    ///
    /// See [`SeededLweBootstrapKeyChunk::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLweBootstrapKeyChunk::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    /// Return a view of the [`SeededLweBootstrapKeyChunk`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> SeededLweBootstrapKeyChunk<&'_ [Scalar]> {
        SeededLweBootstrapKeyChunk::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.compression_seed(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededLweBootstrapKeyChunk<C> {
    /// Mutable variant of [`SeededLweBootstrapKeyChunk::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLweBootstrapKeyChunk<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        let global_compression_seed = self.compression_seed();
        let ciphertext_modulus = self.ciphertext_modulus();
        SeededLweBootstrapKeyChunk::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            global_compression_seed,
            ciphertext_modulus,
        )
    }
}

/// A [`SeededLweBootstrapKeyChunk`] owning the memory for its own storage.
pub type SeededLweBootstrapKeyChunkOwned<Scalar> = SeededLweBootstrapKeyChunk<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> SeededLweBootstrapKeyChunkOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededLweBootstrapKeyChunk`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an LWE bootstrap key you need to use
    /// [`crate::core_crypto::algorithms::generate_chunked_seeded_lwe_bootstrap_key`] or its
    /// parallel equivalent
    /// [`crate::core_crypto::algorithms::par_generate_chunked_seeded_lwe_bootstrap_key`] using
    /// this key as output.
    ///
    /// See [`SeededLweBootstrapKeyChunk::from_container`] for usage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        chunk_size: ChunkSize,
        global_compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ggsw_list: SeededGgswCiphertextList::new(
                fill_with,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(chunk_size.0),
                global_compression_seed,
                ciphertext_modulus,
            ),
        }
    }
}
