//! Module containing the definition of the [`SeededLweKeyswitchKeyChunk`].

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::seeded_lwe_keyswitch_key_chunk::SeededLweKeyswitchKeyChunkVersions;
use crate::core_crypto::commons::math::random::CompressionSeed;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::named::Named;
use tfhe_versionable::Versionize;

/// A [`seeded LWE keyswitch key chunk`](`SeededLweKeyswitchKeyChunk`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLweKeyswitchKeyChunkVersions)]
pub struct SeededLweKeyswitchKeyChunk<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<C: Container> Named for SeededLweKeyswitchKeyChunk<C>
where
    C::Element: UnsignedInteger,
{
    const NAME: &'static str = "core_crypto::SeededLweKeyswitchKeyChunk";
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededLweKeyswitchKeyChunk<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for SeededLweKeyswitchKeyChunk<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededLweKeyswitchKeyChunk<C> {
    /// Create a [`SeededLweKeyswitchKeyChunk`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate a
    /// [`SeededLweKeyswitchKeyChunk`] you need to call
    /// [`crate::core_crypto::algorithms::generate_chunked_seeded_lwe_keyswitch_key`] using this key
    /// as output.
    ///
    /// Individual chunks are not meant to be decompressed. Instead, the whole key should be
    /// assembled first, then decompressed. See
    /// [`allocate_and_assemble_seeded_lwe_keyswitch_key_from_chunks`][`crate::core_crypto::algorithms::allocate_and_assemble_seeded_lwe_keyswitch_key_from_chunks`].
    ///
    /// This docstring exhibits [`SeededLweKeyswitchKeyChunk`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweKeyswitchKeyChunk creation
    /// let chunk_size = ChunkSize(17);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    /// let global_seed = seeder.seed().into();
    ///
    /// // Create a new SeededLweKeyswitchKeyChunk
    /// let lwe_ksk = SeededLweKeyswitchKeyChunk::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     chunk_size,
    ///     output_lwe_dimension,
    ///     global_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.chunk_size(), chunk_size);
    /// assert_eq!(lwe_ksk.output_key_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(
    ///     lwe_ksk.output_lwe_size(),
    ///     output_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let compression_seed = lwe_ksk.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_ksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_ksk = SeededLweKeyswitchKeyChunk::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_lwe_dimension.to_lwe_size(),
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.chunk_size(), chunk_size);
    /// assert_eq!(lwe_ksk.output_key_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(
    ///     lwe_ksk.output_lwe_size(),
    ///     output_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_lwe_size: LweSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container.container_len() > 0,
            "Got an empty container to create a SeededLweKeyswitchKeyChunk"
        );
        assert!(
            container
                .container_len()
                .is_multiple_of(decomp_level_count.0),
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}.",
            decomp_level_count.0,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`SeededLweKeyswitchKeyChunk`].
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededLweKeyswitchKeyChunk`].
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`ChunkSize`] of the [`SeededLweKeyswitchKeyChunk`].
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn chunk_size(&self) -> ChunkSize {
        ChunkSize(self.data.container_len() / self.seeded_input_key_element_encrypted_size())
    }

    /// Return the output [`LweDimension`] of the [`SeededLweKeyswitchKeyChunk`].
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size.to_lwe_dimension()
    }

    /// Return the output [`LweSize`] of the [`SeededLweKeyswitchKeyChunk`].
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn output_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }

    /// Return the output [`CompressionSeed`] of the global [`SeededLweKeyswitchKey`].
    ///
    /// This is the seed for the global key, not just a single chunk [`SeededLweKeyswitchKeyChunk`].
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`SeededLweKeyswitchKeyChunk`].
    pub fn seeded_input_key_element_encrypted_size(&self) -> usize {
        seeded_lwe_keyswitch_key_input_key_element_encrypted_size(self.decomp_level_count)
    }

    /// Return a view of the [`SeededLweKeyswitchKeyChunk`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> SeededLweKeyswitchKeyChunk<&'_ [Scalar]> {
        SeededLweKeyswitchKeyChunk::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_size,
            self.compression_seed.clone(),
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_seeded_lwe_ciphertext_list(&self) -> SeededLweCiphertextListView<'_, Scalar> {
        SeededLweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_size(),
            self.compression_seed(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededLweKeyswitchKeyChunk<C> {
    /// Mutable variant of [`SeededLweKeyswitchKeyChunk::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLweKeyswitchKeyChunk<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        let compression_seed = self.compression_seed.clone();
        let ciphertext_modulus = self.ciphertext_modulus;
        SeededLweKeyswitchKeyChunk::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            compression_seed,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_seeded_lwe_ciphertext_list(
        &mut self,
    ) -> SeededLweCiphertextListMutView<'_, Scalar> {
        let output_lwe_size = self.output_lwe_size();
        let compression_seed = self.compression_seed();
        let ciphertext_modulus = self.ciphertext_modulus();
        SeededLweCiphertextListMutView::from_container(
            self.as_mut(),
            output_lwe_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// A [`SeededLweKeyswitchKeyChunk`] owning the memory for its own storage.
pub type SeededLweKeyswitchKeyChunkOwned<Scalar> = SeededLweKeyswitchKeyChunk<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> SeededLweKeyswitchKeyChunkOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededLweKeyswitchKeyChunk`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`SeededLweKeyswitchKeyChunk`] you need to call
    /// [`crate::core_crypto::algorithms::generate_chunked_seeded_lwe_keyswitch_key`] using this key
    /// as output.
    ///
    /// See [`SeededLweKeyswitchKeyChunk::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        chunk_size: ChunkSize,
        output_key_lwe_dimension: LweDimension,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                chunk_size.0
                    * seeded_lwe_keyswitch_key_input_key_element_encrypted_size(decomp_level_count)
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_lwe_dimension.to_lwe_size(),
            compression_seed,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for SeededLweKeyswitchKeyChunk<C>
{
    type Element = C::Element;

    type EntityViewMetadata = SeededLweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = SeededLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this>
        = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(
        &self,
    ) -> SeededLweCiphertextListCreationMetadata<Self::Element> {
        SeededLweCiphertextListCreationMetadata {
            lwe_size: self.output_lwe_size(),
            compression_seed: self.compression_seed(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.seeded_input_key_element_encrypted_size()
    }

    /// Unimplemented for [`SeededLweKeyswitchKeyChunk`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededLweKeyswitchKeyChunk. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for SeededLweKeyswitchKeyChunk<C>
{
    type EntityMutView<'this>
        = SeededLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this>
        = DummyCreateFrom
    where
        Self: 'this;
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ParameterSetConformant
    for SeededLweKeyswitchKeyChunk<C>
{
    type ParameterSet = LweKeyswitchKeyChunkConformanceParams<Scalar>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
            compression_seed: _,
        } = self;

        *ciphertext_modulus == parameter_set.ciphertext_modulus
            && data.container_len()
                == parameter_set.chunk_size.0
                    * seeded_lwe_keyswitch_key_input_key_element_encrypted_size(
                        parameter_set.decomp_level_count,
                    )
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *output_lwe_size == parameter_set.output_lwe_size
    }
}
