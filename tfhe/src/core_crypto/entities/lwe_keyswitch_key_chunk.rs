//! Module containing the definition of the [`LweKeyswitchKeyChunk`].

use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::backward_compatibility::entities::lwe_keyswitch_key_chunk::LweKeyswitchKeyChunkVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::named::Named;

/// An [`LWE keyswitch key chunk`](`LweKeyswitchKeyChunk`).
///
/// It is a chunked version of [`LWE keyswitch key`](`LweKeyswitchKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweKeyswitchKeyChunkVersions)]
pub struct LweKeyswitchKeyChunk<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<C: Container> Named for LweKeyswitchKeyChunk<C>
where
    C::Element: UnsignedInteger,
{
    const NAME: &'static str = "core_crypto::LweKeyswitchKeyChunk";
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweKeyswitchKeyChunk<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweKeyswitchKeyChunk<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweKeyswitchKeyChunk<C> {
    /// Create an [`LweKeyswitchKeyChunk`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LweKeyswitchKeyChunk`] you need to call
    /// [`crate::core_crypto::algorithms::generate_chunked_lwe_keyswitch_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`LweKeyswitchKeyChunk`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweKeyswitchKeyChunk creation
    /// let chunk_size = ChunkSize(13);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweKeyswitchKeyChunk
    /// let lwe_ksk = LweKeyswitchKeyChunk::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     chunk_size,
    ///     output_lwe_dimension,
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
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_ksk.into_container();
    ///
    /// // Recreate a keyswitch key using from_container
    /// let lwe_ksk = LweKeyswitchKeyChunk::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_lwe_dimension.to_lwe_size(),
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
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKeyChunk"
        );
        assert!(
            container.container_len()
                % lwe_keyswitch_key_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_lwe_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * output_lwe_size: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_size: {output_lwe_size:?}.",
            decomp_level_count.0 * output_lwe_size.0,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`ChunkSize`] of the [`LweKeyswitchKeyChunk`].
    ///
    /// See [`LweKeyswitchKeyChunk::from_container`] for usage.
    pub fn chunk_size(&self) -> ChunkSize {
        ChunkSize(self.data.container_len() / self.input_key_element_encrypted_size())
    }

    /// Return the output [`LweDimension`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size.to_lwe_dimension()
    }

    /// Return the output [`LweSize`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn output_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LweKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    /// Return a view of the [`LweKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweKeyswitchKeyChunkView<'_, Scalar> {
        LweKeyswitchKeyChunk::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_lwe_ciphertext_list(&self) -> LweCiphertextListView<'_, Scalar> {
        LweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweKeyswitchKeyChunk<C> {
    /// Mutable variant of [`LweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweKeyswitchKeyChunkMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        LweKeyswitchKeyChunk::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_lwe_ciphertext_list(&mut self) -> LweCiphertextListMutView<'_, Scalar> {
        let output_lwe_size = self.output_lwe_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweCiphertextListMutView::from_container(self.as_mut(), output_lwe_size, ciphertext_modulus)
    }
}

/// An [`LweKeyswitchKeyChunk`] owning the memory for its own storage.
pub type LweKeyswitchKeyChunkOwned<Scalar> = LweKeyswitchKeyChunk<Vec<Scalar>>;
/// An [`LweKeyswitchKeyChunk`] immutably borrowing memory for its own storage.
pub type LweKeyswitchKeyChunkView<'data, Scalar> = LweKeyswitchKeyChunk<&'data [Scalar]>;
/// An [`LweKeyswitchKeyChunk`] mutably borrowing memory for its own storage.
pub type LweKeyswitchKeyChunkMutView<'data, Scalar> = LweKeyswitchKeyChunk<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweKeyswitchKeyChunkOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweKeyswitchKeyChunk`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LweKeyswitchKeyChunk`] you need to call
    /// [`crate::core_crypto::algorithms::generate_chunked_lwe_keyswitch_key`] using this key as
    /// output.
    ///
    /// See [`LweKeyswitchKeyChunk::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        chunk_size: ChunkSize,
        output_key_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                chunk_size.0
                    * lwe_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_lwe_dimension.to_lwe_size()
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_lwe_dimension.to_lwe_size(),
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LweKeyswitchKeyChunk<C>
{
    type Metadata = LweKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LweKeyswitchKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LweKeyswitchKeyChunk<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LweKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = LweKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LweCiphertextListCreationMetadata {
            lwe_size: self.output_lwe_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LweKeyswitchKeyCreationMetadata {
            decomp_base_log: self.decomposition_base_log(),
            decomp_level_count: self.decomposition_level_count(),
            output_lwe_size: self.output_lwe_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LweKeyswitchKeyChunk<C>
{
    type EntityMutView<'this>
        = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = LweKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}

pub struct LweKeyswitchKeyChunkConformanceParams<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub output_lwe_size: LweSize,
    pub chunk_size: ChunkSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ParameterSetConformant
    for LweKeyswitchKeyChunk<C>
{
    type ParameterSet = LweKeyswitchKeyChunkConformanceParams<Scalar>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        } = self;

        *ciphertext_modulus == parameter_set.ciphertext_modulus
            && data.container_len()
                == parameter_set.chunk_size.0
                    * lwe_keyswitch_key_input_key_element_encrypted_size(
                        parameter_set.decomp_level_count,
                        parameter_set.output_lwe_size,
                    )
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *output_lwe_size == parameter_set.output_lwe_size
    }
}
