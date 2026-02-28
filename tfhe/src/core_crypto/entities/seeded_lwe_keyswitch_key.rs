//! Module containing the definition of the [`SeededLweKeyswitchKey`].

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_lwe_keyswitch_key::SeededLweKeyswitchKeyVersions;
use crate::core_crypto::commons::math::random::{CompressionSeed, DefaultRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use tfhe_versionable::Versionize;

/// A [`seeded LWE keyswitch key`](`SeededLweKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLweKeyswitchKeyVersions)]
pub struct SeededLweKeyswitchKey<C: Container>
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededLweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for SeededLweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`LweSecretKey`] element for a
/// [`SeededLweKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`LweSize`].
pub fn seeded_lwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    // One seeded ciphertext per level
    decomp_level_count.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededLweKeyswitchKey<C> {
    /// Create a [`SeededLweKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`SeededLweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_lwe_keyswitch_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`SeededLweKeyswitchKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweKeyswitchKey
    /// let lwe_ksk = SeededLweKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_lwe_dimension,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
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
    /// let lwe_ksk = SeededLweKeyswitchKey::from_container(
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
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_key_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(
    ///     lwe_ksk.output_lwe_size(),
    ///     output_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let lwe_ksk = lwe_ksk.decompress_into_lwe_keyswitch_key();
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
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
            "Got an empty container to create an SeededLweKeyswitchKey"
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

    /// Return the [`DecompositionBaseLog`] of the [`SeededLweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededLweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`LweDimension`] of the [`SeededLweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.seeded_input_key_element_encrypted_size())
    }

    /// Return the output [`LweDimension`] of the [`SeededLweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size.to_lwe_dimension()
    }

    /// Return the output [`LweSize`] of the [`SeededLweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn output_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }

    /// Return the output [`CompressionSeed`] of the [`SeededLweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`SeededLweKeyswitchKey`].
    pub fn seeded_input_key_element_encrypted_size(&self) -> usize {
        seeded_lwe_keyswitch_key_input_key_element_encrypted_size(self.decomp_level_count)
    }

    /// Return a view of the [`SeededLweKeyswitchKey`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> SeededLweKeyswitchKey<&'_ [Scalar]> {
        SeededLweKeyswitchKey::from_container(
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
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededLweKeyswitchKey`] and decompress it into a standard
    /// [`LweKeyswitchKey`].
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn decompress_into_lwe_keyswitch_key(self) -> LweKeyswitchKeyOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_ksk = LweKeyswitchKeyOwned::new(
            Scalar::ZERO,
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_key_lwe_dimension(),
            self.output_key_lwe_dimension(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_lwe_keyswitch_key::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_ksk,
            &self,
        );
        decompressed_ksk
    }

    /// Parallel variant of
    /// [`decompress_into_lwe_keyswitch_key`](`Self::decompress_into_lwe_keyswitch_key`).
    pub fn par_decompress_into_lwe_keyswitch_key(self) -> LweKeyswitchKeyOwned<Scalar>
    where
        Scalar: UnsignedTorus + Send + Sync,
    {
        let mut decompressed_ksk = LweKeyswitchKeyOwned::new(
            Scalar::ZERO,
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_key_lwe_dimension(),
            self.output_key_lwe_dimension(),
            self.ciphertext_modulus(),
        );
        par_decompress_seeded_lwe_keyswitch_key::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_ksk,
            &self,
        );
        decompressed_ksk
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

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededLweKeyswitchKey<C> {
    /// Mutable variant of [`SeededLweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLweKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        let compression_seed = self.compression_seed.clone();
        let ciphertext_modulus = self.ciphertext_modulus;
        SeededLweKeyswitchKey::from_container(
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

/// A [`SeededLweKeyswitchKey`] owning the memory for its own storage.
pub type SeededLweKeyswitchKeyOwned<Scalar> = SeededLweKeyswitchKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> SeededLweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededLweKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`SeededLweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_lwe_keyswitch_key`] using this key as
    /// output.
    ///
    /// See [`SeededLweKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
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
    for SeededLweKeyswitchKey<C>
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

    /// Unimplemented for [`SeededLweKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededLweKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for SeededLweKeyswitchKey<C>
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
    for SeededLweKeyswitchKey<C>
{
    type ParameterSet = LweKeyswitchKeyConformanceParams<Scalar>;

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
                == parameter_set.input_lwe_dimension.0
                    * seeded_lwe_keyswitch_key_input_key_element_encrypted_size(
                        parameter_set.decomp_level_count,
                    )
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *output_lwe_size == parameter_set.output_lwe_size
    }
}
