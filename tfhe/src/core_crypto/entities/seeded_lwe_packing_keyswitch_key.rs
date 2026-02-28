//! Module containing the definition of the [`SeededLwePackingKeyswitchKey`].

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_lwe_packing_keyswitch_key::SeededLwePackingKeyswitchKeyVersions;
use crate::core_crypto::commons::generators::MaskRandomGenerator;
use crate::core_crypto::commons::math::random::{CompressionSeed, DefaultRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use tfhe_versionable::Versionize;

/// A [`seeded LWE packing keyswitch key`](`SeededLwePackingKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLwePackingKeyswitchKeyVersions)]
pub struct SeededLwePackingKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for SeededLwePackingKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for SeededLwePackingKeyswitchKey<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`LweSecretKey`] element for a
/// [`SeededLwePackingKeyswitchKey`] given a [`DecompositionLevelCount`] and output
/// [`PolynomialSize`].
pub fn seeded_lwe_packing_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_polynomial_size: PolynomialSize,
) -> usize {
    // One seeded ciphertext per level
    decomp_level_count.0 * output_polynomial_size.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> SeededLwePackingKeyswitchKey<C> {
    /// Create a [`SeededLwePackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`SeededLwePackingKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_lwe_packing_keyswitch_key`] using this key
    /// as output.
    ///
    /// This docstring exhibits [`SeededLwePackingKeyswitchKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLwePackingKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_glwe_dimension = GlweDimension(1);
    /// let output_polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLwePackingKeyswitchKey
    /// let lwe_pksk = SeededLwePackingKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_glwe_dimension,
    ///     output_polynomial_size,
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_pksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_pksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_pksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_pksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(
    ///     lwe_pksk.output_key_polynomial_size(),
    ///     output_polynomial_size
    /// );
    /// assert_eq!(
    ///     lwe_pksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(lwe_pksk.output_polynomial_size(), output_polynomial_size);
    /// assert_eq!(lwe_pksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let compression_seed = lwe_pksk.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_pksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_pksk = SeededLwePackingKeyswitchKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_glwe_dimension.to_glwe_size(),
    ///     output_polynomial_size,
    ///     compression_seed,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_pksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_pksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_pksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_pksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(
    ///     lwe_pksk.output_key_polynomial_size(),
    ///     output_polynomial_size
    /// );
    /// assert_eq!(
    ///     lwe_pksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(lwe_pksk.output_polynomial_size(), output_polynomial_size);
    /// assert_eq!(lwe_pksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// let lwe_pksk = lwe_pksk.decompress_into_lwe_packing_keyswitch_key();
    ///
    /// assert_eq!(lwe_pksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_pksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_pksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_pksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(
    ///     lwe_pksk.output_key_polynomial_size(),
    ///     output_polynomial_size
    /// );
    /// assert_eq!(
    ///     lwe_pksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(lwe_pksk.output_polynomial_size(), output_polynomial_size);
    /// assert_eq!(lwe_pksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            ciphertext_modulus.is_compatible_with_native_modulus(),
            "Seeded entities are not yet compatible with non power of 2 moduli."
        );

        assert!(
            container.container_len() > 0,
            "Got an empty container to create an SeededLwePackingKeyswitchKey"
        );
        assert!(
            container
                .container_len()
                .is_multiple_of(decomp_level_count.0 * output_polynomial_size.0),
            "The provided container length is not valid. \
            It needs to be dividable by decomp_level_count * output_polynomial_size: {}. \
            Got container length: {} decomp_level_count: {decomp_level_count:?} \
            and output_polynomial_size {output_polynomial_size:?}.",
            decomp_level_count.0 * output_polynomial_size.0,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            compression_seed,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`LweDimension`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.seeded_input_key_element_encrypted_size())
    }

    /// Return the output [`GlweDimension`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_key_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`PolynomialSize`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_key_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the output [`GlweSize`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the output [`CompressionSeed`] of the [`SeededLwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed.clone()
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`SeededLwePackingKeyswitchKey`].
    pub fn seeded_input_key_element_encrypted_size(&self) -> usize {
        seeded_lwe_packing_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_polynomial_size,
        )
    }

    /// Return a view of the [`SeededLwePackingKeyswitchKey`]. This is useful if an algorithm takes
    /// a view by value.
    pub fn as_view(&self) -> SeededLwePackingKeyswitchKey<&'_ [Scalar]> {
        SeededLwePackingKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
            self.compression_seed.clone(),
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededLwePackingKeyswitchKey`] and decompress it into a standard
    /// [`LwePackingKeyswitchKey`].
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    pub fn decompress_into_lwe_packing_keyswitch_key(self) -> LwePackingKeyswitchKeyOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_pksk = LwePackingKeyswitchKeyOwned::new(
            Scalar::ZERO,
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_key_lwe_dimension(),
            self.output_key_glwe_dimension(),
            self.output_key_polynomial_size(),
            self.ciphertext_modulus(),
        );
        decompress_seeded_lwe_packing_keyswitch_key::<_, _, _, DefaultRandomGenerator>(
            &mut decompressed_pksk,
            &self,
        );
        decompressed_pksk
    }

    /// Decompress the [`SeededLwePackingKeyswitchKey`] into [`LwePackingKeyswitchKey`]
    /// without consuming `self`
    pub fn decompress_to_lwe_packing_keyswitch_key_with_pre_seeded_generator<Gen>(
        &self,
        generator: &mut MaskRandomGenerator<Gen>,
    ) -> LwePackingKeyswitchKeyOwned<Scalar>
    where
        Scalar: UnsignedTorus,
        Gen: ByteRandomGenerator,
    {
        let mut decompressed_pksk = LwePackingKeyswitchKeyOwned::new(
            Scalar::ZERO,
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_key_lwe_dimension(),
            self.output_key_glwe_dimension(),
            self.output_key_polynomial_size(),
            self.ciphertext_modulus(),
        );

        decompress_seeded_lwe_packing_keyswitch_key_with_pre_seeded_generator(
            &mut decompressed_pksk,
            self,
            generator,
        );

        decompressed_pksk
    }

    pub fn as_seeded_glwe_ciphertext_list(&self) -> SeededGlweCiphertextListView<'_, Scalar> {
        SeededGlweCiphertextListView::from_container(
            self.as_ref(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.compression_seed(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> SeededLwePackingKeyswitchKey<C> {
    /// Mutable variant of [`SeededLwePackingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLwePackingKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let compression_seed = self.compression_seed.clone();
        let ciphertext_modulus = self.ciphertext_modulus;
        SeededLwePackingKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            compression_seed,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_seeded_lwe_ciphertext_list(
        &mut self,
    ) -> SeededGlweCiphertextListMutView<'_, Scalar> {
        let output_glwe_size = self.output_glwe_size();
        let output_polynomial_size = self.output_polynomial_size();
        let compression_seed = self.compression_seed();
        let ciphertext_modulus = self.ciphertext_modulus();
        SeededGlweCiphertextListMutView::from_container(
            self.as_mut(),
            output_glwe_size,
            output_polynomial_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

/// A [`SeededLwePackingKeyswitchKey`] owning the memory for its own storage.
pub type SeededLwePackingKeyswitchKeyOwned<Scalar> = SeededLwePackingKeyswitchKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> SeededLwePackingKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededLwePackingKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`SeededLwePackingKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_lwe_packing_keyswitch_key`] using this key
    /// as output.
    ///
    /// See [`SeededLwePackingKeyswitchKey::from_container`] for usage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_glwe_dimension: GlweDimension,
        output_key_polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * seeded_lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_polynomial_size,
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_glwe_dimension.to_glwe_size(),
            output_key_polynomial_size,
            compression_seed,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for SeededLwePackingKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = SeededGlweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = SeededGlweCiphertextListView<'this, Self::Element>
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
    ) -> SeededGlweCiphertextListCreationMetadata<Self::Element> {
        SeededGlweCiphertextListCreationMetadata {
            glwe_size: self.output_glwe_size(),
            polynomial_size: self.output_polynomial_size(),
            compression_seed: self.compression_seed(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.seeded_input_key_element_encrypted_size()
    }

    /// Unimplemented for [`SeededLwePackingKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for SeededLwePackingKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for SeededLwePackingKeyswitchKey<C>
{
    type EntityMutView<'this>
        = SeededGlweCiphertextListMutView<'this, Self::Element>
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
    for SeededLwePackingKeyswitchKey<C>
{
    type ParameterSet = LwePackingKeyswitchKeyConformanceParams<Scalar>;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
            compression_seed: _,
        } = self;

        data.container_len()
            == seeded_lwe_packing_keyswitch_key_input_key_element_encrypted_size(
                *decomp_level_count,
                *output_polynomial_size,
            ) * parameter_set.input_lwe_dimension.0
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *output_glwe_size == parameter_set.output_glwe_size
            && *output_polynomial_size == parameter_set.output_polynomial_size
            && *ciphertext_modulus == parameter_set.ciphertext_modulus
    }
}
