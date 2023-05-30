/*
//! Module containing the definition of the SeededGlweKeyswitchKey.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded GLWE keyswitch key`](`SeededGlweKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeededGlweKeyswitchKey<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    poly_size: PolynomialSize,
    compression_seed: CompressionSeed,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for SeededGlweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for SeededGlweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`GlweSecretKey`] element for a
/// [`SeededGlweKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`GlweSize`].
pub fn seeded_glwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    // One seeded ciphertext per level
    decomp_level_count.0
}

impl<Scalar, C: Container<Element = Scalar>> SeededGlweKeyswitchKey<C> {
    /// Create an [`SeededGlweKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`SeededGlweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_glwe_keyswitch_key`] using this key as
    /// output.
    ///
    /// This docstring exhibits [`SeededGlweKeyswitchKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
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
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        poly_size: PolynomialSize,
        compression_seed: CompressionSeed,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an SeededLweKeyswitchKey"
        );
        assert!(
            container.container_len() % (decomp_level_count.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}.",
            decomp_level_count.0,
            container.container_len()
        );

        SeededGlweKeyswitchKey {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            poly_size,
            compression_seed,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`GlweDimension`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn input_key_glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.data.container_len() / (self.seeded_input_key_element_encrypted_size()
            * self.input_poly_size))
    }

    /// Return the input [`PolynomialSize`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Return the output [`GlweDimension`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn output_key_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`CompressionSeed`] of the [`SeededGlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Return the number of elements in an encryption of an input [`GlweSecretKey`] element of the
    /// current [`SeededGlweKeyswitchKey`].
    pub fn seeded_input_key_element_encrypted_size(&self) -> usize {
        seeded_glwe_keyswitch_key_input_key_element_encrypted_size(self.decomp_level_count)
    }

    /// Return a view of the [`SeededGlweKeyswitchKey`]. This is useful if an algorithm takes a view
    /// by value.
    pub fn as_view(&self) -> SeededGlweKeyswitchKey<&'_ [Scalar]> {
        SeededGlweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_glwe_size,
            self.poly_size,
            self.compression_seed,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededGlweKeyswitchKey`] and decompress it into a standard
    /// [`GlweKeyswitchKey`].
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn decompress_into_glwe_keyswitch_key(self) -> GlweKeyswitchKeyOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_ksk = GlweKeyswitchKeyOwned::new(
            Scalar::ZERO,
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_key_glwe_dimension(),
            self.output_key_glwe_dimension(),
            self.polynomial_size(),
        );
        decompress_seeded_glwe_keyswitch_key::<_, _, _, ActivatedRandomGenerator>(
            &mut decompressed_ksk,
            &self,
        );
        decompressed_ksk
    }

    pub fn as_seeded_glwe_ciphertext_list(&self) -> SeededGlweCiphertextListView<'_, Scalar> {
        SeededGlweCiphertextListView::from_container(
            self.as_ref(),
            self.output_glwe_size(),
            self.polynomial_size(),
            self.compression_seed(),
        )
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> SeededGlweKeyswitchKey<C> {
    /// Mutable variant of [`SeededGlweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> SeededGlweKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let poly_size = self.poly_size;
        let compression_seed = self.compression_seed;
        SeededGlweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            poly_size,
            compression_seed,
        )
    }

    pub fn as_mut_seeded_glwe_ciphertext_list(
        &mut self,
    ) -> SeededGlweCiphertextListMutView<'_, Scalar> {
        let output_glwe_size = self.output_glwe_size();
        let poly_size = self.polynomial_size();
        let compression_seed = self.compression_seed();
        SeededGlweCiphertextListMutView::from_container(
            self.as_mut(),
            output_glwe_size,
            poly_size,
            compression_seed,
        )
    }
}

/// A [`SeededGlweKeyswitchKey`] owning the memory for its own storage.
pub type SeededGlweKeyswitchKeyOwned<Scalar> = SeededGlweKeyswitchKey<Vec<Scalar>>;

impl<Scalar: Copy> SeededGlweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`SeededGlweKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`SeededGlweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_seeded_glwe_keyswitch_key`] using this key as
    /// output.
    ///
    /// See [`SeededGlweKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_glwe_dimension: GlweDimension,
        output_key_glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        compression_seed: CompressionSeed,
    ) -> SeededGlweKeyswitchKeyOwned<Scalar> {
        SeededGlweKeyswitchKeyOwned::from_container(
            vec![
                fill_with;
                input_key_glwe_dimension.0 * polynomial_size.0
                    * seeded_lwe_keyswitch_key_input_key_element_encrypted_size(decomp_level_count,)
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_glwe_dimension.to_glwe_size(),
            polynomial_size,
            compression_seed,
        )
    }
}

impl<C: Container> ContiguousEntityContainer for SeededGlweKeyswitchKey<C> {
    type Element = C::Element;

    type EntityViewMetadata = SeededGlweCiphertextListCreationMetadata;

    type EntityView<'this> = SeededGlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> SeededGlweCiphertextListCreationMetadata {
        SeededGlweCiphertextListCreationMetadata(self.output_glwe_size(), self.compression_seed())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.seeded_input_key_element_encrypted_size()
    }

    /// Unimplemented for [`SeededGlweKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for SeededLweKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for SeededGlweKeyswitchKey<C> {
    type EntityMutView<'this> = SeededGlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
*/
