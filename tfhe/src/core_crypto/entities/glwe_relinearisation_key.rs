//! Module containing the definition of the GlweRelinearisationKey.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`GLWE relinearisation key`](`GlweRelinearisationKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlweRelinearisationKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweRelinearisationKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweRelinearisationKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`GlweSecretKey`] element for a
/// [`GlweRelinearisationKey`] given a [`DecompositionLevelCount`], [`GlweSize`] and
/// [`PolynomialSize`].
pub fn glwe_relinearisation_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * glwe_size.0 * polynomial_size.0
}

/// Return the number of elements in a [`GlweRelinearisationKey`] given a
/// [`DecompositionLevelCount`], [`GlweSize`], and [`PolynomialSize`].
pub fn glwe_relinearisation_key_size(
    decomp_level_count: DecompositionLevelCount,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    (glwe_size.to_glwe_dimension().0 * (glwe_size.to_glwe_dimension().0 + 1)) / 2
        * glwe_relinearisation_key_input_key_element_encrypted_size(
            decomp_level_count,
            glwe_size,
            polynomial_size,
        )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweRelinearisationKey<C> {
    /// Create a [`GlweRelinearisationKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`GlweRelinearisationKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_glwe_relinearisation_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`GlweRelinearisationKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweRelinearisationKey creation
    /// let glwe_size = GlweSize(3);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GlweRelinearisationKey
    /// let relin_key = GlweRelinearisationKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(relin_key.glwe_dimension(), glwe_size.to_glwe_dimension());
    /// assert_eq!(relin_key.glwe_size(), glwe_size);
    /// assert_eq!(relin_key.polynomial_size(), polynomial_size);
    /// assert_eq!(relin_key.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(relin_key.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(relin_key.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = relin_key.into_container();
    ///
    /// // Recreate a key using from_container
    /// let relin_key = GlweRelinearisationKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(relin_key.glwe_dimension(), glwe_size.to_glwe_dimension());
    /// assert_eq!(relin_key.glwe_size(), glwe_size);
    /// assert_eq!(relin_key.polynomial_size(), polynomial_size);
    /// assert_eq!(relin_key.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(relin_key.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(relin_key.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKey"
        );
        assert!(
            container.container_len()
                % glwe_relinearisation_key_input_key_element_encrypted_size(
                    decomp_level_count,
                    glwe_size,
                    polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be divisable by decomp_level_count * glwe_size * polynomial_size:\
         {}. Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        glwe_size: {glwe_size:?}, polynomial_size: {polynomial_size:?}.",
            glwe_relinearisation_key_input_key_element_encrypted_size(
                decomp_level_count,
                glwe_size,
                polynomial_size
            ),
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweDimension`] of the [`GlweRelinearisationKey`].
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_size.to_glwe_dimension()
    }

    /// Return the [`GlweSize`] of the [`GlweRelinearisationKey`].
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`GlweRelinearisationKey`].
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`DecompositionLevelCount`] of the [`GlweRelinearisationKey`].
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`GlweRelinearisationKey`].
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the number of elements in an encryption of an input [`GlweSecretKey`] element of the
    /// current [`GlweRelinearisationKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        glwe_relinearisation_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.glwe_size,
            self.polynomial_size,
        )
    }

    /// Return a view of the [`GlweRelinearisationKey`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> GlweRelinearisationKey<&'_ [Scalar]> {
        GlweRelinearisationKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`GlweRelinearisationKey`]
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GlweRelinearisationKey<C> {
    /// Mutable variant of [`LweTracePackingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> GlweRelinearisationKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        GlweRelinearisationKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// A [`GlweRelinearisationKey`] owning the memory for its own storage.
pub type GlweRelinearisationKeyOwned<Scalar> = GlweRelinearisationKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> GlweRelinearisationKeyOwned<Scalar> {
    /// Create a new [`GlweRelinearisationKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`GlweRelinearisationKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_glwe_relinearisation_key`]
    /// using this key as output.
    ///
    /// See [`GlweRelinearisationKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                glwe_relinearisation_key_size(decomp_level_count, glwe_size, polynomial_size)
            ],
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for GlweRelinearisationKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Scalar>;

    type EntityView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" packing keyswitch keys. So we use a
    // dummy placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        // Fix to use the correct ciphertext modulus
        GlweCiphertextListCreationMetadata(
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus(),
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`GlweRelinearisationKey`]. At the moment it does not
    /// make sense to return "sub" packing keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for GlweRelinearisationKey. \
        At the moment it does not make sense to return 'sub' relinearisation keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for GlweRelinearisationKey<C>
{
    type EntityMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" relinearisation keys. So we use a
    // dummy placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}

/// Metadata used in the [`CreateFrom`] implementation to create
/// [`GlweRelinearisationKey`] entities.
#[derive(Clone, Copy)]
pub struct GlweRelinearisationKeyCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for GlweRelinearisationKey<C>
{
    type Metadata = GlweRelinearisationKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GlweRelinearisationKeyCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}
