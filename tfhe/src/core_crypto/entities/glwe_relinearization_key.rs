//! Module containing the definition of the [`GlweRelinearizationKey`].

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`GLWE relinearization key`](`GlweRelinearizationKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlweRelinearizationKey<C: Container>
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweRelinearizationKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweRelinearizationKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`GlweSecretKey`] element for a
/// [`GlweRelinearizationKey`] given a [`DecompositionLevelCount`], [`GlweSize`] and
/// [`PolynomialSize`].
pub fn glwe_relinearization_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * glwe_size.0 * polynomial_size.0
}

/// Return the number of elements in a [`GlweRelinearizationKey`] given a
/// [`DecompositionLevelCount`], [`GlweSize`], and [`PolynomialSize`].
pub fn glwe_relinearization_key_size(
    decomp_level_count: DecompositionLevelCount,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    (glwe_size.to_glwe_dimension().0 * (glwe_size.to_glwe_dimension().0 + 1)) / 2
        * glwe_relinearization_key_input_key_element_encrypted_size(
            decomp_level_count,
            glwe_size,
            polynomial_size,
        )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweRelinearizationKey<C> {
    /// Create a [`GlweRelinearizationKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`GlweRelinearizationKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_glwe_relinearization_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`GlweRelinearizationKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweRelinearizationKey creation
    /// let glwe_size = GlweSize(3);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GlweRelinearizationKey
    /// let relin_key = GlweRelinearizationKey::new(
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
    /// let relin_key = GlweRelinearizationKey::from_container(
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
            "Got an empty container to create a GlweRelinearizationKey"
        );
        assert!(
            container.container_len()
                % glwe_relinearization_key_input_key_element_encrypted_size(
                    decomp_level_count,
                    glwe_size,
                    polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be divisible by decomp_level_count * glwe_size * polynomial_size:\
         {}. Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        glwe_size: {glwe_size:?}, polynomial_size: {polynomial_size:?}.",
            glwe_relinearization_key_input_key_element_encrypted_size(
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

    /// Return the [`GlweDimension`] of the [`GlweRelinearizationKey`].
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn glwe_dimension(&self) -> GlweDimension {
        self.glwe_size.to_glwe_dimension()
    }

    /// Return the [`GlweSize`] of the [`GlweRelinearizationKey`].
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`GlweRelinearizationKey`].
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`DecompositionLevelCount`] of the [`GlweRelinearizationKey`].
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`GlweRelinearizationKey`].
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the number of elements in an encryption of an input [`GlweSecretKey`] element of the
    /// current [`GlweRelinearizationKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        glwe_relinearization_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.glwe_size,
            self.polynomial_size,
        )
    }

    /// Return a view of the [`GlweRelinearizationKey`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> GlweRelinearizationKey<&'_ [Scalar]> {
        GlweRelinearizationKey::from_container(
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
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`GlweRelinearizationKey`]
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GlweRelinearizationKey<C> {
    /// Mutable variant of [`GlweRelinearizationKey::as_view`].
    pub fn as_mut_view(&mut self) -> GlweRelinearizationKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        GlweRelinearizationKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// A [`GlweRelinearizationKey`] owning the memory for its own storage.
pub type GlweRelinearizationKeyOwned<Scalar> = GlweRelinearizationKey<Vec<Scalar>>;
/// A [`GlweRelinearizationKey`] immutably borrowing memory for its own storage.
pub type GlweRelinearizationKeyView<'data, Scalar> = GlweRelinearizationKey<&'data [Scalar]>;
/// A [`GlweRelinearizationKey`] mutably borrowing memory for its own storage.
pub type GlweRelinearizationKeyMutView<'data, Scalar> = GlweRelinearizationKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> GlweRelinearizationKeyOwned<Scalar> {
    /// Create a new [`GlweRelinearizationKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`GlweRelinearizationKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_glwe_relinearization_key`]
    /// using this key as output.
    ///
    /// See [`GlweRelinearizationKey::from_container`] for usage.
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
                glwe_relinearization_key_size(decomp_level_count, glwe_size, polynomial_size)
            ],
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create
/// [`GlweRelinearizationKey`] entities.
#[derive(Clone, Copy)]
pub struct GlweRelinearizationKeyCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for GlweRelinearizationKey<C>
{
    type Metadata = GlweRelinearizationKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GlweRelinearizationKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        } = meta;
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

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for GlweRelinearizationKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = GlweRelinearizationKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = GlweRelinearizationKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextListCreationMetadata {
            glwe_size: self.glwe_size(),
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        GlweRelinearizationKeyCreationMetadata {
            decomp_base_log: self.decomposition_base_log(),
            decomp_level_count: self.decomposition_level_count(),
            glwe_size: self.glwe_size(),
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for GlweRelinearizationKey<C>
{
    type EntityMutView<'this>
        = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = GlweRelinearizationKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}

pub struct RelinearizationKeyConformanceParmas {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

impl<C: Container<Element = u64>> ParameterSetConformant for GlweRelinearizationKey<C> {
    type ParameterSet = RelinearizationKeyConformanceParmas;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        } = self;

        *ciphertext_modulus == parameter_set.ciphertext_modulus
            && data.container_len()
                == glwe_relinearization_key_size(
                    parameter_set.decomp_level_count,
                    parameter_set.glwe_size,
                    parameter_set.polynomial_size,
                )
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *glwe_size == parameter_set.glwe_size
            && *polynomial_size == parameter_set.polynomial_size
    }
}
