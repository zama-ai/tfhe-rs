//! Module containing the definition of the LwePrivateFunctionalPackingKeyswitchKey.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// An [`LWE private functional packing keyswitch key`](`LwePrivateFunctionalPackingKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePrivateFunctionalPackingKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]>
    for LwePrivateFunctionalPackingKeyswitchKey<C>
{
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LwePrivateFunctionalPackingKeyswitchKey<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`LweSecretKey`] element for a
/// [`LwePrivateFunctionalPackingKeyswitchKey`] given a [`DecompositionLevelCount`] and output
/// [`GlweSize`] and [`PolynomialSize`].
pub fn lwe_pfpksk_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_glwe_size.0 * output_polynomial_size.0
}

/// Return the number of elements in an [`LwePrivateFunctionalPackingKeyswitchKey`] given an input
/// [`LweSize`], [`DecompositionLevelCount`], output [`GlweSize`], and output [`PolynomialSize`].
pub fn lwe_pfpksk_size(
    input_lwe_size: LweSize,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    input_lwe_size.0
        * lwe_pfpksk_input_key_element_encrypted_size(
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>>
    LwePrivateFunctionalPackingKeyswitchKey<C>
{
    /// Create an [`LwePrivateFunctionalPackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LwePrivateFunctionalPackingKeyswitchKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_private_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_private_functional_packing_keyswitch_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`LwePrivateFunctionalPackingKeyswitchKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePrivateFunctionalPackingKeyswitchKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LwePrivateFunctionalPackingKeyswitchKey
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(
    ///     pfpksk.output_key_glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pfpksk.output_glwe_size(), glwe_size);
    /// assert_eq!(pfpksk.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pfpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pfpksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(pfpksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = pfpksk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let pfpksk = LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension.to_lwe_size(),
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(
    ///     pfpksk.output_key_glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pfpksk.output_glwe_size(), glwe_size);
    /// assert_eq!(pfpksk.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pfpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pfpksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(pfpksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKey"
        );
        assert!(
            container.container_len()
                % lwe_pfpksk_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * output_glwe_size * output_polynomial_size:\
         {}. Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_glwe_size: {output_glwe_size:?}, output_polynomial_size: \
        {output_polynomial_size:?}.",
            lwe_pfpksk_input_key_element_encrypted_size(
                decomp_level_count,
                output_glwe_size,
                output_polynomial_size
            ),
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the output key [`GlweDimension`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn output_key_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the input key [`LweDimension`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.input_key_element_encrypted_size() - 1)
    }

    /// Return the [`DecompositionLevelCount`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`CiphertextModulus`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LwePrivateFunctionalPackingKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_pfpksk_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Return a view of the [`LwePrivateFunctionalPackingKeyswitchKey`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> LwePrivateFunctionalPackingKeyswitchKey<&'_ [Scalar]> {
        LwePrivateFunctionalPackingKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>>
    LwePrivateFunctionalPackingKeyswitchKey<C>
{
    /// Mutable variant of [`LwePrivateFunctionalPackingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LwePrivateFunctionalPackingKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        LwePrivateFunctionalPackingKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// An [`LwePrivateFunctionalPackingKeyswitchKey`] owning the memory for its own storage.
pub type LwePrivateFunctionalPackingKeyswitchKeyOwned<Scalar> =
    LwePrivateFunctionalPackingKeyswitchKey<Vec<Scalar>>;
/// An [`LwePrivateFunctionalPackingKeyswitchKey`] immutably borrowing memory for its own storage.
pub type LwePrivateFunctionalPackingKeyswitchKeyView<'data, Scalar> =
    LwePrivateFunctionalPackingKeyswitchKey<&'data [Scalar]>;
/// An [`LwePrivateFunctionalPackingKeyswitchKey`] mutably borrowing memory for its own storage.
pub type LwePrivateFunctionalPackingKeyswitchKeyMutView<'data, Scalar> =
    LwePrivateFunctionalPackingKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LwePrivateFunctionalPackingKeyswitchKeyOwned<Scalar> {
    /// Create an [`LwePrivateFunctionalPackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LwePrivateFunctionalPackingKeyswitchKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_private_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_private_functional_packing_keyswitch_key`]
    /// using this key as output.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                lwe_pfpksk_size(
                    input_key_lwe_dimension.to_lwe_size(),
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
            ],
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LwePrivateFunctionalPackingKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this> = LwePrivateFunctionalPackingKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextListCreationMetadata(
            self.output_glwe_size,
            self.output_polynomial_size,
            self.ciphertext_modulus,
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LwePrivateFunctionalPackingKeyswitchKey<C>
{
    type EntityMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = LwePrivateFunctionalPackingKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}

/// Metadata used in the [`CreateFrom`] implementation to create
/// [`LwePrivateFunctionalPackingKeyswitchKey`] entities.
#[derive(Clone, Copy)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LwePrivateFunctionalPackingKeyswitchKey<C>
{
    type Metadata = LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}
