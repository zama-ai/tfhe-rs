//! Module containing the definition of the LwePublicFunctionalPackingKeyswitchKey.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`LWE public functional packing keyswitch key`](`LwePublicFunctionalPackingKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePublicFunctionalPackingKeyswitchKey<C: Container>
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
    for LwePublicFunctionalPackingKeyswitchKey<C>
{
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LwePublicFunctionalPackingKeyswitchKey<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of a list of input [`LweSecretKey`] elements for
/// a [`LwePublicFunctionalPackingKeyswitchKey`] given a [`DecompositionLevelCount`] and output
/// [`GlweSize`] and [`PolynomialSize`].
pub fn lwe_pubfpksk_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_glwe_size.0 * output_polynomial_size.0
}

/// Return the number of elements in an [`LwePublicFunctionalPackingKeyswitchKey`] given an input
/// ['size of the list of LWe] [`LweSize`], [`DecompositionLevelCount`], output [`GlweSize`], and
/// output [`PolynomialSize`].
pub fn lwe_pubfpksk_size(
    input_lwe_size: LweSize,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
) -> usize {
    input_lwe_size.0
        * lwe_pubfpksk_input_key_element_encrypted_size(
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
        )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>>
    LwePublicFunctionalPackingKeyswitchKey<C>
{
    /// Create an [`LwePublicFunctionalPackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LwePublicFunctionalPackingKeyswitchKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_public_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_public_functional_packing_keyswitch_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`LwePublicFunctionalPackingKeyswitchKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePublicFunctionalPackingKeyswitchKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LwePublicFunctionalPackingKeyswitchKey
    /// let pubfpksk = LwePublicFunctionalPackingKeyswitchKey::new(
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
    ///     pubfpksk.output_glwe_key_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pubfpksk.output_glwe_size(), glwe_size);
    /// assert_eq!(pubfpksk.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pubfpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pubfpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pubfpksk.input_lwe_key_dimension(), input_lwe_dimension);
    /// assert_eq!(pubfpksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = pubfpksk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let pubfpksk = LwePublicFunctionalPackingKeyswitchKeyList::from_container(
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
    ///     pubfpksk.output_glwe_key_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pubfpksk.output_glwe_size(), glwe_size);
    /// assert_eq!(pubfpksk.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pubfpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pubfpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(pubfpksk.input_lwe_key_dimension(), input_lwe_dimension);
    /// assert_eq!(pubfpksk.ciphertext_modulus(), ciphertext_modulus);
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
                % lwe_pubfpksk_input_key_element_encrypted_size(
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
            lwe_pubfpksk_input_key_element_encrypted_size(
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

    /// Return the output key [`GlweDimension`] of the [`LwePublicFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`LwePublicFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`LwePublicFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the input key [`LweDimension`] of the [`LwePublicFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn input_lwe_key_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.input_key_element_encrypted_size() - 1)
    }

    /// Return the [`DecompositionLevelCount`] of the [`LwePublicFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`LwePublicFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LwePublicFunctionalPackingKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_pubfpksk_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Return a view of the [`LwePublicFunctionalPackingKeyswitchKey`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> LwePublicFunctionalPackingKeyswitchKey<&'_ [Scalar]> {
        LwePublicFunctionalPackingKeyswitchKey::from_container(
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
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`LwePublicFunctionalPackingKeyswitchKey`]
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>>
    LwePublicFunctionalPackingKeyswitchKey<C>
{
    /// Mutable variant of [`LwePublicFunctionalPackingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LwePublicFunctionalPackingKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        LwePublicFunctionalPackingKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// An [`LwePublicFunctionalPackingKeyswitchKey`] owning the memory for its own storage.
pub type LwePublicFunctionalPackingKeyswitchKeyOwned<Scalar> =
    LwePublicFunctionalPackingKeyswitchKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LwePublicFunctionalPackingKeyswitchKeyOwned<Scalar> {
    /// Create an [`LwePublicFunctionalPackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LwePublicFunctionalPackingKeyswitchKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_public_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_public_functional_packing_keyswitch_key`]
    /// using this key as output.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKey::from_container`] for usage.
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
                lwe_pubfpksk_size(
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
    for LwePublicFunctionalPackingKeyswitchKey<C>
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
        GlweCiphertextListCreationMetadata(
            self.output_glwe_size,
            self.output_polynomial_size,
            self.ciphertext_modulus,
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`LwePublicFunctionalPackingKeyswitchKey`]. At the moment it does not
    /// make sense to return "sub" packing keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for LwePublicFunctionalPackingKeyswitchKey. \
        At the moment it does not make sense to return 'sub' packing keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LwePublicFunctionalPackingKeyswitchKey<C>
{
    type EntityMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" packing keyswitch keys. So we use a
    // dummy placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}

/// Metadata used in the [`CreateFrom`] implementation to create
/// [`LwePublicFunctionalPackingKeyswitchKey`] entities.
#[derive(Clone, Copy)]
pub struct LwePublicFunctionalPackingKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LwePublicFunctionalPackingKeyswitchKey<C>
{
    type Metadata = LwePublicFunctionalPackingKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LwePublicFunctionalPackingKeyswitchKeyCreationMetadata(
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
