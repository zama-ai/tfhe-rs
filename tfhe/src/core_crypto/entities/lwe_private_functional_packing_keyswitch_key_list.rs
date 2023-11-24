//! Module containing the definition of the LwePrivateFunctionalPackingKeyswitchKeyList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing [`LWE private functional packing keyswitch
/// keys`](`crate::core_crypto::entities::LwePrivateFunctionalPackingKeyswitchKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyList<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_size: LweSize,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]>
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>>
    LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    /// Create an [`LwePrivateFunctionalPackingKeyswitchKeyList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate keys
    /// in the list you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_private_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_private_functional_packing_keyswitch_key`]
    /// on the individual keys in the list. Alternatively if you need to generate a list of keys for
    /// use with the [`crate::core_crypto::algorithms::lwe_wopbs`] primitives you can use
    /// [`crate::core_crypto::algorithms::generate_circuit_bootstrap_lwe_pfpksk_list`] or its
    /// parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_circuit_bootstrap_lwe_pfpksk_list`].
    ///
    /// This docstring exhibits [`LwePrivateFunctionalPackingKeyswitchKeyList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePrivateFunctionalPackingKeyswitchKeyList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let lwe_pfpksk_count = FunctionalPackingKeyswitchKeyCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LwePrivateFunctionalPackingKeyswitchKeyList
    /// let pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyList::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     glwe_size,
    ///     polynomial_size,
    ///     lwe_pfpksk_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(
    ///     pfpksk_list.output_key_glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pfpksk_list.output_glwe_size(), glwe_size);
    /// assert_eq!(pfpksk_list.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pfpksk_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(
    ///     pfpksk_list.input_lwe_size(),
    ///     input_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(pfpksk_list.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(pfpksk_list.lwe_pfpksk_count(), lwe_pfpksk_count);
    /// assert_eq!(pfpksk_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = pfpksk_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let pfpksk_list = LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
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
    ///     pfpksk_list.output_key_glwe_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pfpksk_list.output_glwe_size(), glwe_size);
    /// assert_eq!(pfpksk_list.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pfpksk_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(pfpksk_list.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(
    ///     pfpksk_list.input_lwe_size(),
    ///     input_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(pfpksk_list.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(pfpksk_list.lwe_pfpksk_count(), lwe_pfpksk_count);
    /// assert_eq!(pfpksk_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_size: LweSize,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len()
                % lwe_pfpksk_size(
                    input_lwe_size,
                    decomp_level_count,
                    output_glwe_size,
                    output_polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by input_lwe_size * decomp_level_count * output_glwe_size * \
        output_polynomial_size: {}. Got container length: {} and input_lwe_size: {input_lwe_size:?}\
         decomp_level_count: {decomp_level_count:?},  output_glwe_size: {output_glwe_size:?}, \
        output_polynomial_size: {output_polynomial_size:?}.",
            lwe_pfpksk_size(
                input_lwe_size,
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
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the output key [`GlweDimension`] of the [`LwePrivateFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn output_key_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`LwePrivateFunctionalPackingKeyswitchKey`] stored in
    /// the list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`LwePrivateFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the input key [`LweDimension`] of the [`LwePrivateFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_size.to_lwe_dimension()
    }

    /// Return the input [`LweSize`] of the [`LwePrivateFunctionalPackingKeyswitchKey`]stored in the
    /// list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn input_lwe_size(&self) -> LweSize {
        self.input_lwe_size
    }

    /// Return the [`DecompositionLevelCount`] of the [`LwePrivateFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`LwePrivateFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`CiphertextModulus`] of the [`LwePrivateFunctionalPackingKeyswitchKey`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return the number of elements in a  [`LwePrivateFunctionalPackingKeyswitchKey`]  stored in
    /// the list.
    pub fn lwe_pfpksk_size(&self) -> usize {
        lwe_pfpksk_size(
            self.input_lwe_size,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Return the [`FunctionalPackingKeyswitchKeyCount`] of the
    /// [`LwePrivateFunctionalPackingKeyswitchKeyList`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn lwe_pfpksk_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        FunctionalPackingKeyswitchKeyCount(self.as_ref().container_len() / self.lwe_pfpksk_size())
    }

    /// Return a view of the [`LwePrivateFunctionalPackingKeyswitchKeyList`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> LwePrivateFunctionalPackingKeyswitchKeyList<&'_ [Scalar]> {
        LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_size,
            self.output_glwe_size,
            self.output_polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>>
    LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    /// Mutable variant of [`LwePrivateFunctionalPackingKeyswitchKeyList::as_view`].
    pub fn as_mut_view(&mut self) -> LwePrivateFunctionalPackingKeyswitchKeyList<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_size = self.input_lwe_size;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        LwePrivateFunctionalPackingKeyswitchKeyList::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// An [`LwePrivateFunctionalPackingKeyswitchKeyList`] owning the memory for its own storage.
pub type LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar> =
    LwePrivateFunctionalPackingKeyswitchKeyList<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LwePrivateFunctionalPackingKeyswitchKeyListOwned<Scalar> {
    /// Allocate memory and create a new owned [`LwePrivateFunctionalPackingKeyswitchKeyList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate keys in the list you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_private_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_private_functional_packing_keyswitch_key`]
    /// on the individual keys in the list. Alternatively if you need to generate a list of keys for
    /// use with the [`crate::core_crypto::algorithms::lwe_wopbs`] primitives you can use
    /// [`crate::core_crypto::algorithms::generate_circuit_bootstrap_lwe_pfpksk_list`] or its
    /// parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_circuit_bootstrap_lwe_pfpksk_list`].
    ///
    /// See [`LwePrivateFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        pfpksk_count: FunctionalPackingKeyswitchKeyCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                pfpksk_count.0
                    * lwe_pfpksk_size(
                        input_key_lwe_dimension.to_lwe_size(),
                        decomp_level_count,
                        output_glwe_size,
                        output_polynomial_size
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension.to_lwe_size(),
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create
/// [`LwePrivateFunctionalPackingKeyswitchKeyList`] entities.
#[derive(Clone, Copy)]
pub struct LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub LweSize,
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    type Metadata = LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    type Element = C::Element;

    type EntityViewMetadata =
        LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata<Self::Element>;

    type EntityView<'this> = LwePrivateFunctionalPackingKeyswitchKey<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata =
        LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata<Self::Element>;

    type SelfView<'this> = LwePrivateFunctionalPackingKeyswitchKeyList<&'this [Self::Element]>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LwePrivateFunctionalPackingKeyswitchKeyCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_pfpksk_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LwePrivateFunctionalPackingKeyswitchKeyListCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.input_lwe_size(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LwePrivateFunctionalPackingKeyswitchKeyList<C>
{
    type EntityMutView<'this> = LwePrivateFunctionalPackingKeyswitchKey<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = LwePrivateFunctionalPackingKeyswitchKeyList<&'this mut [Self::Element]>
    where
        Self: 'this;
}
