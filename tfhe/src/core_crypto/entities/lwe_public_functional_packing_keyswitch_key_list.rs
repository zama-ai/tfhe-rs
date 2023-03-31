//! Module containing the definition of the LwePublicFunctionalPackingKeyswitchKeyList.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A contiguous list containing [`LWE private functional packing keyswitch
/// keys`](`crate::core_crypto::entities::LwePrivateFunctionalPackingKeyswitchKey`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePublicFunctionalPackingKeyswitchKeyList<C: Container>
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
    for LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>>
    LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    /// Create an [`LwePublicFunctionalPackingKeyswitchKeyList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate keys
    /// in the list you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_public_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_public_functional_packing_keyswitch_key`]
    /// on the individual keys in the list.
    ///
    /// This docstring exhibits [`LwePublicFunctionalPackingKeyswitchKeyList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePublicFunctionalPackingKeyswitchKeyList creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let lwe_pubfpksk_count = FunctionalPackingKeyswitchKeyCount(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LwePublicFunctionalPackingKeyswitchKeyList
    /// let pubfpksk_list = LwePublicFunctionalPackingKeyswitchKeyList::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     glwe_size,
    ///     polynomial_size,
    ///     lwe_pubfpksk_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(
    ///     pubfpksk_list.output_glwe_key_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pubfpksk_list.output_glwe_size(), glwe_size);
    /// assert_eq!(pubfpksk_list.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pubfpksk_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(
    ///     pubfpksk_list.decomposition_level_count(),
    ///     decomp_level_count
    /// );
    /// assert_eq!(
    ///     pubfpksk_list.input_lwe_size(),
    ///     input_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(pubfpksk_list.input_lwe_key_dimension(), input_lwe_dimension);
    /// assert_eq!(pubfpksk_list.lwe_pubfpksk_count(), lwe_pubfpksk_count);
    /// assert_eq!(pubfpksk_list.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = pubfpksk_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let pubfpksk_list = LwePublicFunctionalPackingKeyswitchKeyList::from_container(
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
    ///     pubfpksk_list.output_glwe_key_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(pubfpksk_list.output_glwe_size(), glwe_size);
    /// assert_eq!(pubfpksk_list.output_polynomial_size(), polynomial_size);
    /// assert_eq!(pubfpksk_list.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(
    ///     pubfpksk_list.decomposition_level_count(),
    ///     decomp_level_count
    /// );
    /// assert_eq!(
    ///     pubfpksk_list.input_lwe_size(),
    ///     input_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(pubfpksk_list.input_lwe_key_dimension(), input_lwe_dimension);
    /// assert_eq!(pubfpksk_list.lwe_pubfpksk_count(), lwe_pubfpksk_count);
    /// assert_eq!(pubfpksk_list.ciphertext_modulus(), ciphertext_modulus);
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
                % lwe_pubfpksk_size(
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
            lwe_pubfpksk_size(
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

    /// Return the output key [`GlweDimension`] of the [`LwePublicFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`LwePublicFunctionalPackingKeyswitchKey`] stored in
    /// the list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`LwePublicFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn output_polynomial_size(&self) -> PolynomialSize {
        self.output_polynomial_size
    }

    /// Return the input key [`LweDimension`] of the [`LwePublicFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn input_lwe_key_dimension(&self) -> LweDimension {
        self.input_lwe_size.to_lwe_dimension()
    }

    /// Return the input [`LweSize`] of the [`LwePublicFunctionalPackingKeyswitchKey`]stored in the
    /// list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn input_lwe_size(&self) -> LweSize {
        self.input_lwe_size
    }

    /// Return the [`DecompositionLevelCount`] of the [`LwePublicFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`LwePublicFunctionalPackingKeyswitchKey`]
    /// stored in the list.
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the number of elements in a  [`LwePublicFunctionalPackingKeyswitchKey`]  stored in
    /// the list.
    pub fn lwe_pubfpksk_size(&self) -> usize {
        lwe_pubfpksk_size(
            self.input_lwe_size,
            self.decomp_level_count,
            self.output_glwe_size,
            self.output_polynomial_size,
        )
    }

    /// Return the [`FunctionalPackingKeyswitchKeyCount`] of the
    /// [`LwePublicFunctionalPackingKeyswitchKeyList`].
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn lwe_pubfpksk_count(&self) -> FunctionalPackingKeyswitchKeyCount {
        FunctionalPackingKeyswitchKeyCount(self.as_ref().container_len() / self.lwe_pubfpksk_size())
    }

    /// Return a view of the [`LwePublicFunctionalPackingKeyswitchKeyList`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> LwePublicFunctionalPackingKeyswitchKeyList<&'_ [Scalar]> {
        LwePublicFunctionalPackingKeyswitchKeyList::from_container(
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
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`LwePublicFunctionalPackingKeyswitchKeyList`]
    ///
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>>
    LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    /// Mutable variant of [`LwePublicFunctionalPackingKeyswitchKeyList::as_view`].
    pub fn as_mut_view(&mut self) -> LwePublicFunctionalPackingKeyswitchKeyList<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_size = self.input_lwe_size;
        let output_glwe_size = self.output_glwe_size;
        let output_polynomial_size = self.output_polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;

        LwePublicFunctionalPackingKeyswitchKeyList::from_container(
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

/// An [`LwePublicFunctionalPackingKeyswitchKeyList`] owning the memory for its own storage.
pub type LwePublicFunctionalPackingKeyswitchKeyListOwned<Scalar> =
    LwePublicFunctionalPackingKeyswitchKeyList<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LwePublicFunctionalPackingKeyswitchKeyListOwned<Scalar> {
    /// Allocate memory and create a new owned [`LwePublicFunctionalPackingKeyswitchKeyList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate keys in the list you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_public_functional_packing_keyswitch_key`] or
    /// the parallel variant
    /// [`crate::core_crypto::algorithms::par_generate_lwe_public_functional_packing_keyswitch_key`]
    /// on the individual keys in the list.
    /// See [`LwePublicFunctionalPackingKeyswitchKeyList::from_container`] for usage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_glwe_size: GlweSize,
        output_polynomial_size: PolynomialSize,
        pubfpksk_count: FunctionalPackingKeyswitchKeyCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                pubfpksk_count.0
                    * lwe_pubfpksk_size(
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
/// [`LwePublicFunctionalPackingKeyswitchKeyList`] entities.
#[derive(Clone, Copy)]
pub struct LwePublicFunctionalPackingKeyswitchKeyListCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub LweSize,
    pub GlweSize,
    pub PolynomialSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    type Metadata = LwePublicFunctionalPackingKeyswitchKeyListCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LwePublicFunctionalPackingKeyswitchKeyListCreationMetadata(
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
    for LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LwePublicFunctionalPackingKeyswitchKeyCreationMetadata<Scalar>;

    type EntityView<'this> = LwePublicFunctionalPackingKeyswitchKey<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = LwePublicFunctionalPackingKeyswitchKeyListCreationMetadata<Scalar>;

    type SelfView<'this> = LwePublicFunctionalPackingKeyswitchKeyList<&'this [Self::Element]>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LwePublicFunctionalPackingKeyswitchKeyCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.output_glwe_size(),
            self.output_polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.lwe_pubfpksk_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LwePublicFunctionalPackingKeyswitchKeyListCreationMetadata(
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
    for LwePublicFunctionalPackingKeyswitchKeyList<C>
{
    type EntityMutView<'this> = LwePublicFunctionalPackingKeyswitchKey<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this> = LwePublicFunctionalPackingKeyswitchKeyList<&'this mut [Self::Element]>
    where
        Self: 'this;
}
