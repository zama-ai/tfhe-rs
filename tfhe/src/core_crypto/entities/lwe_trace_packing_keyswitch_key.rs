//! Module containing the definition of the [`LweTracePackingKeyswitchKey`].

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// An [`LWE trace packing keyswitch key`](`LweTracePackingKeyswitchKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweTracePackingKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_size: LweSize,
    output_glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweTracePackingKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LweTracePackingKeyswitchKey<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`GlweSecretKey`] element for a
/// [`LweTracePackingKeyswitchKey`] given a [`DecompositionLevelCount`] and output
/// [`GlweSize`] and [`PolynomialSize`].
pub fn lwe_tpksk_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_glwe_size.0 * polynomial_size.0
}

/// Return the number of elements in an [`LweTracePackingKeyswitchKey`] given a
/// [`DecompositionLevelCount`], output [`GlweSize`], and output [`PolynomialSize`].
pub fn lwe_tpksk_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> usize {
    output_glwe_size.to_glwe_dimension().0
        * polynomial_size.log2().0
        * lwe_tpksk_input_key_element_encrypted_size(
            decomp_level_count,
            output_glwe_size,
            polynomial_size,
        )
}

pub fn tpksk_encryption_mask_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> EncryptionMaskSampleCount {
    decomp_level_count.0
        * glwe_size.to_glwe_dimension().0
        * glwe_ciphertext_encryption_mask_sample_count(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
        )
}

pub fn tpksk_encryption_noise_sample_count(
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> EncryptionNoiseSampleCount {
    decomp_level_count.0 * glwe_ciphertext_encryption_noise_sample_count(polynomial_size)
}

pub fn lwe_trace_packing_keyswitch_key_encryption_fork_config<
    Scalar,
    MaskDistribution,
    NoiseDistribution,
>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level_count: DecompositionLevelCount,
    mask_distribution: MaskDistribution,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> EncryptionRandomGeneratorForkConfig
where
    Scalar: UnsignedInteger
        + RandomGenerable<MaskDistribution, CustomModulus = Scalar>
        + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    MaskDistribution: Distribution,
    NoiseDistribution: Distribution,
{
    let tpksk_mask_sample_count =
        tpksk_encryption_mask_sample_count(glwe_size, polynomial_size, decomposition_level_count);
    let tpksk_noise_sample_count =
        tpksk_encryption_noise_sample_count(polynomial_size, decomposition_level_count);

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        polynomial_size.log2().0,
        tpksk_mask_sample_count,
        mask_distribution,
        tpksk_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweTracePackingKeyswitchKey<C> {
    /// Create an [`LweTracePackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LweTracePackingKeyswitchKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_trace_packing_keyswitch_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`LweTracePackingKeyswitchKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweTracePackingKeyswitchKey creation
    /// let lwe_size = LweSize(1001);
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweTracePackingKeyswitchKey
    /// let tpksk = LweTracePackingKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     lwe_size,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(
    ///     tpksk.output_glwe_key_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(tpksk.output_glwe_size(), glwe_size);
    /// assert_eq!(tpksk.polynomial_size(), polynomial_size);
    /// assert_eq!(tpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(tpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(tpksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = tpksk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let tpksk = LweTracePackingKeyswitchKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     lwe_size,
    ///     glwe_size,
    ///     polynomial_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(
    ///     tpksk.output_glwe_key_dimension(),
    ///     glwe_size.to_glwe_dimension()
    /// );
    /// assert_eq!(tpksk.input_lwe_size(), lwe_size);
    /// assert_eq!(tpksk.output_glwe_size(), glwe_size);
    /// assert_eq!(tpksk.polynomial_size(), polynomial_size);
    /// assert_eq!(tpksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(tpksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(tpksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_size: LweSize,
        output_glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a LweTracePackingKeyswitchKey"
        );
        assert!(
            container.container_len()
                % lwe_tpksk_input_key_element_encrypted_size(
                    decomp_level_count,
                    output_glwe_size,
                    polynomial_size
                )
                == 0,
            "The provided container length is not valid. \
        It needs to be divisible by decomp_level_count * output_glwe_size * polynomial_size:\
         {}. Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_glwe_size: {output_glwe_size:?}, polynomial_size: \
        {polynomial_size:?}.",
            lwe_tpksk_input_key_element_encrypted_size(
                decomp_level_count,
                output_glwe_size,
                polynomial_size
            ),
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the output key [`GlweDimension`] of the [`LweTracePackingKeyswitchKey`].
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_key_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`LweTracePackingKeyswitchKey`].
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the output [`PolynomialSize`] of the [`LweTracePackingKeyswitchKey`].
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the input [`LweSize`] of the [`LweTracePackingKeyswitchKey`].
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn input_lwe_size(&self) -> LweSize {
        self.input_lwe_size
    }

    /// Return the [`DecompositionLevelCount`] of the [`LweTracePackingKeyswitchKey`].
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the [`DecompositionBaseLog`] of the [`LweTracePackingKeyswitchKey`].
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LweTracePackingKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_tpksk_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_glwe_size,
            self.polynomial_size,
        )
    }

    /// Return a view of the [`LweTracePackingKeyswitchKey`]. This is useful if an
    /// algorithm takes a view by value.
    pub fn as_view(&self) -> LweTracePackingKeyswitchKey<&'_ [Scalar]> {
        LweTracePackingKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_size,
            self.output_glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_glwe_ciphertext_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.output_glwe_size(),
            self.polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    /// Return the [`CiphertextModulus`] of the [`LweTracePackingKeyswitchKey`]
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn encryption_fork_config<MaskDistribution, NoiseDistribution>(
        &self,
        mask_distribution: MaskDistribution,
        noise_distribution: NoiseDistribution,
    ) -> EncryptionRandomGeneratorForkConfig
    where
        MaskDistribution: Distribution,
        NoiseDistribution: Distribution,
        Scalar: RandomGenerable<MaskDistribution, CustomModulus = Scalar>
            + RandomGenerable<NoiseDistribution, CustomModulus = Scalar>,
    {
        lwe_trace_packing_keyswitch_key_encryption_fork_config(
            self.output_glwe_size(),
            self.polynomial_size(),
            self.decomposition_level_count(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweTracePackingKeyswitchKey<C> {
    /// Mutable variant of [`LweTracePackingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweTracePackingKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_size = self.input_lwe_size;
        let output_glwe_size = self.output_glwe_size;
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        LweTracePackingKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_glwe_ciphertext_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let output_glwe_size = self.output_glwe_size();
        let output_polynomial_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        )
    }
}

/// An [`LweTracePackingKeyswitchKey`] owning the memory for its own storage.
pub type LweTracePackingKeyswitchKeyOwned<Scalar> = LweTracePackingKeyswitchKey<Vec<Scalar>>;
/// An [`LweTracePackingKeyswitchKey`] immutably borrowing memory for its own storage.
pub type LweTracePackingKeyswitchKeyView<'data, Scalar> =
    LweTracePackingKeyswitchKey<&'data [Scalar]>;
/// An [`LweTracePackingKeyswitchKey`] mutably borrowing memory for its own storage.
pub type LweTracePackingKeyswitchKeyMutView<'data, Scalar> =
    LweTracePackingKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweTracePackingKeyswitchKeyOwned<Scalar> {
    /// Create an [`LweTracePackingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LweTracePackingKeyswitchKey`] you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_trace_packing_keyswitch_key`]
    /// using this key as output.
    ///
    /// See [`LweTracePackingKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_size: LweSize,
        output_glwe_size: GlweSize,
        poly_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; lwe_tpksk_size(decomp_level_count, output_glwe_size, poly_size)],
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            poly_size,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create
/// [`LweTracePackingKeyswitchKey`] entities.
#[derive(Clone, Copy)]
pub struct LweTracePackingKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_size: LweSize,
    pub output_glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for LweTracePackingKeyswitchKey<C>
{
    type Metadata = LweTracePackingKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LweTracePackingKeyswitchKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LweTracePackingKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Scalar>;

    type EntityView<'this>
        = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LweTracePackingKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = LweTracePackingKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GlweCiphertextListCreationMetadata {
            glwe_size: self.output_glwe_size(),
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size() * self.output_glwe_size.to_glwe_dimension().0
    }

    /// Unimplemented for [`LweTracePackingKeyswitchKey`]. At the moment it does not
    /// make sense to return "sub" packing keyswitch keys.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LweTracePackingKeyswitchKeyCreationMetadata {
            decomp_base_log: self.decomposition_base_log(),
            decomp_level_count: self.decomposition_level_count(),
            input_lwe_size: self.input_lwe_size(),
            output_glwe_size: self.output_glwe_size(),
            polynomial_size: self.polynomial_size(),
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LweTracePackingKeyswitchKey<C>
{
    type EntityMutView<'this>
        = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = LweTracePackingKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}

pub struct LweTracePackingKeyswitchKeyConformanceParams {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_size: LweSize,
    pub output_glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

impl<C: Container<Element = u64>> ParameterSetConformant for LweTracePackingKeyswitchKey<C> {
    type ParameterSet = LweTracePackingKeyswitchKeyConformanceParams;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            input_lwe_size,
            output_glwe_size,
            polynomial_size,
            ciphertext_modulus,
        } = self;

        *ciphertext_modulus == parameter_set.ciphertext_modulus
            && data.container_len()
                == lwe_tpksk_size(
                    parameter_set.decomp_level_count,
                    parameter_set.output_glwe_size,
                    parameter_set.polynomial_size,
                )
            && *decomp_base_log == parameter_set.decomp_base_log
            && *decomp_level_count == parameter_set.decomp_level_count
            && *input_lwe_size == parameter_set.input_lwe_size
            && *output_glwe_size == parameter_set.output_glwe_size
            && *polynomial_size == parameter_set.polynomial_size
    }
}
