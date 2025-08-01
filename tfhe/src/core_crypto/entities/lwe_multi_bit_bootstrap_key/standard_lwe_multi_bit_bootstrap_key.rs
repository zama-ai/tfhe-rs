use crate::core_crypto::backward_compatibility::entities::lwe_multi_bit_bootstrap_key::LweMultiBitBootstrapKeyVersions;
use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

use tfhe_versionable::Versionize;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweMultiBitBootstrapKeyVersions)]
pub struct LweMultiBitBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    // An LweMultiBitBootstrapKey is literally a GgswCiphertextList, so we wrap a
    // GgswCiphertextList and use Deref to have access to all the primitives of the
    // GgswCiphertextList easily
    ggsw_list: GgswCiphertextList<C>,
    grouping_factor: LweBskGroupingFactor,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> std::ops::Deref
    for LweMultiBitBootstrapKey<C>
{
    type Target = GgswCiphertextList<C>;

    fn deref(&self) -> &GgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> std::ops::DerefMut
    for LweMultiBitBootstrapKey<C>
{
    fn deref_mut(&mut self) -> &mut GgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

#[allow(clippy::too_many_arguments)]
pub fn lwe_multi_bit_bootstrap_key_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomposition_level_count: DecompositionLevelCount,
    grouping_factor: LweBskGroupingFactor,
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
    let ggsw_group_mask_sample_count = grouping_factor.ggsw_per_multi_bit_element().0
        * ggsw_ciphertext_encryption_mask_sample_count(
            glwe_size,
            polynomial_size,
            decomposition_level_count,
        );

    let ggsw_group_noise_sample_count = grouping_factor.ggsw_per_multi_bit_element().0
        * ggsw_ciphertext_encryption_noise_sample_count(
            glwe_size,
            polynomial_size,
            decomposition_level_count,
        );

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        input_lwe_dimension.0,
        ggsw_group_mask_sample_count,
        mask_distribution,
        ggsw_group_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweMultiBitBootstrapKey<C> {
    /// Create an [`LweMultiBitBootstrapKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an LWE
    /// bootstrap key you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_multi_bit_bootstrap_key`] or its parallel
    /// equivalent [`crate::core_crypto::algorithms::par_generate_lwe_multi_bit_bootstrap_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`LweMultiBitBootstrapKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweMultiBitBootstrapKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let grouping_factor = LweBskGroupingFactor(2);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweMultiBitBootstrapKey
    /// let bsk = LweMultiBitBootstrapKey::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     grouping_factor,
    ///     ciphertext_modulus,
    /// );
    ///
    /// // These methods are "inherited" from GgswCiphertextList and are accessed through the Deref
    /// // trait
    /// assert_eq!(bsk.glwe_size(), glwe_size);
    /// assert_eq!(bsk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // These methods are specific to the LweMultiBitBootstrapKey
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.multi_bit_input_lwe_dimension(),
    ///     LweDimension(input_lwe_dimension.0 / grouping_factor.0)
    /// );
    /// assert_eq!(
    ///     bsk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    /// assert_eq!(bsk.grouping_factor(), grouping_factor);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = bsk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let bsk = LweMultiBitBootstrapKey::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     grouping_factor,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(bsk.glwe_size(), glwe_size);
    /// assert_eq!(bsk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.multi_bit_input_lwe_dimension(),
    ///     LweDimension(input_lwe_dimension.0 / grouping_factor.0)
    /// );
    /// assert_eq!(
    ///     bsk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    /// assert_eq!(bsk.grouping_factor(), grouping_factor);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        grouping_factor: LweBskGroupingFactor,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        let bsk = Self {
            ggsw_list: GgswCiphertextList::from_container(
                container,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                ciphertext_modulus,
            ),
            grouping_factor,
        };
        assert!(
            bsk.input_lwe_dimension().0 % grouping_factor.0 == 0,
            "Input LWE dimension ({}) of the bootstrap key needs to be a multiple of {}",
            bsk.input_lwe_dimension().0,
            grouping_factor.0,
        );
        bsk
    }

    /// Return the [`LweDimension`] of the input [`LweSecretKey`].
    ///
    /// See [`LweMultiBitBootstrapKey::from_container`] for usage.
    pub fn input_lwe_dimension(&self) -> LweDimension {
        let grouping_factor = self.grouping_factor;
        let ggsw_per_multi_bit_element = grouping_factor.ggsw_per_multi_bit_element();
        LweDimension(
            self.ggsw_ciphertext_count().0 * grouping_factor.0 / ggsw_per_multi_bit_element.0,
        )
    }

    /// Return the [`LweDimension`] of the input [`LweSecretKey`] taking into consideration the
    /// grouping factor. This essentially returns the input [`LweDimension`] divided by the grouping
    /// factor.
    ///
    /// See [`LweMultiBitBootstrapKey::from_container`] for usage.
    pub fn multi_bit_input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.input_lwe_dimension().0 / self.grouping_factor.0)
    }

    /// Return the [`LweDimension`] of the equivalent output [`LweSecretKey`].
    ///
    /// See [`LweMultiBitBootstrapKey::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    /// Return the [`LweBskGroupingFactor`] of the current [`LweMultiBitBootstrapKey`].
    ///
    /// See [`LweMultiBitBootstrapKey::from_container`] for usage.
    pub fn grouping_factor(&self) -> LweBskGroupingFactor {
        self.grouping_factor
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweMultiBitBootstrapKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    /// Return a view of the [`LweMultiBitBootstrapKey`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> LweMultiBitBootstrapKey<&'_ [Scalar]> {
        LweMultiBitBootstrapKey::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.grouping_factor(),
            self.ciphertext_modulus(),
        )
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
        lwe_multi_bit_bootstrap_key_fork_config(
            self.input_lwe_dimension(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_level_count(),
            self.grouping_factor(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweMultiBitBootstrapKey<C> {
    /// Mutable variant of [`LweMultiBitBootstrapKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweMultiBitBootstrapKey<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        let grouping_factor = self.grouping_factor();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweMultiBitBootstrapKey::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            grouping_factor,
            ciphertext_modulus,
        )
    }
}

/// An [`LweMultiBitBootstrapKey`] owning the memory for its own storage.
pub type LweMultiBitBootstrapKeyOwned<Scalar> = LweMultiBitBootstrapKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LweMultiBitBootstrapKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweMultiBitBootstrapKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an LWE bootstrap key you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_bootstrap_key`] or its parallel
    /// equivalent [`crate::core_crypto::algorithms::par_generate_lwe_bootstrap_key`] using this
    /// key as output.
    ///
    /// See [`LweMultiBitBootstrapKey::from_container`] for usage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        grouping_factor: LweBskGroupingFactor,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            input_lwe_dimension.0 % grouping_factor.0 == 0,
            "Multi Bit BSK requires input LWE dimension ({}) to be a multiple of {}",
            input_lwe_dimension.0,
            grouping_factor.0
        );
        let equivalent_multi_bit_dimension = input_lwe_dimension.0 / grouping_factor.0;

        LweMultiBitBootstrapKeyOwned {
            ggsw_list: GgswCiphertextList::new(
                fill_with,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(
                    equivalent_multi_bit_dimension * grouping_factor.ggsw_per_multi_bit_element().0,
                ),
                ciphertext_modulus,
            ),
            grouping_factor,
        }
    }
}

#[derive(Copy, Clone)]
pub struct MultiBitBootstrapKeyConformanceParams<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub grouping_factor: LweBskGroupingFactor,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}
