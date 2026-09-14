//! Module containing the definition of the [`LweHalfProductBootstrapKey`].

use rayon::prelude::*;

use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// An [`LWE bootstrap key`](`LweBootstrapKey`) made of [`half-product GGSW
/// ciphertexts`](`HalfProductGgswCiphertext`).
///
/// The container holds exactly `input_lwe_dimension` half-product GGSW ciphertexts back to back,
/// with no padding: see [`HalfProductGgswCiphertext`] for the layout of a single one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LweHalfProductBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log_mask: DecompositionBaseLog,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_base_log_body: DecompositionBaseLog,
    decomp_level_count_body: DecompositionLevelCount,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweHalfProductBootstrapKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]>
    for LweHalfProductBootstrapKey<C>
{
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// A [`LweHalfProductBootstrapKey`] owning its memory.
pub type LweHalfProductBootstrapKeyOwned<Scalar> = LweHalfProductBootstrapKey<Vec<Scalar>>;

/// Return the number of elements in a [`LweHalfProductBootstrapKey`].
pub fn lwe_half_product_bootstrap_key_size(
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
) -> usize {
    input_lwe_dimension.0
        * half_product_ggsw_ciphertext_size(
            glwe_size,
            polynomial_size,
            decomp_level_count_mask,
            decomp_level_count_body,
        )
}

/// One child per input LWE key bit, each encrypting one [`HalfProductGgswCiphertext`].
#[allow(clippy::too_many_arguments)]
pub fn lwe_half_product_bootstrap_key_encryption_fork_config<
    Scalar,
    MaskDistribution,
    NoiseDistribution,
>(
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
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
    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        input_lwe_dimension.0,
        half_product_ggsw_ciphertext_encryption_mask_sample_count(
            glwe_size,
            polynomial_size,
            decomp_level_count_mask,
            decomp_level_count_body,
        ),
        mask_distribution,
        half_product_ggsw_ciphertext_encryption_noise_sample_count(
            glwe_size,
            polynomial_size,
            decomp_level_count_mask,
            decomp_level_count_body,
        ),
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweHalfProductBootstrapKey<C> {
    /// Create a [`LweHalfProductBootstrapKey`] from an existing container.
    ///
    /// # Panics
    ///
    /// Panics if the container length is not an exact multiple of
    /// [`half_product_ggsw_ciphertext_size`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log_mask: DecompositionBaseLog,
        decomp_level_count_mask: DecompositionLevelCount,
        decomp_base_log_body: DecompositionBaseLog,
        decomp_level_count_body: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        let ggsw_size = half_product_ggsw_ciphertext_size(
            glwe_size,
            polynomial_size,
            decomp_level_count_mask,
            decomp_level_count_body,
        );
        assert!(
            container.container_len().is_multiple_of(ggsw_size),
            "The provided container length is not valid. \
            It needs to be dividable by the half-product GGSW ciphertext size: {ggsw_size}. \
            Got container length: {}.",
            container.container_len(),
        );

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log_mask,
            decomp_level_count_mask,
            decomp_base_log_body,
            decomp_level_count_body,
            ciphertext_modulus,
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    pub fn decomposition_base_log_mask(&self) -> DecompositionBaseLog {
        self.decomp_base_log_mask
    }

    pub fn decomposition_level_count_mask(&self) -> DecompositionLevelCount {
        self.decomp_level_count_mask
    }

    pub fn decomposition_base_log_body(&self) -> DecompositionBaseLog {
        self.decomp_base_log_body
    }

    pub fn decomposition_level_count_body(&self) -> DecompositionLevelCount {
        self.decomp_level_count_body
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
    }

    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.half_product_ggsw_ciphertext_size())
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.glwe_size.to_glwe_dimension().0 * self.polynomial_size.0)
    }

    pub fn half_product_ggsw_ciphertext_size(&self) -> usize {
        half_product_ggsw_ciphertext_size(
            self.glwe_size,
            self.polynomial_size,
            self.decomp_level_count_mask,
            self.decomp_level_count_body,
        )
    }

    /// Iterate over the [`half-product GGSW ciphertexts`](`HalfProductGgswCiphertext`) of the key.
    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = HalfProductGgswCiphertextView<'_, Scalar>>
           + ExactSizeIterator<Item = HalfProductGgswCiphertextView<'_, Scalar>> {
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let decomp_base_log_mask = self.decomp_base_log_mask;
        let decomp_level_count_mask = self.decomp_level_count_mask;
        let decomp_base_log_body = self.decomp_base_log_body;
        let decomp_level_count_body = self.decomp_level_count_body;
        let ciphertext_modulus = self.ciphertext_modulus;

        self.as_ref()
            .into_chunks(self.half_product_ggsw_ciphertext_size())
            .map(move |slice| {
                HalfProductGgswCiphertextView::from_container(
                    slice,
                    glwe_size,
                    polynomial_size,
                    decomp_base_log_mask,
                    decomp_level_count_mask,
                    decomp_base_log_body,
                    decomp_level_count_body,
                    ciphertext_modulus,
                )
            })
    }

    pub fn as_view(&self) -> LweHalfProductBootstrapKey<&[Scalar]> {
        LweHalfProductBootstrapKey::from_container(
            self.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.decomp_base_log_mask,
            self.decomp_level_count_mask,
            self.decomp_base_log_body,
            self.decomp_level_count_body,
            self.ciphertext_modulus,
        )
    }

    pub fn into_container(self) -> C {
        self.data
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
        lwe_half_product_bootstrap_key_encryption_fork_config(
            self.input_lwe_dimension(),
            self.glwe_size,
            self.polynomial_size,
            self.decomp_level_count_mask,
            self.decomp_level_count_body,
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweHalfProductBootstrapKey<C> {
    /// Mutable variant of [`LweHalfProductBootstrapKey::iter`].
    pub fn iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = HalfProductGgswCiphertextMutView<'_, Scalar>>
           + ExactSizeIterator<Item = HalfProductGgswCiphertextMutView<'_, Scalar>> {
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let decomp_base_log_mask = self.decomp_base_log_mask;
        let decomp_level_count_mask = self.decomp_level_count_mask;
        let decomp_base_log_body = self.decomp_base_log_body;
        let decomp_level_count_body = self.decomp_level_count_body;
        let ciphertext_modulus = self.ciphertext_modulus;
        let ggsw_size = self.half_product_ggsw_ciphertext_size();

        self.as_mut().into_chunks(ggsw_size).map(move |slice| {
            HalfProductGgswCiphertextMutView::from_container(
                slice,
                glwe_size,
                polynomial_size,
                decomp_base_log_mask,
                decomp_level_count_mask,
                decomp_base_log_body,
                decomp_level_count_body,
                ciphertext_modulus,
            )
        })
    }

    /// Parallel variant of [`LweHalfProductBootstrapKey::iter_mut`].
    pub fn par_iter_mut(
        &mut self,
    ) -> impl IndexedParallelIterator<Item = HalfProductGgswCiphertextMutView<'_, Scalar>>
    where
        Scalar: Send + Sync,
    {
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let decomp_base_log_mask = self.decomp_base_log_mask;
        let decomp_level_count_mask = self.decomp_level_count_mask;
        let decomp_base_log_body = self.decomp_base_log_body;
        let decomp_level_count_body = self.decomp_level_count_body;
        let ciphertext_modulus = self.ciphertext_modulus;
        let ggsw_size = self.half_product_ggsw_ciphertext_size();

        self.as_mut()
            .par_chunks_exact_mut(ggsw_size)
            .map(move |slice| {
                HalfProductGgswCiphertextMutView::from_container(
                    slice,
                    glwe_size,
                    polynomial_size,
                    decomp_base_log_mask,
                    decomp_level_count_mask,
                    decomp_base_log_body,
                    decomp_level_count_body,
                    ciphertext_modulus,
                )
            })
    }
}

impl<Scalar: UnsignedInteger> LweHalfProductBootstrapKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweHalfProductBootstrapKey`].
    ///
    /// This function only allocates memory, if you want to generate a bootstrap key you need to
    /// use
    /// [`crate::core_crypto::algorithms::par_generate_new_half_product_lwe_bootstrap_key`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
        input_lwe_dimension: LweDimension,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log_mask: DecompositionBaseLog,
        decomp_level_count_mask: DecompositionLevelCount,
        decomp_base_log_body: DecompositionBaseLog,
        decomp_level_count_body: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                lwe_half_product_bootstrap_key_size(
                    input_lwe_dimension,
                    glwe_size,
                    polynomial_size,
                    decomp_level_count_mask,
                    decomp_level_count_body,
                )
            ],
            glwe_size,
            polynomial_size,
            decomp_base_log_mask,
            decomp_level_count_mask,
            decomp_base_log_body,
            decomp_level_count_body,
            ciphertext_modulus,
        )
    }
}
