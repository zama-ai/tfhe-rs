//! Module containing the definition of the [`HalfProductGgswCiphertext`].

use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A "half-product" GGSW ciphertext.
///
/// A standard GGSW ciphertext is made of `k + 1` GLev ciphertexts, all sharing the same
/// decomposition parameters.
/// The half-product variant lets the last GLev
/// — the one multiplied by the body of the input GLWE during the external product —
/// use its own, typically lighter (level_count_body < level_count_mask), decomposition parameters:
///
/// * the `k` mask GLev ciphertexts use `(base_log_mask, level_count_mask)`,
/// * the body GLev ciphertext uses `(base_log_body, level_count_body)`.
///
/// The rows that a standard GGSW would hold for body levels beyond `level_count_body` are simply
/// absent, which is where the size and latency gain comes from.
///
/// # Memory layout
///
/// The container holds exactly [`half_product_ggsw_ciphertext_row_count`] GLWE ciphertexts, the
/// mask block first, level-major within each block:
///
/// ```text
/// [ level l_msk: rows 0..k-1 ] .. [ level 1: rows 0..k-1 ] [ level l_body ] .. [ level 1 ]
/// |<---------------- k * l_msk GLWE ciphertexts ---------->|<---- l_body GLWE ciphertexts -->|
/// ```
///
/// Levels are stored in decreasing order, matching the order in which
/// [`crate::core_crypto::commons::math::decomposition::SignedDecomposer`] yields its terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalfProductGgswCiphertext<C: Container>
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

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for HalfProductGgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for HalfProductGgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// A [`HalfProductGgswCiphertext`] owning its memory.
pub type HalfProductGgswCiphertextOwned<Scalar> = HalfProductGgswCiphertext<Vec<Scalar>>;
/// A [`HalfProductGgswCiphertext`] borrowing its memory.
pub type HalfProductGgswCiphertextView<'data, Scalar> = HalfProductGgswCiphertext<&'data [Scalar]>;
/// A [`HalfProductGgswCiphertext`] mutably borrowing its memory.
pub type HalfProductGgswCiphertextMutView<'data, Scalar> =
    HalfProductGgswCiphertext<&'data mut [Scalar]>;

/// Return the number of GLWE ciphertexts in a [`HalfProductGgswCiphertext`].
pub fn half_product_ggsw_ciphertext_row_count(
    glwe_size: GlweSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
) -> usize {
    glwe_size.to_glwe_dimension().0 * decomp_level_count_mask.0 + decomp_level_count_body.0
}

/// Return the number of GLWE ciphertexts in the mask block of a [`HalfProductGgswCiphertext`].
pub fn half_product_ggsw_ciphertext_mask_row_count(
    glwe_size: GlweSize,
    decomp_level_count_mask: DecompositionLevelCount,
) -> usize {
    glwe_size.to_glwe_dimension().0 * decomp_level_count_mask.0
}

/// Return the number of elements in a [`HalfProductGgswCiphertext`].
pub fn half_product_ggsw_ciphertext_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
) -> usize {
    half_product_ggsw_ciphertext_row_count(
        glwe_size,
        decomp_level_count_mask,
        decomp_level_count_body,
    ) * glwe_ciphertext_size(glwe_size, polynomial_size)
}

/// Return the number of elements in the Fourier domain representation of a
/// [`HalfProductGgswCiphertext`].
pub fn fourier_half_product_ggsw_ciphertext_size(
    glwe_size: GlweSize,
    fourier_polynomial_size: FourierPolynomialSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
) -> usize {
    half_product_ggsw_ciphertext_row_count(
        glwe_size,
        decomp_level_count_mask,
        decomp_level_count_body,
    ) * glwe_size.0
        * fourier_polynomial_size.0
}

/// Return the number of mask samples used during encryption of a [`HalfProductGgswCiphertext`].
pub fn half_product_ggsw_ciphertext_encryption_mask_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
) -> EncryptionMaskSampleCount {
    half_product_ggsw_ciphertext_row_count(
        glwe_size,
        decomp_level_count_mask,
        decomp_level_count_body,
    ) * glwe_ciphertext_encryption_mask_sample_count(glwe_size.to_glwe_dimension(), polynomial_size)
}

/// Return the number of noise samples used during encryption of a [`HalfProductGgswCiphertext`].
pub fn half_product_ggsw_ciphertext_encryption_noise_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count_mask: DecompositionLevelCount,
    decomp_level_count_body: DecompositionLevelCount,
) -> EncryptionNoiseSampleCount {
    half_product_ggsw_ciphertext_row_count(
        glwe_size,
        decomp_level_count_mask,
        decomp_level_count_body,
    ) * glwe_ciphertext_encryption_noise_sample_count(polynomial_size)
}

/// Every row of a [`HalfProductGgswCiphertext`] is an independent GLWE encryption, so the fork is
/// flat: one child per row.
pub fn half_product_ggsw_ciphertext_encryption_fork_config<
    Scalar,
    MaskDistribution,
    NoiseDistribution,
>(
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
    let row_count = half_product_ggsw_ciphertext_row_count(
        glwe_size,
        decomp_level_count_mask,
        decomp_level_count_body,
    );

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        row_count,
        glwe_ciphertext_encryption_mask_sample_count(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
        ),
        mask_distribution,
        glwe_ciphertext_encryption_noise_sample_count(polynomial_size),
        noise_distribution,
        modulus,
    )
}

/// Assert that a `(base_log, level_count)` pair can be handed to a
/// [`crate::core_crypto::commons::math::decomposition::SignedDecomposer`] over `Scalar`.
pub(crate) fn assert_valid_decomposition<Scalar: UnsignedInteger>(
    base_log: DecompositionBaseLog,
    level_count: DecompositionLevelCount,
    name: &str,
) {
    assert!(
        level_count.0 > 0,
        "Got a zero {name} decomposition level count"
    );
    assert!(
        base_log.0 * level_count.0 <= Scalar::BITS,
        "Invalid {name} decomposition parameters: base_log ({}) * level_count ({}) must not exceed \
        the {} bits of the scalar type",
        base_log.0,
        level_count.0,
        Scalar::BITS,
    );
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> HalfProductGgswCiphertext<C> {
    /// Create a [`HalfProductGgswCiphertext`] from an existing container.
    ///
    /// # Panics
    ///
    /// Panics if the container length is not exactly
    /// [`half_product_ggsw_ciphertext_size`] elements.
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
        assert_valid_decomposition::<Scalar>(decomp_base_log_mask, decomp_level_count_mask, "mask");
        assert_valid_decomposition::<Scalar>(decomp_base_log_body, decomp_level_count_body, "body");

        let expected_len = half_product_ggsw_ciphertext_size(
            glwe_size,
            polynomial_size,
            decomp_level_count_mask,
            decomp_level_count_body,
        );
        assert_eq!(
            container.container_len(),
            expected_len,
            "The provided container length is not valid. \
            Expected {expected_len} for glwe_size: {glwe_size:?}, \
            polynomial_size: {polynomial_size:?}, \
            decomp_level_count_mask: {decomp_level_count_mask:?}, \
            decomp_level_count_body: {decomp_level_count_body:?}.",
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

    /// Return the total number of GLWE ciphertexts held by this ciphertext.
    pub fn row_count(&self) -> usize {
        half_product_ggsw_ciphertext_row_count(
            self.glwe_size,
            self.decomp_level_count_mask,
            self.decomp_level_count_body,
        )
    }

    /// Return the number of GLWE ciphertexts of the mask block.
    pub fn mask_row_count(&self) -> usize {
        half_product_ggsw_ciphertext_mask_row_count(self.glwe_size, self.decomp_level_count_mask)
    }

    /// Interpret the [`HalfProductGgswCiphertext`] as a [`GlweCiphertextList`].
    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Interpret the [`HalfProductGgswCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    pub fn as_view(&self) -> HalfProductGgswCiphertextView<'_, Scalar> {
        HalfProductGgswCiphertextView::from_container(
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
        half_product_ggsw_ciphertext_encryption_fork_config(
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

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> HalfProductGgswCiphertext<C> {
    /// Mutable variant of [`HalfProductGgswCiphertext::as_glwe_list`].
    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`HalfProductGgswCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> HalfProductGgswCiphertextMutView<'_, Scalar> {
        let glwe_size = self.glwe_size;
        let polynomial_size = self.polynomial_size;
        let decomp_base_log_mask = self.decomp_base_log_mask;
        let decomp_level_count_mask = self.decomp_level_count_mask;
        let decomp_base_log_body = self.decomp_base_log_body;
        let decomp_level_count_body = self.decomp_level_count_body;
        let ciphertext_modulus = self.ciphertext_modulus;
        HalfProductGgswCiphertextMutView::from_container(
            self.as_mut(),
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

impl<Scalar: UnsignedInteger> HalfProductGgswCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`HalfProductGgswCiphertext`].
    ///
    /// This function only allocates memory, if you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_half_product_ggsw_ciphertext`] or its
    /// parallel counterpart.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fill_with: Scalar,
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
                half_product_ggsw_ciphertext_size(
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
