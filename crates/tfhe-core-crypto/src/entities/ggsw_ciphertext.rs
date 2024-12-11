//! Module containing the definition of the GgswCiphertext.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::ggsw_ciphertext::GgswCiphertextVersions;
use crate::core_crypto::commons::generators::EncryptionRandomGeneratorForkConfig;
use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`GGSW Ciphertext`](`GgswCiphertext`).
///
/// # Formal Definition
///
/// # GGSW Ciphertext
///
/// A GGSW ciphertext is an encryption of a polynomial plaintext.
/// It is a vector of [`GLWE ciphertexts`](`crate::core_crypto::entities::GlweCiphertext`).
/// It is a generalization of both GSW ciphertexts and RGSW ciphertexts.
///
/// We call $q$ the ciphertext modulus.
/// We use the notation $\mathcal{R}\_q$ for the following cyclotomic ring:
/// $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where $N\in\mathbb{N}$ is a
/// power of two.
///
/// We indicate a GGSW ciphertext of a polynomial plaintext $\mathsf{PT} \in\mathcal{R}\_q$
/// as the following vector:
///
/// $$\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0}, \cdots
/// , \overline{\mathsf{CT}\_{k}} \right) \in \mathsf{GGSW}\_{\vec{S}}^{\beta,
/// \ell}\left(\mathsf{PT}\right) \subseteq \mathcal{R}\_q^{(k+1)\times\ell\cdot(k+1)}$$
///
/// Where $\vec{S}=\left(S\_0, \cdots , S\_{k-1}\right)\in \mathcal{R}\_q^k$ and for all $0\le i<k$
/// we have $\overline{\mathsf{CT}\_i} \in \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left( -S\_i \cdot
/// \mathsf{PT}\right)\subseteq \mathcal{R}\_q^{\ell \cdot (k+1)}$ and $\overline{\mathsf{CT}\_k}
/// \in \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left( \mathsf{PT}\right)\subseteq
/// \mathcal{R}\_q^{\ell \cdot (k+1)}$.
///
/// This type of ciphertext contains a lot of redundancy ($k+1$ GLev ciphertexts -- definition
/// below -- each encrypting the same plaintext times an element of the secret key) .
///
/// ## Levels and decomposition base
/// A GGSW ciphertext contains GLev ciphertexts that are parameterized with an
/// integer $\ell$ called level and an integer $\beta$ (generally a power of 2) called
/// decomposition base.
///
/// ## Secret Key
/// A GGSW ciphertext is encrypted under a
/// [`GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`).
///
/// ## GGSW Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in\mathcal{R}\_q$: a polynomial plaintext
/// - $\vec{S}=\left(S\_0, \cdots, S\_{k-1} \right) \in\mathcal{R}\_q^k$: a [`GLWE secret
///   key`](`crate::core_crypto::entities::GlweSecretKey`)
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean of
///   $\mu$
/// - $\ell$: number of levels desired
/// - $\beta$: decomposition base
///
/// ###### outputs:
/// - $\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0}, \cdots ,
///   \overline{\mathsf{CT}\_{k-1}} \right) \in \mathsf{GGSW}\_{\vec{S}}^{\beta,
///   \ell}\left(\mathsf{PT}\right) \subseteq \mathcal{R}\_q^{(k+1)\cdot\ell\cdot(k+1)}$: a GGSW
///   ciphertext
///
/// ###### algorithm:
/// 1. for $0\le i < k$:
///     - compute $\mathsf{PT}\_i = -S\_i\cdot\mathsf{PT} \in \mathbb{Z}\_q$
///     - compute $\overline{\mathsf{CT}\_i} \leftarrow \mathsf{GLev}.\mathsf{encrypt}\left(
///       \mathsf{PT}\_i, \vec{S} ,\mathcal{D\_{\sigma^2,\mu}} ,\ell \right)$
/// 2. compute  $\overline{\mathsf{CT}\_n} \leftarrow \mathsf{GLev}.\mathsf{encrypt}\left(
///    \mathsf{PT}, \vec{s} ,\mathcal{D\_{\sigma^2,\mu}} ,\ell \right)$
/// 3. output $\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0} , \cdots ,
///    \overline{\mathsf{CT}\_{n}} \right)$
///
/// ###### equivalent algorithm (using the gadget matrix):
/// 1. for $0\le i \le k$:
///     - for  $0\le j < \ell$:
///         - compute $\mathsf{CT}\_{i,j} \leftarrow \mathsf{GLWE}.\mathsf{encrypt}\left( 0, \vec{S}
///           ,\mathcal{D\_{\sigma^2,\mu}} \right)$
///         - add to the $i$-th component of $\mathsf{CT}\_{i,j}$ the value
///           $\left\lfloor\mathsf{PT}\cdot \frac{q}{\beta^{j+1}} \right\rceil \in \mathcal{R}\_q$
///     - set $\overline{\mathsf{CT}\_i} = \left( \mathsf{CT}\_{i,0} , \cdots ,
///       \mathsf{CT}\_{i,\ell-1} \right)$
/// 2. output $\overline{\overline{\mathsf{CT}}} = \left( \overline{\mathsf{CT}\_0} , \cdots ,
///    \overline{\mathsf{CT}\_{n}} \right)$
///
/// ## GGSW Decryption
/// Simply use the GLev decryption algorithm on the last GLev ciphertext contained in the GGSW
/// ciphertext.
///
/// # GLev Ciphertext
///
/// **Remark:** This type of ciphertexts is not yet directly exposed in the library but its
/// description helps understanding GGSW ciphertext.
///
/// A GLev ciphertext is an encryption of a polynomial plaintext.
/// It is a vector of GLev ciphertexts.
/// It is a generalization of both Lev ciphertexts and RLev ciphertexts.
///
/// We call $q$ the ciphertext modulus.
/// We use the notation $\mathcal{R}\_q$ for the following cyclotomic ring:
/// $\mathbb{Z}\_q\[X\]/\left\langle X^N + 1\right\rangle$ where $N\in\mathbb{N}$ is a power of two.
///
/// We indicate a GLev ciphertext of a polynomial plaintext $\mathsf{PT} \in\mathcal{R}\_q^{k+1}$ as
/// the following vector: $$\overline{\mathsf{CT}} = \left( \mathsf{CT}\_0 , \cdots ,
/// \mathsf{CT}\_{\ell-1} \right) \in \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left(\mathsf{PT}\right)
/// \subseteq \mathcal{R}\_q^{(k+1)\cdot \ell}$$
///
/// Where $k=|\vec{S}|$ and for all $0\le i <\ell$, we have $\mathsf{CT}\_i \in
/// \mathsf{GLWE}\_{\vec{S}}\left( \left\lfloor\mathsf{PT}\cdot \frac{q}{\beta^{i+1}} \right\rceil
/// \right)\subseteq  \mathcal{R}\_q^{k+1}$ (we are using the encoding in the MSB with $\Delta =
/// \frac{q}{\beta^{i+1}}$).
///
/// This type of ciphertext contains redundancy ($\ell$
/// [`GLWE ciphertext`](`crate::core_crypto::entities::GlweCiphertext`),
/// each encrypting the same plaintext times a different scaling factor).
///
/// ## Decomposition base
/// A GLev ciphertext is parameterized with a decomposition base $\beta$, generally chosen as a
/// power of 2.
///
/// ## Levels
/// A GLev ciphertext contains a number of levels $\ell$ from level $0$ to level $\ell-1$.
///
/// ## Secret Key
/// A GLev ciphertext is encrypted under a
/// [`GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`).
///
/// ## GLev Encryption
/// ###### inputs:
/// - $\mathsf{PT}\in \mathcal{R}\_q$: a polynomial plaintext
/// - $\vec{S}\in  \mathcal{R}\_q^k$: a [`GLWE Secret
///   Key`](`crate::core_crypto::entities::GlweSecretKey`)
/// - $\mathcal{D\_{\sigma^2,\mu}}$: a normal distribution of variance $\sigma^2$ and a mean of
///   $\mu$
/// - $\ell$: number of levels desired
/// - $\beta$: decomposition base
///
/// ###### outputs:
/// - $\overline{\mathsf{CT}} = \left( \mathsf{CT}\_0 , \cdots , \mathsf{CT}\_{\ell-1} \right) \in
///   \mathsf{GLev}\_{\vec{S}}^{\beta, \ell}\left(\mathsf{PT}\right) \subseteq
///   \mathcal{R}\_q^{(k+1)\cdot\ell}$: a GLev ciphertext
///
/// ###### algorithm:
/// 1. for $0\le i < \ell-1$:
///     - compute $\mathsf{PT}\_i = \left\lfloor\mathsf{PT}\cdot \frac{q}{\beta^{i+1}} \right\rceil
///       \in \mathcal{R}\_q$
///     - compute $\mathsf{CT}\_i \leftarrow \mathsf{GLWE}.\mathsf{encrypt}\left( \mathsf{PT}\_i,
///       \vec{S} ,\mathcal{D\_{\sigma^2,\mu}} \right)$
/// 2. output $\overline{\mathsf{CT}} = \left( \mathsf{CT}\_0 , \cdots , \mathsf{CT}\_{\ell-1}
///    \right)$
///
/// ## GLev Decryption
/// Simply use the
/// [`GLWE decryption
/// algorithm`](`crate::core_crypto::algorithms::glwe_encryption::decrypt_glwe_ciphertext`)
/// on one of the GLWE ciphertexts contained in the GLev ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(GgswCiphertextVersions)]
pub struct GgswCiphertext<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GgswCiphertext<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GgswCiphertext<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in a [`GgswCiphertext`] given a [`GlweSize`], [`PolynomialSize`]
/// and [`DecompositionLevelCount`].
pub fn ggsw_ciphertext_size(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0 * ggsw_level_matrix_size(glwe_size, polynomial_size)
}

/// Return the number of elements in a [`GgswLevelMatrix`] given a [`GlweSize`] and
/// [`PolynomialSize`].
pub fn ggsw_level_matrix_size(glwe_size: GlweSize, polynomial_size: PolynomialSize) -> usize {
    glwe_size.0 * glwe_size.0 * polynomial_size.0
}

/// Return the number of elements in a [`FourierGgswCiphertext`] given a [`GlweSize`],
/// [`FourierPolynomialSize`] and [`DecompositionLevelCount`].
pub fn fourier_ggsw_ciphertext_size(
    glwe_size: GlweSize,
    fourier_polynomial_size: FourierPolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    decomp_level_count.0 * fourier_ggsw_level_matrix_size(glwe_size, fourier_polynomial_size)
}

/// Return the number of elements in a [`FourierGgswLevelMatrix`] given a [`GlweSize`] and
/// [`FourierPolynomialSize`].
pub fn fourier_ggsw_level_matrix_size(
    glwe_size: GlweSize,
    fourier_polynomial_size: FourierPolynomialSize,
) -> usize {
    glwe_size.0 * glwe_size.0 * fourier_polynomial_size.0
}

/// Return the number of mask samples used during encryption of a [`GgswCiphertext`] given a
/// [`GlweSize`], [`PolynomialSize`] and [`DecompositionLevelCount`].
pub fn ggsw_ciphertext_encryption_mask_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> EncryptionMaskSampleCount {
    decomp_level_count.0
        * ggsw_level_matrix_encryption_mask_sample_count(glwe_size, polynomial_size)
}

/// Return the number of mask samples used during encryption of a [`GgswLevelMatrix`] given a
/// [`GlweSize`] and [`PolynomialSize`].
pub fn ggsw_level_matrix_encryption_mask_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> EncryptionMaskSampleCount {
    glwe_size.0
        * glwe_ciphertext_encryption_mask_sample_count(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
        )
}

/// Return the number of noise samples used during encryption of a [`GgswCiphertext`] given a
/// [`GlweSize`], [`PolynomialSize`] and [`DecompositionLevelCount`].
pub fn ggsw_ciphertext_encryption_noise_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> EncryptionNoiseSampleCount {
    decomp_level_count.0
        * ggsw_level_matrix_encryption_noise_sample_count(glwe_size, polynomial_size)
}

/// Return the number of noise samples used during encryption of a [`GgswLevelMatrix`] given a
/// [`GlweSize`] and [`PolynomialSize`].
pub fn ggsw_level_matrix_encryption_noise_sample_count(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
) -> EncryptionNoiseSampleCount {
    glwe_size.0 * glwe_ciphertext_encryption_noise_sample_count(polynomial_size)
}

pub fn ggsw_ciphertext_encryption_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
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
    let ggsw_level_matrix_mask_sample_count =
        ggsw_level_matrix_encryption_mask_sample_count(glwe_size, polynomial_size);
    let ggsw_level_matrix_noise_sample_count =
        ggsw_level_matrix_encryption_noise_sample_count(glwe_size, polynomial_size);

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        decomposition_level_count.0,
        ggsw_level_matrix_mask_sample_count,
        mask_distribution,
        ggsw_level_matrix_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

pub fn ggsw_level_matrix_encryption_fork_config<Scalar, MaskDistribution, NoiseDistribution>(
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
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
    let glwe_ciphertext_mask_sample_count = glwe_ciphertext_encryption_mask_sample_count(
        glwe_size.to_glwe_dimension(),
        polynomial_size,
    );
    let glwe_ciphertext_noise_sample_count =
        glwe_ciphertext_encryption_noise_sample_count(polynomial_size);

    let modulus = ciphertext_modulus.get_custom_modulus_as_optional_scalar();

    EncryptionRandomGeneratorForkConfig::new(
        glwe_size.0,
        glwe_ciphertext_mask_sample_count,
        mask_distribution,
        glwe_ciphertext_noise_sample_count,
        noise_distribution,
        modulus,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GgswCiphertext<C> {
    /// Create a [`GgswCiphertext`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its
    /// parallel counterpart
    /// [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`] using
    /// this ciphertext as output.
    ///
    /// This docstring exhibits [`GgswCiphertext`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GgswCiphertext creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new GgswCiphertext
    /// let ggsw = GgswCiphertext::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.ggsw_level_matrix_size(),
    ///     ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = ggsw.into_container();
    ///
    /// // Recreate a ciphertext using from_container
    /// let ggsw = GgswCiphertext::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(ggsw.glwe_size(), glwe_size);
    /// assert_eq!(ggsw.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(ggsw.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(ggsw.ciphertext_modulus(), ciphertext_modulus);
    /// assert_eq!(
    ///     ggsw.ggsw_level_matrix_size(),
    ///     ggsw_level_matrix_size(glwe_size, polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GgswCiphertext"
        );
        assert!(
            container.container_len() % (glwe_size.0 * glwe_size.0 * polynomial_size.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by glwe_size * glwe_size * polynomial_size: {}. \
        Got container length: {} and glwe_size: {glwe_size:?}, \
        polynomial_size: {polynomial_size:?}.",
            glwe_size.0 * glwe_size.0 * polynomial_size.0,
            container.container_len()
        );

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        }
    }

    /// Return the [`PolynomialSize`] of the [`GgswCiphertext`].
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`GlweSize`] of the [`GgswCiphertext`].
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`DecompositionBaseLog`] of the [`GgswCiphertext`].
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`GgswCiphertext`].
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        DecompositionLevelCount(self.data.container_len() / self.ggsw_level_matrix_size())
    }

    /// Return the [`CiphertextModulus`] of the [`GgswCiphertext`].
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Return the size in number of elements of a single [`GgswLevelMatrix`] of the current
    /// [`GgswCiphertext`].
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn ggsw_level_matrix_size(&self) -> usize {
        // GlweSize GlweCiphertext(glwe_size, polynomial_size) per level
        ggsw_level_matrix_size(self.glwe_size, self.polynomial_size)
    }

    /// Interpret the [`GgswCiphertext`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, Scalar> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Interpret the [`GgswCiphertext`] as a [`GlweCiphertextList`].
    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }

    /// Return a view of the [`GgswCiphertext`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> GgswCiphertextView<'_, Scalar> {
        GgswCiphertextView::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.ciphertext_modulus(),
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
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
        ggsw_ciphertext_encryption_fork_config(
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_level_count(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GgswCiphertext<C> {
    /// Mutable variant of [`GgswCiphertext::as_polynomial_list`].
    pub fn as_mut_polynomial_list(&mut self) -> PolynomialListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        PolynomialListMutView::from_container(self.as_mut(), polynomial_size)
    }

    /// Mutable variant of [`GgswCiphertext::as_glwe_list`].
    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let polynomial_size = self.polynomial_size;
        let glwe_size = self.glwe_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        )
    }

    /// Mutable variant of [`GgswCiphertext::as_view`].
    pub fn as_mut_view(&mut self) -> GgswCiphertextMutView<'_, Scalar> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let ciphertext_modulus = self.ciphertext_modulus;
        GgswCiphertextMutView::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

/// A [`GgswCiphertext`] owning the memory for its own storage.
pub type GgswCiphertextOwned<Scalar> = GgswCiphertext<Vec<Scalar>>;
/// A [`GgswCiphertext`] immutably borrowing memory for its own storage.
pub type GgswCiphertextView<'data, Scalar> = GgswCiphertext<&'data [Scalar]>;
/// A [`GgswCiphertext`] immutably borrowing memory for its own storage.
pub type GgswCiphertextMutView<'data, Scalar> = GgswCiphertext<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> GgswCiphertextOwned<Scalar> {
    /// Allocate memory and create a new owned [`GgswCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_constant_ggsw_ciphertext`] or its parallel
    /// counterpart [`crate::core_crypto::algorithms::par_encrypt_constant_ggsw_ciphertext`]
    /// using this ciphertext as output.
    ///
    /// See [`GgswCiphertext::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; ggsw_ciphertext_size(glwe_size, polynomial_size, decomp_level_count)],
            glwe_size,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GgswCiphertext`] entities.
#[derive(Clone, Copy)]
pub struct GgswCiphertextCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub decomp_base_log: DecompositionBaseLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for GgswCiphertext<C> {
    type Metadata = GgswCiphertextCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GgswCiphertextCreationMetadata {
            glwe_size,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        } = meta;
        Self::from_container(
            from,
            glwe_size,
            polynomial_size,
            decomp_base_log,
            ciphertext_modulus,
        )
    }
}

/// A convenience structure to more easily write iterators on a [`GgswCiphertext`] levels.
pub struct GgswLevelMatrix<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GgswLevelMatrix<C> {
    /// Create a [`GgswLevelMatrix`] from an existing container.
    ///
    /// # Note
    ///
    /// This docstring exhibits [`GgswLevelMatrix`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GgswLevelMatrix creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// let container = vec![0u64; ggsw_level_matrix_size(glwe_size, polynomial_size)];
    ///
    /// // Create a new GgswLevelMatrix
    /// let ggsw_level_matrix =
    ///     GgswLevelMatrix::from_container(container, glwe_size, polynomial_size, ciphertext_modulus);
    ///
    /// assert_eq!(ggsw_level_matrix.glwe_size(), glwe_size);
    /// assert_eq!(ggsw_level_matrix.polynomial_size(), polynomial_size);
    /// assert_eq!(ggsw_level_matrix.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() == ggsw_level_matrix_size(glwe_size, polynomial_size),
            "The provided container length is not valid. \
            Expected length of {} (glwe_size * glwe_size * polynomial_size), got {}",
            ggsw_level_matrix_size(glwe_size, polynomial_size),
            container.container_len(),
        );

        Self {
            data: container,
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`GlweSize`] of the [`GgswLevelMatrix`].
    ///
    /// See [`GgswLevelMatrix::from_container`] for usage.
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Return the [`PolynomialSize`] of the [`GgswLevelMatrix`].
    ///
    /// See [`GgswLevelMatrix::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Return the [`CiphertextModulus`] of the [`GgswLevelMatrix`].
    ///
    /// See [`GgswLevelMatrix::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    /// Interpret the [`GgswLevelMatrix`] as a [`GlweCiphertextList`].
    pub fn as_glwe_list(&self) -> GlweCiphertextListView<'_, C::Element> {
        GlweCiphertextListView::from_container(
            self.data.as_ref(),
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
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
        ggsw_level_matrix_encryption_fork_config(
            self.glwe_size(),
            self.polynomial_size(),
            mask_distribution,
            noise_distribution,
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GgswLevelMatrix<C> {
    /// Mutable variant of [`GgswLevelMatrix::as_glwe_list`]
    pub fn as_mut_glwe_list(&mut self) -> GlweCiphertextListMutView<'_, C::Element> {
        GlweCiphertextListMutView::from_container(
            self.data.as_mut(),
            self.glwe_size,
            self.polynomial_size,
            self.ciphertext_modulus,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`GgswLevelMatrix`] entities.
#[derive(Clone, Copy)]
pub struct GgswLevelMatrixCreationMetadata<Scalar: UnsignedInteger> {
    pub glwe_size: GlweSize,
    pub polynomial_size: PolynomialSize,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for GgswLevelMatrix<C> {
    type Metadata = GgswLevelMatrixCreationMetadata<C::Element>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let GgswLevelMatrixCreationMetadata {
            glwe_size,
            polynomial_size,
            ciphertext_modulus,
        } = meta;
        Self::from_container(from, glwe_size, polynomial_size, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for GgswCiphertext<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GgswLevelMatrixCreationMetadata<Self::Element>;

    type EntityView<'this>
        = GgswLevelMatrix<&'this [Self::Element]>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this>
        = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        GgswLevelMatrixCreationMetadata {
            glwe_size: self.glwe_size,
            polynomial_size: self.polynomial_size,
            ciphertext_modulus: self.ciphertext_modulus,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.ggsw_level_matrix_size()
    }

    /// Unimplemented for [`GgswCiphertext`]. At the moment it does not make sense to
    /// return "sub" GgswCiphertext.
    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        unimplemented!(
            "This function is not supported for GgswCiphertext. \
        At the moment it does not make sense to return 'sub' GgswCiphertext."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for GgswCiphertext<C>
{
    type EntityMutView<'this>
        = GgswLevelMatrix<&'this mut [Self::Element]>
    where
        Self: 'this;

    type SelfMutView<'this>
        = DummyCreateFrom
    where
        Self: 'this;
}
