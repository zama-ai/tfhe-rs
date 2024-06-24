//! Module containing the definition of the LweBootstrapKey.

use tfhe_versionable::Versionize;

use crate::core_crypto::backward_compatibility::entities::lwe_bootstrap_key::LweBootstrapKeyVersions;
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// An [`LWE bootstrap key`](`LweBootstrapKey`).
///
/// This is a wrapper type of [`GgswCiphertextList`], [`std::ops::Deref`] and [`std::ops::DerefMut`]
/// are implemented to dereference to the underlying [`GgswCiphertextList`] for ease of use. See
/// [`GgswCiphertextList`] for additional methods.
///
/// # Formal Definition
///
/// ## Bootstrapping Key
/// A bootstrapping key is a vector of
/// [`GGSW ciphertexts`](`crate::core_crypto::entities::GgswCiphertext`). It encrypts the
/// coefficients of the [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{in}}$ under the
/// [GLWE secret key](`crate::core_crypto::entities::GlweSecretKey`)
/// $\vec{S}\_{\mathsf{out}}$.
///
/// $$\mathsf{BSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{S}\_{\mathsf{out}}} = \left(
/// \overline{\overline{\mathsf{CT}\_0}}, \cdots ,
/// \overline{\overline{\mathsf{CT}\_{n\_{\mathsf{in}}-1}}}\right) \subseteq
/// \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)\cdot n\_{\mathsf{in}}}$$
///
/// where $\vec{s}\_{\mathsf{in}} = \left( s\_0 , \cdots , s\_{\mathsf{in}-1} \right)$ and for all
/// $0\le i <n\_{\mathsf{in}}$ we have $\overline{\overline{\mathsf{CT}\_i}} \in
/// \mathsf{GGSW}\_{\vec{S}\_{\mathsf{out}}}^{\beta, \ell}\left(s\_i\right)$.
///
/// **Remark:** Observe that the GGSW secret key, which is a GLWE secret key,  can be easily seen as
/// a LWE secret key by simply taking all the coefficients of the polynomials composing the secret
/// key and putting them into a vector in order. We will call this LWE secret key derived from the
/// GLWE secret key **_extracted LWE key_**.
///
/// Let $\vec{S}\_{\mathsf{out}} = (S\_{\mathsf{out},0}, \ldots,
/// S\_{\mathsf{out},k\_{\mathsf{out}}-1}) \in \mathcal{R}^{k\_{\mathsf{out}}}$, such that
/// $S\_{\mathsf{out},i} = \sum\_{j=0}^{N\_{\mathsf{out}}-1} s\_{\mathsf{out},i, j} \cdot X^j$.
/// Then, the extracted LWE key will be $\vec{s}\_{\mathsf{out}} = (s\_{\mathsf{out},0,0}, \ldots,
/// s\_{\mathsf{out},0,N\_{\mathsf{out}}-1}, \ldots, s\_{\mathsf{out},k\_{\mathsf{out}}-1,0},
/// \ldots, s\_{\mathsf{out},k\_{\mathsf{out}}-1,N\_{\mathsf{out}}-1}) \in
/// \mathbb{Z}^{n\_{\mathsf{out}}}$, where $n\_{\mathsf{out}} = k\_{\mathsf{out}} \cdot
/// N\_{\mathsf{out}}$.
///
/// ## Programmable Bootstrapping
///
/// This homomorphic procedure allows to both reduce the noise of a ciphertext and to evaluate a
/// Look-Up Table (LUT) on the encrypted plaintext at the same time, i.e., it transforms an input
/// [`LWE ciphertext`](`LweCiphertext`)
/// $\mathsf{ct}\_{\mathsf{in}} = \left(
/// \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in
/// \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}( \mathsf{pt} ) \subseteq
/// \mathbb{Z}\_q^{(n\_{\mathsf{in}}+1)}$ into an output [`LWE ciphertext`](`LweCiphertext`)
/// $\mathsf{ct}\_{\mathsf{out}} = \left( \vec{a}\_{\mathsf{out}} ,
/// b\_{\mathsf{out}}\right) \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}(
/// \mathsf{LUT(pt)} )\subseteq \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$ where $n\_{\mathsf{in}} =
/// |\vec{s}\_{\mathsf{in}}|$ and $n\_{\mathsf{out}} = |\vec{s}\_{\mathsf{out}}|$, such that the
/// noise in this latter is set to a fixed (reduced) amount. It requires a
/// [`bootstrapping key`](`LweBootstrapKey`).
///
/// The input ciphertext is encrypted under the
/// [`LWE secret key`](`LweSecretKey`)
/// $\vec{s}\_{\mathsf{in}}$ and the
/// output ciphertext is encrypted under the
/// [`LWE secret key`](`LweSecretKey`)
/// $\vec{s}\_{\mathsf{out}}$.
///
/// $$\mathsf{ct}\_{\mathsf{in}} \in \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}(
/// \mathsf{pt} ) ~~~~~~~~~~\mathsf{BSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow
/// \vec{S}\_{\mathsf{out}}}$$ $$ \mathsf{PBS}\left(\mathsf{ct}\_{\mathsf{in}} , \mathsf{BSK}
/// \right) \rightarrow \mathsf{ct}\_{\mathsf{out}} \in
/// \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}} \left( \mathsf{pt} \right)$$
///
/// ## Algorithm
/// ###### inputs:
/// - $\mathsf{ct}\_{\mathsf{in}} = \left( \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in
///   \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}( \mathsf{pt} )$: an [`LWE
///   ciphertext`](`LweCiphertext`) with $\vec{a}\_{\mathsf{in}}=\left(a\_0, \cdots
///   a\_{n\_{\mathsf{in}}-1}\right)$
/// - $\mathsf{BSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{S}\_{\mathsf{out}}}$: a bootstrapping
///   key as defined above
/// - $\mathsf{LUT} \in \mathcal{R}\_q$: a LUT represented as a polynomial \_with redundancy\_
///
/// ###### outputs:
/// - $\mathsf{ct}\_{\mathsf{out}} \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}
///   \left( \mathsf{LUT(pt)} \right)$: an [`LWE ciphertext`](`LweCiphertext`)
///
/// ###### algorithm:
/// 1. Compute $\tilde{a}\_i \in \mathbb{Z}\_{2N\_{\mathsf{out}}} \leftarrow \lfloor \frac{2
///    N\_{\mathsf{out}} \cdot a\_i}{q} \rceil$, for $i= 0, 1, \ldots, n\_{\mathsf{in}-1}$
/// 2. Compute $\tilde{b}\_\mathsf{in} \in \mathbb{Z}\_{2N\_{\mathsf{out}}} \leftarrow \lfloor
///    \frac{2 N\_{\mathsf{out}} \cdot b\_\mathsf{in}}{q} \rceil$
/// 3. Set $\mathsf{ACC} = (0, \ldots, 0, \mathsf{LUT} \cdot X^{-\tilde{b}\_\mathsf{in}})$
/// 4. Compute $\mathsf{ACC} = \mathsf{CMux}(\overline{\overline{\mathsf{CT}\_i}}, \mathsf{ACC}
///    \cdot X^{\tilde{a}\_i}, \mathsf{ACC})$, for $i= 0, 1, \ldots, n\_{\mathsf{in}-1}$
/// 5. Output $\mathsf{ct}\_{\mathsf{out}} \leftarrow \mathsf{SampleExtract}(\mathsf{ACC})$
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweBootstrapKeyVersions)]
pub struct LweBootstrapKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    // An LweBootstrapKey is literally a GgswCiphertextList, so we wrap a GgswCiphertextList and
    // use Deref to have access to all the primitives of the GgswCiphertextList easily
    ggsw_list: GgswCiphertextList<C>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> std::ops::Deref
    for LweBootstrapKey<C>
{
    type Target = GgswCiphertextList<C>;

    fn deref(&self) -> &GgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> std::ops::DerefMut
    for LweBootstrapKey<C>
{
    fn deref_mut(&mut self) -> &mut GgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

pub fn lwe_bootstrap_key_size(
    input_lwe_dimension: LweDimension,
    glwe_size: GlweSize,
    polynomial_size: PolynomialSize,
    decomp_level_count: DecompositionLevelCount,
) -> usize {
    ggsw_ciphertext_list_size(
        GgswCiphertextCount(input_lwe_dimension.0),
        glwe_size,
        polynomial_size,
        decomp_level_count,
    )
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweBootstrapKey<C> {
    /// Create an [`LweBootstrapKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an LWE
    /// bootstrap key you need to use [`crate::core_crypto::algorithms::generate_lwe_bootstrap_key`]
    /// or its parallel equivalent
    /// [`crate::core_crypto::algorithms::par_generate_lwe_bootstrap_key`] using this key as output.
    ///
    /// This docstring exhibits [`LweBootstrapKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweBootstrapKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweBootstrapKey
    /// let bsk = LweBootstrapKey::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
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
    /// // These methods are specific to the LweBootstrapKey
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = bsk.into_container();
    ///
    /// // Recreate a key using from_container
    /// let bsk = LweBootstrapKey::from_container(
    ///     underlying_container,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
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
    ///     bsk.output_lwe_dimension(),
    ///     glwe_size
    ///         .to_glwe_dimension()
    ///         .to_equivalent_lwe_dimension(polynomial_size)
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        Self {
            ggsw_list: GgswCiphertextList::from_container(
                container,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                ciphertext_modulus,
            ),
        }
    }

    /// Return the [`LweDimension`] of the input [`LweSecretKey`].
    ///
    /// See [`LweBootstrapKey::from_container`] for usage.
    pub fn input_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.ggsw_ciphertext_count().0)
    }

    /// Return the [`LweDimension`] of the equivalent output [`LweSecretKey`].
    ///
    /// See [`LweBootstrapKey::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.glwe_size()
            .to_glwe_dimension()
            .to_equivalent_lwe_dimension(self.polynomial_size())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweBootstrapKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.ggsw_list.into_container()
    }

    /// Return a view of the [`LweBootstrapKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweBootstrapKey<&'_ [Scalar]> {
        LweBootstrapKey::from_container(
            self.as_ref(),
            self.glwe_size(),
            self.polynomial_size(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweBootstrapKey<C> {
    /// Mutable variant of [`LweBootstrapKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweBootstrapKey<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweBootstrapKey::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            ciphertext_modulus,
        )
    }
}

/// An [`LweBootstrapKey`] owning the memory for its own storage.
pub type LweBootstrapKeyOwned<Scalar> = LweBootstrapKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LweBootstrapKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweBootstrapKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an LWE bootstrap key you need to use
    /// [`crate::core_crypto::algorithms::generate_lwe_bootstrap_key`] or its parallel
    /// equivalent [`crate::core_crypto::algorithms::par_generate_lwe_bootstrap_key`] using this
    /// key as output.
    ///
    /// See [`LweBootstrapKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            ggsw_list: GgswCiphertextList::new(
                fill_with,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(input_lwe_dimension.0),
                ciphertext_modulus,
            ),
        }
    }
}
