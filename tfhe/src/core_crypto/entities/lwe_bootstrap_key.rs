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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweBootstrapKey<C: Container> {
    // An LweBootstrapKey is literally a GgswCiphertextList, so we wrap a GgswCiphetextList and use
    // Deref to have access to all the primitives of the GgswCiphertextList easily
    ggsw_list: GgswCiphertextList<C>,
}

impl<C: Container> std::ops::Deref for LweBootstrapKey<C> {
    type Target = GgswCiphertextList<C>;

    fn deref(&self) -> &GgswCiphertextList<C> {
        &self.ggsw_list
    }
}

impl<C: ContainerMut> std::ops::DerefMut for LweBootstrapKey<C> {
    fn deref_mut(&mut self) -> &mut GgswCiphertextList<C> {
        &mut self.ggsw_list
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweBootstrapKey<C> {
    /// Create a [`LweBootstrapKey`] from an existing container.
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
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // Define parameters for LweBootstrapKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(8);
    /// let decomp_level_count = DecompositionLevelCount(3);
    /// let input_lwe_dimension = LweDimension(600);
    ///
    /// // Create a new LweBootstrapKey
    /// let bsk = LweBootstrapKey::new(
    ///     0u64,
    ///     glwe_size,
    ///     polynomial_size,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    /// );
    ///
    /// // These methods are "inherited" from GgswCiphertextList and are accessed through the Deref
    /// // trait
    /// assert_eq!(bsk.glwe_size(), glwe_size);
    /// assert_eq!(bsk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk.decomposition_level_count(), decomp_level_count);
    ///
    /// // These methods are specific to the LweBootstrapKey
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.output_lwe_dimension().0,
    ///     glwe_size.to_glwe_dimension().0 * polynomial_size.0
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
    /// );
    ///
    /// assert_eq!(bsk.glwe_size(), glwe_size);
    /// assert_eq!(bsk.polynomial_size(), polynomial_size);
    /// assert_eq!(bsk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(bsk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(bsk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(
    ///     bsk.output_lwe_dimension().0,
    ///     glwe_size.to_glwe_dimension().0 * polynomial_size.0
    /// );
    /// ```
    pub fn from_container(
        container: C,
        glwe_size: GlweSize,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
    ) -> LweBootstrapKey<C> {
        LweBootstrapKey {
            ggsw_list: GgswCiphertextList::from_container(
                container,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
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
        LweDimension(self.glwe_size().to_glwe_dimension().0 * self.polynomial_size().0)
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
        )
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweBootstrapKey<C> {
    /// Mutable variant of [`LweBootstrapKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweBootstrapKey<&'_ mut [Scalar]> {
        let glwe_size = self.glwe_size();
        let polynomial_size = self.polynomial_size();
        let decomp_base_log = self.decomposition_base_log();
        let decomp_level_count = self.decomposition_level_count();
        LweBootstrapKey::from_container(
            self.as_mut(),
            glwe_size,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
        )
    }
}

/// An [`LweBootstrapKey`] owning the memory for its own storage.
pub type LweBootstrapKeyOwned<Scalar> = LweBootstrapKey<Vec<Scalar>>;

impl<Scalar: Copy> LweBootstrapKeyOwned<Scalar> {
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
    ) -> LweBootstrapKeyOwned<Scalar> {
        LweBootstrapKeyOwned {
            ggsw_list: GgswCiphertextList::new(
                fill_with,
                glwe_size,
                polynomial_size,
                decomp_base_log,
                decomp_level_count,
                GgswCiphertextCount(input_lwe_dimension.0),
            ),
        }
    }
}
