//! Module containing the definition of the GlweKeyswitchKey.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`GLWE keyswitch key`](`GlweKeyswitchKey`).
///
/// # Formal Definition
///
/// ## Key Switching Key
///
/// A key switching key is a vector of GLev ciphertexts (described on the bottom of
/// [`this page`](`crate::core_crypto::entities::GgswCiphertext#Glev-ciphertext`)).
/// It encrypts the coefficient of
/// the [`GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`)
/// $\vec{S}\_{\mathsf{in}}$ under the
/// [`GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`)
/// $\vec{S}\_{\mathsf{out}}$.
///
/// $$\mathsf{KSK}\_{\vec{S}\_{\mathsf{in}}\rightarrow \vec{S}\_{\mathsf{out}}} = \left(
/// \overline{\mathsf{CT}\_0}, \cdots , \overline{\mathsf{CT}\_{k\_{\mathsf{in}}-1}}\right)
/// \subseteq R\_q^{(k\_{\mathsf{out}}+1)\cdot k\_{\mathsf{in}}\cdot \ell}$$
///
/// where $\vec{S}\_{\mathsf{in}} = \left( S\_0 , \cdots , S\_{\mathsf{in}-1} \right)$ and for all
/// $0\le i <k\_{\mathsf{in}}$ we have $\overline{\mathsf{CT}\_i} \in
/// \mathsf{GLev}\_{\vec{S}\_{\mathsf{out}}}^{\beta, \ell}\left(S\_i\right)$.
///
/// ## GLWE Keyswitch
///
/// This homomorphic procedure transforms an input
/// [`GLWE ciphertext`](`crate::core_crypto::entities::GlweCiphertext`)
/// $\mathsf{CT}\_{\mathsf{in}} =
/// \left( \vec{A}\_{\mathsf{in}} , B\_{\mathsf{in}}\right) \in \mathsf{GLWE}^{k\_{\mathsf{in}}}\_
/// {\vec{S}\_{\mathsf{in}}}( \mathsf{PT} ) \subseteq R\_q^{(k\_{\mathsf{in}}+1)}$ into an
/// output [`GLWE ciphertext`](`crate::core_crypto::entities::GlweCiphertext`)
/// $\mathsf{CT}\_{\mathsf{out}} =
/// \left( \vec{A}\_{\mathsf{out}} , B\_{\mathsf{out}}\right) \in
/// \mathsf{GLWE}^{k\_{\mathsf{out}}}\_{\vec{S}\_{\mathsf{out}}}( \mathsf{PT} )\subseteq
/// R\_q^{(k\_{\mathsf{out}}+1)}$ where $k\_{\mathsf{in}} = |\vec{S}\_{\mathsf{in}}|$ and
/// $k\_{\mathsf{out}} = |\vec{S}\_{\mathsf{out}}|$. It requires a
/// [`key switching key`](`crate::core_crypto::entities::GlweKeyswitchKey`).
/// The input ciphertext is encrypted under the
/// [`GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`)
/// $\vec{S}\_{\mathsf{in}}$ and the output ciphertext is
/// encrypted under the [`GLWE secret key`](`crate::core_crypto::entities::GlweSecretKey`)
/// $\vec{S}\_{\mathsf{out}}$.
///
/// $$\mathsf{CT}\_{\mathsf{in}} \in \mathsf{GLWE}^{k\_{\mathsf{in}}}\_{\vec{S}\_{\mathsf{in}}}(
/// \mathsf{PT} ) ~~~~~~~~~~\mathsf{KSK}\_{\vec{S}\_{\mathsf{in}}\rightarrow
/// \vec{S}\_{\mathsf{out}}}$$ $$ \mathsf{keyswitch}\left(\mathsf{CT}\_{\mathsf{in}} , \mathsf{KSK}
/// \right) \rightarrow \mathsf{CT}\_{\mathsf{out}} \in
/// \mathsf{GLWE}^{k\_{\mathsf{out}}}\_{\vec{S}\_{\mathsf{out}}} \left( \mathsf{PT} \right)$$
///
/// ## Algorithm
/// ###### inputs:
/// - $\mathsf{CT}\_{\mathsf{in}} = \left( \vec{A}\_{\mathsf{in}} , B\_{\mathsf{in}}\right) \in
///   \mathsf{GLWE}^{k\_{\mathsf{in}}}\_{\vec{S}\_{\mathsf{in}}}( \mathsf{PT} )$: a [`GLWE
///   ciphertext`](`GlweCiphertext`) with $\vec{A}\_{\mathsf{in}}=\left(A\_0, \cdots
///   A\_{k\_{\mathsf{in}}-1}\right)$
/// - $\mathsf{KSK}\_{\vec{S}\_{\mathsf{in}}\rightarrow \vec{S}\_{\mathsf{out}}}$: a
/// [`key switching key`](`crate::core_crypto::entities::GlweKeyswitchKey`)
///
/// ###### outputs:
/// - $\mathsf{CT}\_{\mathsf{out}} \in \mathsf{GLWE}^{k\_{\mathsf{out}}}\_{\vec{S}\_{\mathsf{out}}}
///   \left( \mathsf{PT} \right)$: a
/// [`GLWE ciphertext`](`crate::core_crypto::entities::GlweCiphertext`)
///
/// ###### algorithm:
/// 1. set $\mathsf{cCT}=\left( 0 , \cdots , 0 ,  B\_{\mathsf{in}} \right) \in
/// R\_q^{(k\_{\mathsf{out}}+1)}$
/// 2. compute $\mathsf{CT}\_{\mathsf{out}} = \mathsf{CT} -
/// \sum\_{i=0}^{k\_{\mathsf{in}}-1} \mathsf{decompProduct}\left( A\_i , \overline{\mathsf{CT}\_i}
/// \right)$
/// 3. output $\mathsf{CT}\_{\mathsf{out}}$
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlweKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    poly_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for GlweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for GlweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`GlweSecretKey`] element for a
/// [GlweKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`GlweSize`].
pub fn glwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    poly_size: PolynomialSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_glwe_size.0 * poly_size.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> GlweKeyswitchKey<C> {
    /// Create an [`GlweKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`GlweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_glwe_keyswitch_key`] using this key as output.
    ///
    /// This docstring exhibits [`GlweKeyswitchKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweKeyswitchKey creation
    /// let input_glwe_dimension = GlweDimension(1);
    /// let output_glwe_dimension = GlweDimension(2);
    /// let poly_size = PolynomialSize(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweKeyswitchKey
    /// let glwe_ksk = GlweKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_glwe_dimension,
    ///     output_glwe_dimension,
    ///     poly_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(glwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(glwe_ksk.input_key_glwe_dimension(), input_glwe_dimension);
    /// assert_eq!(glwe_ksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(glwe_ksk.polynomial_size(), poly_size);
    /// assert_eq!(
    ///     glwe_ksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(glwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe_ksk.into_container();
    ///
    /// // Recreate a keyswithc key using from_container
    /// let glwe_ksk = GlweKeyswitchKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_glwe_dimension.to_glwe_size(),
    ///     poly_size,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(glwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(glwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(glwe_ksk.input_key_glwe_dimension(), input_glwe_dimension);
    /// assert_eq!(glwe_ksk.output_key_glwe_dimension(), output_glwe_dimension);
    /// assert_eq!(
    ///     glwe_ksk.output_glwe_size(),
    ///     output_glwe_dimension.to_glwe_size()
    /// );
    /// assert_eq!(glwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_glwe_size: GlweSize,
        poly_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKey"
        );
        assert!(
            container.container_len() % (decomp_level_count.0 * output_glwe_size.0 * poly_size.0)
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * output_glwe_size * output_poly_size: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_glwe_size: {output_glwe_size:?}, poly_size: {poly_size:?}.",
            decomp_level_count.0 * output_glwe_size.0 * poly_size.0,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            poly_size,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`GlweDimension`] of the [`GlweKeyswitchKey`].
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn input_key_glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.data.container_len() / self.input_key_element_encrypted_size())
    }

    /// Return the input [`PolynomialSize`] of the [`GlweKeyswitchKey`].
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.poly_size
    }

    /// Return the output [`GlweDimension`] of the [`GlweKeyswitchKey`].
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn output_key_glwe_dimension(&self) -> GlweDimension {
        self.output_glwe_size.to_glwe_dimension()
    }

    /// Return the output [`GlweSize`] of the [`GlweKeyswitchKey`].
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn output_glwe_size(&self) -> GlweSize {
        self.output_glwe_size
    }

    /// Return the number of elements in an encryption of an input [`GlweSecretKey`] element of the
    /// current [`GlweKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        glwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_glwe_size,
            self.poly_size,
        )
    }

    /// Return a view of the [`GlweKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> GlweKeyswitchKey<&'_ [Scalar]> {
        GlweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_glwe_size,
            self.poly_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Return the [`CiphertextModulus`] of the [`GlweKeyswitchKey`].
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }

    pub fn as_glwe_ciphertext_list(&self) -> GlweCiphertextListView<'_, Scalar> {
        GlweCiphertextListView::from_container(
            self.as_ref(),
            self.output_glwe_size(),
            self.polynomial_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> GlweKeyswitchKey<C> {
    /// Mutable variant of [`GlweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> GlweKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_glwe_size = self.output_glwe_size;
        let poly_size = self.poly_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        GlweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            poly_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_glwe_ciphertext_list(&mut self) -> GlweCiphertextListMutView<'_, Scalar> {
        let output_glwe_size = self.output_glwe_size();
        let poly_size = self.polynomial_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        GlweCiphertextListMutView::from_container(
            self.as_mut(),
            output_glwe_size,
            poly_size,
            ciphertext_modulus,
        )
    }
}

/// A [`GlweKeyswitchKey`] owning the memory for its own storage.
pub type GlweKeyswitchKeyOwned<Scalar> = GlweKeyswitchKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> GlweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`GlweKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`GlweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_glwe_keyswitch_key`] using this key as output.
    ///
    /// See [`GlweKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_glwe_dimension: GlweDimension,
        output_key_glwe_dimension: GlweDimension,
        poly_size: PolynomialSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_glwe_dimension.0
                    * glwe_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_glwe_dimension.to_glwe_size(),
                        poly_size,
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_glwe_dimension.to_glwe_size(),
            poly_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for GlweKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = GlweCiphertextListCreationMetadata<Scalar>;

    type EntityView<'this> = GlweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> GlweCiphertextListCreationMetadata<Scalar> {
        GlweCiphertextListCreationMetadata(
            self.output_glwe_size(),
            self.polynomial_size(),
            self.ciphertext_modulus(),
        )
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`GlweKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for GlweKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for GlweKeyswitchKey<C>
{
    type EntityMutView<'this> = GlweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
