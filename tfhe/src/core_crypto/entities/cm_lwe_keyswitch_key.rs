//! Module containing the definition of the [`CmLweKeyswitchKey`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// An [`LWE keyswitch key`](`CmLweKeyswitchKey`).
///
/// # Formal Definition
///
/// ## Key Switching Key
///
/// A key switching key is a vector of Lev ciphertexts (described on the bottom of
/// [`this page`](`crate::core_crypto::entities::GswCiphertext#lev-ciphertext`)).
/// It encrypts the coefficient of
/// the [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{in}}$ under the
/// [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{out}}$.
///
/// $$\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{s}\_{\mathsf{out}}} = \left(
/// \overline{\mathsf{ct}\_0}, \cdots , \overline{\mathsf{ct}\_{n\_{\mathsf{in}}-1}}\right)
/// \subseteq \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)\cdot n\_{\mathsf{in}}}$$
///
/// where $\vec{s}\_{\mathsf{in}} = \left( s\_0 , \cdots , s\_{\mathsf{in}-1} \right)$ and for all
/// $0\le i <n\_{\mathsf{in}}$ we have $\overline{\mathsf{ct}\_i} \in
/// \mathsf{Lev}\_{\vec{s}\_{\mathsf{out}}}^{\beta, \ell}\left(s\_i\right)$.
///
/// ## LWE Keyswitch
///
/// This homomorphic procedure transforms an input
/// [`LWE ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
/// $\mathsf{ct}\_{\mathsf{in}} =
/// \left( \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in \mathsf{LWE}^{n\_{\mathsf{in}}}\_
/// {\vec{s}\_{\mathsf{in}}}( \mathsf{pt} ) \subseteq \mathbb{Z}\_q^{(n\_{\mathsf{in}}+1)}$ into an
/// output [`LWE ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
/// $\mathsf{ct}\_{\mathsf{out}} =
/// \left( \vec{a}\_{\mathsf{out}} , b\_{\mathsf{out}}\right) \in
/// \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}( \mathsf{pt} )\subseteq
/// \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$ where $n\_{\mathsf{in}} = |\vec{s}\_{\mathsf{in}}|$ and
/// $n\_{\mathsf{out}} = |\vec{s}\_{\mathsf{out}}|$. It requires a
/// [`key switching key`](`crate::core_crypto::entities::CmLweKeyswitchKey`).
/// The input ciphertext is encrypted under the
/// [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{in}}$ and the output ciphertext is
/// encrypted under the [`LWE secret key`](`crate::core_crypto::entities::LweSecretKey`)
/// $\vec{s}\_{\mathsf{out}}$.
///
/// $$\mathsf{ct}\_{\mathsf{in}} \in \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}(
/// \mathsf{pt} ) ~~~~~~~~~~\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow
/// \vec{s}\_{\mathsf{out}}}$$ $$ \mathsf{keyswitch}\left(\mathsf{ct}\_{\mathsf{in}} , \mathsf{KSK}
/// \right) \rightarrow \mathsf{ct}\_{\mathsf{out}} \in
/// \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}} \left( \mathsf{pt} \right)$$
///
/// ## Algorithm
/// ###### inputs:
/// - $\mathsf{ct}\_{\mathsf{in}} = \left( \vec{a}\_{\mathsf{in}} , b\_{\mathsf{in}}\right) \in
///   \mathsf{LWE}^{n\_{\mathsf{in}}}\_{\vec{s}\_{\mathsf{in}}}( \mathsf{pt} )$: an [`LWE
///   ciphertext`](`LweCiphertext`) with $\vec{a}\_{\mathsf{in}}=\left(a\_0, \cdots
///   a\_{n\_{\mathsf{in}}-1}\right)$
/// - $\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{s}\_{\mathsf{out}}}$: a [`key switching
///   key`](`crate::core_crypto::entities::CmLweKeyswitchKey`)
///
/// ###### outputs:
/// - $\mathsf{ct}\_{\mathsf{out}} \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}
///   \left( \mathsf{pt} \right)$: an [`LWE
///   ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
///
/// ###### algorithm:
/// 1. set $\mathsf{ct}=\left( 0 , \cdots , 0 ,  b\_{\mathsf{in}} \right) \in
///    \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$
/// 2. compute $\mathsf{ct}\_{\mathsf{out}} = \mathsf{ct} - \sum\_{i=0}^{n\_{\mathsf{in}}-1}
///    \mathsf{decompProduct}\left( a\_i , \overline{\mathsf{ct}\_i} \right)$
/// 3. output $\mathsf{ct}\_{\mathsf{out}}$
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
//  Versionize
// #[versionize(LweKeyswitchKeyVersions)]
pub struct CmLweKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_dimension: LweDimension,
    output_lwe_dimension: LweDimension,
    cm_dimension: CmDimension,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for CmLweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for CmLweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`LweSecretKey`] element for a
/// [`CmLweKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`LweDimension`].
pub fn cm_lwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_dimension: LweDimension,
    cm_dimension: CmDimension,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * (output_lwe_dimension.0 + cm_dimension.0)
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CmLweKeyswitchKey<C> {
    /// Create an [`CmLweKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`CmLweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// This docstring exhibits [`CmLweKeyswitchKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for CmLweKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    /// let cm_dimension = CmDimension(2);
    ///
    /// // Create a new CmLweKeyswitchKey
    /// let lwe_ksk = CmLweKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_lwe_dimension,
    ///     cm_dimension,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_ksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_ksk = CmLweKeyswitchKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_lwe_dimension,
    ///     cm_dimension,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        output_lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an CmLweKeyswitchKey"
        );
        assert!(
            container.container_len()
                % (decomp_level_count.0 * (output_lwe_dimension.0 + cm_dimension.0))
                == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * (output_lwe_dimension + cm_dimension): {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_dimension: {output_lwe_dimension:?}.",
            decomp_level_count.0 * (output_lwe_dimension.0+ cm_dimension.0),
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        }
    }

    /// Return the [`DecompositionBaseLog`] of the [`CmLweKeyswitchKey`].
    ///
    /// See [`CmLweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.decomp_base_log
    }

    /// Return the [`DecompositionLevelCount`] of the [`CmLweKeyswitchKey`].
    ///
    /// See [`CmLweKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.decomp_level_count
    }

    /// Return the input [`LweDimension`] of the [`CmLweKeyswitchKey`].
    ///
    /// See [`CmLweKeyswitchKey::from_container`] for usage.
    pub fn input_lwe_dimension(&self) -> LweDimension {
        self.input_lwe_dimension
    }

    /// Return the output [`LweDimension`] of the [`CmLweKeyswitchKey`].
    ///
    /// See [`CmLweKeyswitchKey::from_container`] for usage.
    pub fn output_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_dimension
    }

    pub fn cm_dimension(&self) -> CmDimension {
        self.cm_dimension
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`CmLweKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        cm_lwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_dimension,
            self.cm_dimension,
        )
    }

    /// Return a view of the [`CmLweKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> CmLweKeyswitchKeyView<'_, Scalar> {
        CmLweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.input_lwe_dimension,
            self.output_lwe_dimension,
            self.cm_dimension,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`CmLweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_lwe_ciphertext_list(&self) -> CmLweCiphertextListView<'_, Scalar> {
        CmLweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_dimension,
            self.cm_dimension,
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> CmLweKeyswitchKey<C> {
    /// Mutable variant of [`CmLweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> CmLweKeyswitchKeyMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let input_lwe_dimension = self.input_lwe_dimension;
        let output_lwe_dimension = self.output_lwe_dimension;
        let cm_dimension = self.cm_dimension;
        let ciphertext_modulus = self.ciphertext_modulus;
        CmLweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_lwe_ciphertext_list(&mut self) -> CmLweCiphertextListMutView<'_, Scalar> {
        let output_lwe_dimension = self.output_lwe_dimension();
        let cm_dimension = self.cm_dimension;
        let ciphertext_modulus = self.ciphertext_modulus();
        CmLweCiphertextListMutView::from_container(
            self.as_mut(),
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

/// An [`CmLweKeyswitchKey`] owning the memory for its own storage.
pub type CmLweKeyswitchKeyOwned<Scalar> = CmLweKeyswitchKey<Vec<Scalar>>;
/// An [`CmLweKeyswitchKey`] immutably borrowing memory for its own storage.
pub type CmLweKeyswitchKeyView<'data, Scalar> = CmLweKeyswitchKey<&'data [Scalar]>;
/// An [`CmLweKeyswitchKey`] mutably borrowing memory for its own storage.
pub type CmLweKeyswitchKeyMutView<'data, Scalar> = CmLweKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> CmLweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`CmLweKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`CmLweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// See [`CmLweKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
        cm_dimension: CmDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * cm_lwe_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_lwe_dimension,
                        cm_dimension,
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            input_key_lwe_dimension,
            output_key_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct CmLweKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger> {
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub input_lwe_dimension: LweDimension,
    pub output_lwe_dimension: LweDimension,
    pub cm_dimension: CmDimension,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C>
    for CmLweKeyswitchKey<C>
{
    type Metadata = CmLweKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let CmLweKeyswitchKeyCreationMetadata {
            decomp_base_log,
            decomp_level_count,
            output_lwe_dimension,
            ciphertext_modulus,
            input_lwe_dimension,
            cm_dimension,
        } = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            output_lwe_dimension,
            cm_dimension,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for CmLweKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = CmLweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this>
        = CmLweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = CmLweKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this>
        = CmLweKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        CmLweCiphertextListCreationMetadata {
            ciphertext_modulus: self.ciphertext_modulus(),
            lwe_dimension: self.output_lwe_dimension,
            cm_dimension: self.cm_dimension,
        }
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        CmLweKeyswitchKeyCreationMetadata {
            decomp_base_log: self.decomposition_base_log(),
            decomp_level_count: self.decomposition_level_count(),
            output_lwe_dimension: self.output_lwe_dimension,
            input_lwe_dimension: self.input_lwe_dimension,
            cm_dimension: self.cm_dimension,
            ciphertext_modulus: self.ciphertext_modulus(),
        }
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for CmLweKeyswitchKey<C>
{
    type EntityMutView<'this>
        = CmLweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this>
        = CmLweKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}
