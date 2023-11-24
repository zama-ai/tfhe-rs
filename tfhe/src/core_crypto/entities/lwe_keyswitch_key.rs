//! Module containing the definition of the [`LweKeyswitchKey`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// An [`LWE keyswitch key`](`LweKeyswitchKey`).
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
/// [`key switching key`](`crate::core_crypto::entities::LweKeyswitchKey`).
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
/// - $\mathsf{KSK}\_{\vec{s}\_{\mathsf{in}}\rightarrow \vec{s}\_{\mathsf{out}}}$: a
/// [`key switching key`](`crate::core_crypto::entities::LweKeyswitchKey`)
///
/// ###### outputs:
/// - $\mathsf{ct}\_{\mathsf{out}} \in \mathsf{LWE}^{n\_{\mathsf{out}}}\_{\vec{s}\_{\mathsf{out}}}
///   \left( \mathsf{pt} \right)$: an
/// [`LWE ciphertext`](`crate::core_crypto::entities::LweCiphertext`)
///
/// ###### algorithm:
/// 1. set $\mathsf{ct}=\left( 0 , \cdots , 0 ,  b\_{\mathsf{in}} \right) \in
/// \mathbb{Z}\_q^{(n\_{\mathsf{out}}+1)}$
/// 2. compute $\mathsf{ct}\_{\mathsf{out}} = \mathsf{ct} -
/// \sum\_{i=0}^{n\_{\mathsf{in}}-1} \mathsf{decompProduct}\left( a\_i , \overline{\mathsf{ct}\_i}
/// \right)$
/// 3. output $\mathsf{ct}\_{\mathsf{out}}$
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

/// Return the number of elements in an encryption of an input [`LweSecretKey`] element for a
/// [`LweKeyswitchKey`] given a [`DecompositionLevelCount`] and output [`LweSize`].
pub fn lwe_keyswitch_key_input_key_element_encrypted_size(
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
) -> usize {
    // One ciphertext per level encrypted under the output key
    decomp_level_count.0 * output_lwe_size.0
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweKeyswitchKey<C> {
    /// Create an [`LweKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// This docstring exhibits [`LweKeyswitchKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(600);
    /// let output_lwe_dimension = LweDimension(1024);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweKeyswitchKey
    /// let lwe_ksk = LweKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_lwe_dimension,
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_key_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(
    ///     lwe_ksk.output_lwe_size(),
    ///     output_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_ksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_ksk = LweKeyswitchKey::from_container(
    ///     underlying_container,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     output_lwe_dimension.to_lwe_size(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(lwe_ksk.decomposition_base_log(), decomp_base_log);
    /// assert_eq!(lwe_ksk.decomposition_level_count(), decomp_level_count);
    /// assert_eq!(lwe_ksk.input_key_lwe_dimension(), input_lwe_dimension);
    /// assert_eq!(lwe_ksk.output_key_lwe_dimension(), output_lwe_dimension);
    /// assert_eq!(
    ///     lwe_ksk.output_lwe_size(),
    ///     output_lwe_dimension.to_lwe_size()
    /// );
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_lwe_size: LweSize,
        ciphertext_modulus: CiphertextModulus<C::Element>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweKeyswitchKey"
        );
        assert!(
            container.container_len() % (decomp_level_count.0 * output_lwe_size.0) == 0,
            "The provided container length is not valid. \
        It needs to be dividable by decomp_level_count * output_lwe_size: {}. \
        Got container length: {} and decomp_level_count: {decomp_level_count:?}, \
        output_lwe_size: {output_lwe_size:?}.",
            decomp_level_count.0 * output_lwe_size.0,
            container.container_len()
        );

        Self {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
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

    /// Return the input [`LweDimension`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len() / self.input_key_element_encrypted_size())
    }

    /// Return the output [`LweDimension`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size.to_lwe_dimension()
    }

    /// Return the output [`LweSize`] of the [`LweKeyswitchKey`].
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn output_lwe_size(&self) -> LweSize {
        self.output_lwe_size
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LweKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        lwe_keyswitch_key_input_key_element_encrypted_size(
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    /// Return a view of the [`LweKeyswitchKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweKeyswitchKeyView<'_, Scalar> {
        LweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_size,
            self.ciphertext_modulus,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    pub fn as_lwe_ciphertext_list(&self) -> LweCiphertextListView<'_, Scalar> {
        LweCiphertextListView::from_container(
            self.as_ref(),
            self.output_lwe_size(),
            self.ciphertext_modulus(),
        )
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<C::Element> {
        self.ciphertext_modulus
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweKeyswitchKey<C> {
    /// Mutable variant of [`LweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweKeyswitchKeyMutView<'_, Scalar> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        let ciphertext_modulus = self.ciphertext_modulus;
        LweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        )
    }

    pub fn as_mut_lwe_ciphertext_list(&mut self) -> LweCiphertextListMutView<'_, Scalar> {
        let output_lwe_size = self.output_lwe_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweCiphertextListMutView::from_container(self.as_mut(), output_lwe_size, ciphertext_modulus)
    }
}

/// An [`LweKeyswitchKey`] owning the memory for its own storage.
pub type LweKeyswitchKeyOwned<Scalar> = LweKeyswitchKey<Vec<Scalar>>;
/// An [`LweKeyswitchKey`] immutably borrowing memory for its own storage.
pub type LweKeyswitchKeyView<'data, Scalar> = LweKeyswitchKey<&'data [Scalar]>;
/// An [`LweKeyswitchKey`] mutably borrowing memory for its own storage.
pub type LweKeyswitchKeyMutView<'data, Scalar> = LweKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![
                fill_with;
                input_key_lwe_dimension.0
                    * lwe_keyswitch_key_input_key_element_encrypted_size(
                        decomp_level_count,
                        output_key_lwe_dimension.to_lwe_size()
                    )
            ],
            decomp_base_log,
            decomp_level_count,
            output_key_lwe_dimension.to_lwe_size(),
            ciphertext_modulus,
        )
    }
}

#[derive(Clone, Copy)]
pub struct LweKeyswitchKeyCreationMetadata<Scalar: UnsignedInteger>(
    pub DecompositionBaseLog,
    pub DecompositionLevelCount,
    pub LweSize,
    pub CiphertextModulus<Scalar>,
);

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> CreateFrom<C> for LweKeyswitchKey<C> {
    type Metadata = LweKeyswitchKeyCreationMetadata<Scalar>;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> Self {
        let LweKeyswitchKeyCreationMetadata(
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        ) = meta;
        Self::from_container(
            from,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        )
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> ContiguousEntityContainer
    for LweKeyswitchKey<C>
{
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextListCreationMetadata<Self::Element>;

    type EntityView<'this> = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = LweKeyswitchKeyCreationMetadata<Self::Element>;

    type SelfView<'this> = LweKeyswitchKeyView<'this, Self::Element>
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> Self::EntityViewMetadata {
        LweCiphertextListCreationMetadata(self.output_lwe_size(), self.ciphertext_modulus())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    fn get_self_view_creation_metadata(&self) -> Self::SelfViewMetadata {
        LweKeyswitchKeyCreationMetadata(
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.output_lwe_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> ContiguousEntityContainerMut
    for LweKeyswitchKey<C>
{
    type EntityMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    type SelfMutView<'this> = LweKeyswitchKeyMutView<'this, Self::Element>
    where
        Self: 'this;
}
