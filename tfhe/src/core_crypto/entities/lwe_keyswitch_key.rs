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
/// [`this page`](`crate::core_crypto::entities::GswCiphertext`)).
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweKeyswitchKey<C: Container> {
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_lwe_size: LweSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweKeyswitchKey<C> {
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

impl<Scalar, C: Container<Element = Scalar>> LweKeyswitchKey<C> {
    /// Create a [`LweKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate a
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
    ///
    /// // Create a new LweKeyswitchKey
    /// let lwe_ksk = LweKeyswitchKey::new(
    ///     0u64,
    ///     decomp_base_log,
    ///     decomp_level_count,
    ///     input_lwe_dimension,
    ///     output_lwe_dimension,
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
    /// ```
    pub fn from_container(
        container: C,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        output_lwe_size: LweSize,
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

        LweKeyswitchKey {
            data: container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
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
    pub fn as_view(&self) -> LweKeyswitchKey<&'_ [Scalar]> {
        LweKeyswitchKey::from_container(
            self.as_ref(),
            self.decomp_base_log,
            self.decomp_level_count,
            self.output_lwe_size,
        )
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>> LweKeyswitchKey<C> {
    /// Mutable variant of [`LweKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweKeyswitchKey<&'_ mut [Scalar]> {
        let decomp_base_log = self.decomp_base_log;
        let decomp_level_count = self.decomp_level_count;
        let output_lwe_size = self.output_lwe_size;
        LweKeyswitchKey::from_container(
            self.as_mut(),
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
        )
    }
}

/// A [`LweKeyswitchKey`] owning the memory for its own storage.
pub type LweKeyswitchKeyOwned<Scalar> = LweKeyswitchKey<Vec<Scalar>>;

impl<Scalar: Copy> LweKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`LweKeyswitchKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_keyswitch_key`] using this key as output.
    ///
    /// See [`LweKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
    ) -> LweKeyswitchKeyOwned<Scalar> {
        LweKeyswitchKeyOwned::from_container(
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
        )
    }
}

impl<C: Container> ContiguousEntityContainer for LweKeyswitchKey<C> {
    type Element = C::Element;

    type EntityViewMetadata = LweCiphertextListCreationMetadata;

    type EntityView<'this> = LweCiphertextListView<'this, Self::Element>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) -> LweCiphertextListCreationMetadata {
        LweCiphertextListCreationMetadata(self.output_lwe_size())
    }

    fn get_entity_view_pod_size(&self) -> usize {
        self.input_key_element_encrypted_size()
    }

    /// Unimplemented for [`LweKeyswitchKey`]. At the moment it does not make sense to
    /// return "sub" keyswitch keys.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for LweKeyswitchKey. \
        At the moment it does not make sense to return 'sub' keyswitch keys."
        )
    }
}

impl<C: ContainerMut> ContiguousEntityContainerMut for LweKeyswitchKey<C> {
    type EntityMutView<'this> = LweCiphertextListMutView<'this, Self::Element>
    where
        Self: 'this;

    // At the moment it does not make sense to return "sub" keyswitch keys. So we use a dummy
    // placeholder type here.
    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
