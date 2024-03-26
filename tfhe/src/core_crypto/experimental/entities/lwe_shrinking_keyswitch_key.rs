//! Module containing the definition of the [`LweShrinkingKeyswitchKey`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::commons::parameters::{
    LweSecretKeySharedCoefCount, LweSecretKeyUnsharedCoefCount,
};

/// An [`LWE shrinking keyswitch key`](`LweShrinkingKeyswitchKey`) is an [`LWE keyswitch
/// key`](`LweKeyswitchKey`) where the output key is equal to the beginning of the input key.
///
/// See [`the formal definition of an LWE keyswitch key`](`LweKeyswitchKey#formal-definition`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweShrinkingKeyswitchKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    lwe_ksk: LweKeyswitchKey<C>,
}

impl<T: UnsignedInteger, C: Container<Element = T>> AsRef<[T]> for LweShrinkingKeyswitchKey<C> {
    fn as_ref(&self) -> &[T] {
        self.lwe_ksk.as_ref()
    }
}

impl<T: UnsignedInteger, C: ContainerMut<Element = T>> AsMut<[T]> for LweShrinkingKeyswitchKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.lwe_ksk.as_mut()
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LweShrinkingKeyswitchKey<C> {
    /// Create an [`LweShrinkingKeyswitchKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an LWE
    /// shrinking keyswitch key you need to use
    /// [`crate::core_crypto::experimental::algorithms::generate_lwe_shrinking_keyswitch_key`]
    /// using this key as output.
    ///
    /// This docstring exhibits [`LweShrinkingKeyswitchKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::experimental::prelude::*;
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweShrinkingKeyswitchKey creation
    /// let input_lwe_dimension = LweDimension(1024);
    /// let output_lwe_dimension = LweDimension(600);
    /// let expected_lwe_secret_key_shared_coef_count =
    ///     LweSecretKeySharedCoefCount(output_lwe_dimension.0);
    /// let decomp_base_log = DecompositionBaseLog(4);
    /// let decomp_level_count = DecompositionLevelCount(5);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LweShrinkingKeyswitchKey
    /// let lwe_ksk = LweShrinkingKeyswitchKey::new(
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
    /// assert_eq!(
    ///     lwe_ksk.shared_randomness(),
    ///     expected_lwe_secret_key_shared_coef_count
    /// );
    /// assert_eq!(
    ///     lwe_ksk.unshared_randomness(),
    ///     LweSecretKeyUnsharedCoefCount(
    ///         input_lwe_dimension.0 - expected_lwe_secret_key_shared_coef_count.0
    ///     )
    /// );
    /// assert_eq!(lwe_ksk.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_ksk.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_ksk = LweShrinkingKeyswitchKey::from_container(
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
    /// assert_eq!(
    ///     lwe_ksk.shared_randomness(),
    ///     expected_lwe_secret_key_shared_coef_count
    /// );
    /// assert_eq!(
    ///     lwe_ksk.unshared_randomness(),
    ///     LweSecretKeyUnsharedCoefCount(
    ///         input_lwe_dimension.0 - expected_lwe_secret_key_shared_coef_count.0
    ///     )
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
        let lwe_ksk = LweKeyswitchKey::from_container(
            container,
            decomp_base_log,
            decomp_level_count,
            output_lwe_size,
            ciphertext_modulus,
        );

        let output_key_lwe_dimension = lwe_ksk.output_key_lwe_dimension();
        let unshared_randomness_coef_count =
            LweSecretKeyUnsharedCoefCount(lwe_ksk.input_key_lwe_dimension().0);
        let input_key_lwe_dimension =
            LweDimension(output_key_lwe_dimension.0 + unshared_randomness_coef_count.0);

        assert!(
            output_key_lwe_dimension.0 <= input_key_lwe_dimension.0,
            "The output LweDimension ({output_key_lwe_dimension:?}) \
                must be smaller than the input LweDimension ({input_key_lwe_dimension:?}) \
                for an LweShrinkingKeyswitchKey."
        );

        Self { lwe_ksk }
    }

    pub fn as_lwe_keyswitch_key(&self) -> LweKeyswitchKey<&'_ [Scalar]> {
        self.lwe_ksk.as_view()
    }

    /// Return the [`DecompositionBaseLog`] of the [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.lwe_ksk.decomposition_base_log()
    }

    /// Return the [`DecompositionLevelCount`] of the [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.lwe_ksk.decomposition_level_count()
    }

    /// Return the input [`LweDimension`] of the [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn input_key_lwe_dimension(&self) -> LweDimension {
        LweDimension(self.shared_randomness().0 + self.unshared_randomness().0)
    }

    /// Return the output [`LweDimension`] of the [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn output_key_lwe_dimension(&self) -> LweDimension {
        self.output_lwe_size().to_lwe_dimension()
    }

    /// Return the output [`LweSize`] of the [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn output_lwe_size(&self) -> LweSize {
        self.lwe_ksk.output_lwe_size()
    }

    /// Return the unshared [`LweSecretKeyUnsharedCoefCount`] of randomness of the input and
    /// output [`LweSecretKey`] used to build this [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn unshared_randomness(&self) -> LweSecretKeyUnsharedCoefCount {
        LweSecretKeyUnsharedCoefCount(self.lwe_ksk.input_key_lwe_dimension().0)
    }

    /// Return the shared [`LweSecretKeySharedCoefCount`] of randomness of the input and
    /// output [`LweSecretKey`] used to build this [`LweShrinkingKeyswitchKey`].
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn shared_randomness(&self) -> LweSecretKeySharedCoefCount {
        LweSecretKeySharedCoefCount(self.lwe_ksk.output_key_lwe_dimension().0)
    }

    /// Return the number of elements in an encryption of an input [`LweSecretKey`] element of the
    /// current [`LweShrinkingKeyswitchKey`].
    pub fn input_key_element_encrypted_size(&self) -> usize {
        self.lwe_ksk.input_key_element_encrypted_size()
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.lwe_ksk.into_container()
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.lwe_ksk.ciphertext_modulus()
    }

    /// Return a view of the [`LweShrinkingKeyswitchKey`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> LweShrinkingKeyswitchKey<&'_ [Scalar]> {
        LweShrinkingKeyswitchKey::from_container(
            self.as_ref(),
            self.decomposition_base_log(),
            self.decomposition_level_count(),
            self.output_lwe_size(),
            self.ciphertext_modulus(),
        )
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweShrinkingKeyswitchKey<C> {
    pub fn as_mut_lwe_keyswitch_key(&mut self) -> LweKeyswitchKey<&'_ mut [Scalar]> {
        self.lwe_ksk.as_mut_view()
    }

    /// Mutable variant of [`LweShrinkingKeyswitchKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweShrinkingKeyswitchKey<&'_ mut [Scalar]> {
        let decomposition_base_log = self.decomposition_base_log();
        let decomposition_level_count = self.decomposition_level_count();
        let output_lwe_size = self.output_lwe_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        LweShrinkingKeyswitchKey::from_container(
            self.as_mut(),
            decomposition_base_log,
            decomposition_level_count,
            output_lwe_size,
            ciphertext_modulus,
        )
    }
}

/// An [`LweShrinkingKeyswitchKey`] owning the memory for its own storage.
pub type LweShrinkingKeyswitchKeyOwned<Scalar> = LweShrinkingKeyswitchKey<Vec<Scalar>>;
/// A [`LweShrinkingKeyswitchKey`] immutably borrowing memory for its own storage.
pub type LweShrinkingKeyswitchKeyView<'data, Scalar> = LweShrinkingKeyswitchKey<&'data [Scalar]>;
/// A [`LweShrinkingKeyswitchKey`] mutably borrowing memory for its own storage.
pub type LweShrinkingKeyswitchKeyMutView<'data, Scalar> =
    LweShrinkingKeyswitchKey<&'data mut [Scalar]>;

impl<Scalar: UnsignedInteger> LweShrinkingKeyswitchKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LweShrinkingKeyswitchKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an LWE shrinking keysiwtch key you need to use
    /// [`crate::core_crypto::experimental::algorithms::generate_lwe_shrinking_keyswitch_key`] using
    /// this key as output.
    ///
    /// See [`LweShrinkingKeyswitchKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_key_lwe_dimension: LweDimension,
        output_key_lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            output_key_lwe_dimension.0 <= input_key_lwe_dimension.0,
            "The output LweDimension ({output_key_lwe_dimension:?}) \
            must be smaller than the input LweDimension ({input_key_lwe_dimension:?}) \
            for an LweShrinkingKeyswitchKey."
        );

        let shared_randomness_coef_count = LweSecretKeySharedCoefCount(output_key_lwe_dimension.0);

        let unshared_randomness_coef_count =
            input_key_lwe_dimension.unshared_coef_count_from(shared_randomness_coef_count);

        Self {
            lwe_ksk: LweKeyswitchKey::new(
                fill_with,
                decomp_base_log,
                decomp_level_count,
                LweDimension(unshared_randomness_coef_count.0),
                output_key_lwe_dimension,
                ciphertext_modulus,
            ),
        }
    }
}
