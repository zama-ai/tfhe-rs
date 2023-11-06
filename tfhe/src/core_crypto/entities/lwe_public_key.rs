//! Module containing the definition of the [`LwePublicKey`].

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// An LwePublicKey is literally an LweCiphertextList, so we wrap an LweCiphertextList and use
// Deref to have access to all the primitives of the LweCiphertextList easily

/// A [`public LWE encryption key`](`LwePublicKey`).
///
/// This is a wrapper type of [`LweCiphertextList`], [`std::ops::Deref`] and [`std::ops::DerefMut`]
/// are implemented to dereference to the underlying [`LweCiphertextList`] for ease of use. See
/// [`LweCiphertextList`] for additional methods.
///
/// # Formal Definition
///
/// ## LWE Public Key
///
/// An LWE public key contains $m$ LWE encryptions of 0 under a secret key
/// $\vec{s}\in\mathbb{Z}\_q^n$ where $n$ is the LWE dimension of the ciphertexts contained in the
/// public key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePublicKey<C: Container>
where
    C::Element: UnsignedInteger,
{
    lwe_list: LweCiphertextList<C>,
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> std::ops::Deref for LwePublicKey<C> {
    type Target = LweCiphertextList<C>;

    fn deref(&self) -> &LweCiphertextList<C> {
        &self.lwe_list
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> std::ops::DerefMut
    for LwePublicKey<C>
{
    fn deref_mut(&mut self) -> &mut LweCiphertextList<C> {
        &mut self.lwe_list
    }
}

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> LwePublicKey<C> {
    /// Create an [`LwePublicKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LwePublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_public_key`] using this key as output.
    ///
    /// This docstring exhibits [`LwePublicKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePublicKey creation
    /// let lwe_size = LweSize(600);
    /// let zero_encryption_count = LwePublicKeyZeroEncryptionCount(3);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Create a new LwePublicKey
    /// let lwe_public_key =
    ///     LwePublicKey::new(0u64, lwe_size, zero_encryption_count, ciphertext_modulus);
    ///
    /// // This is a method from LweCiphertextList
    /// assert_eq!(lwe_public_key.lwe_size(), lwe_size);
    /// // This is a method from LwePublicKey
    /// assert_eq!(
    ///     lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    /// assert_eq!(lwe_public_key.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_public_key.into_container();
    ///
    /// // Recreate a public key using from_container
    /// let lwe_public_key =
    ///     LwePublicKey::from_container(underlying_container, lwe_size, ciphertext_modulus);
    ///
    /// assert_eq!(lwe_public_key.lwe_size(), lwe_size);
    /// assert_eq!(
    ///     lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    /// assert_eq!(lwe_public_key.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LwePublicKey"
        );
        Self {
            lwe_list: LweCiphertextList::from_container(container, lwe_size, ciphertext_modulus),
        }
    }

    /// Return the [`LwePublicKeyZeroEncryptionCount`] of the [`LwePublicKey`].
    ///
    /// See [`LwePublicKey::from_container`] for usage.
    pub fn zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.lwe_ciphertext_count().0)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LwePublicKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.lwe_list.into_container()
    }

    /// Return a view of the [`LwePublicKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LwePublicKey<&'_ [Scalar]> {
        LwePublicKey::from_container(self.as_ref(), self.lwe_size(), self.ciphertext_modulus())
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LwePublicKey<C> {
    /// Mutable variant of [`LwePublicKey::as_view`].
    pub fn as_mut_view(&mut self) -> LwePublicKey<&'_ mut [Scalar]> {
        let lwe_size = self.lwe_size();
        let ciphertext_modulus = self.ciphertext_modulus();
        LwePublicKey::from_container(self.as_mut(), lwe_size, ciphertext_modulus)
    }
}

/// An [`LwePublicKey`] owning the memory for its own storage.
pub type LwePublicKeyOwned<Scalar> = LwePublicKey<Vec<Scalar>>;

impl<Scalar: UnsignedInteger> LwePublicKeyOwned<Scalar> {
    /// Allocate memory and create a new owned [`LwePublicKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LwePublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_public_key`] using this key as output.
    ///
    /// See [`LwePublicKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        zero_encryption_count: LwePublicKeyZeroEncryptionCount,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_container(
            vec![fill_with; lwe_size.0 * zero_encryption_count.0],
            lwe_size,
            ciphertext_modulus,
        )
    }
}
