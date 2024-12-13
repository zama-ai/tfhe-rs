//! Module containing the definition of the LweSecretKey.

use tfhe_versionable::Versionize;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::lwe_secret_key::LweSecretKeyVersions;
use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::parameters::LweDimension;
use crate::core_crypto::commons::traits::*;
use crate::named::Named;

/// An [`LWE secret key`](`LweSecretKey`).
///
/// # Formal Definition
///
/// ## LWE Secret Key
///
/// We consider a secret key:
/// $$\vec{s} \in \mathbb{Z}^n$$
/// This vector contains $n$ integers that have been sampled for some distribution which is either
/// uniformly binary, uniformly ternary, gaussian or even uniform.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(LweSecretKeyVersions)]
pub struct LweSecretKey<C: Container> {
    data: C,
}

impl<C: Container> Named for LweSecretKey<C> {
    const NAME: &'static str = "core_crypto::LweSecretKey";
}

impl<T, C: Container<Element = T>> AsRef<[T]> for LweSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for LweSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> LweSecretKey<C> {
    /// Create an [`LweSecretKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LweSecretKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_binary_lwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// This docstring exhibits [`LweSecretKey`] primitives usage.
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweSecretKey creation
    /// let lwe_dimension = LweDimension(600);
    ///
    /// // Create a new LweSecretKey
    /// let lwe_secret_key = LweSecretKey::new_empty_key(0u64, lwe_dimension);
    ///
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_secret_key.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let lwe_secret_key = LweSecretKey::from_container(underlying_container);
    ///
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// ```
    pub fn from_container(container: C) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LweSecretKey"
        );
        Self { data: container }
    }

    /// Return the [`LweDimension`] of the [`LweSecretKey`].
    ///
    /// See [`LweSecretKey::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }

    /// Return a view of the [`LweSecretKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LweSecretKeyView<'_, Scalar> {
        LweSecretKey::from_container(self.as_ref())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweSecretKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> LweSecretKey<C> {
    /// Mutable variant of [`LweSecretKey::as_view`].
    pub fn as_mut_view(&mut self) -> LweSecretKeyMutView<'_, Scalar> {
        LweSecretKey::from_container(self.as_mut())
    }
}

/// An [`LweSecretKey`] owning the memory for its own storage.
pub type LweSecretKeyOwned<Scalar> = LweSecretKey<Vec<Scalar>>;
/// An [`LweSecretKey`] immutably borrowing memory for its own storage.
pub type LweSecretKeyView<'data, Scalar> = LweSecretKey<&'data [Scalar]>;
/// An [`LweSecretKey`] mutably borrowing memory for its own storage.
pub type LweSecretKeyMutView<'data, Scalar> = LweSecretKey<&'data mut [Scalar]>;

impl<Scalar> LweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new empty owned [`LweSecretKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LweSecretKey`] you need to call
    /// [`generate_new_binary`](`Self::generate_new_binary`) or
    /// [`crate::core_crypto::algorithms::generate_binary_lwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// See [`LweSecretKey::from_container`] for usage.
    pub fn new_empty_key(fill_with: Scalar, lwe_dimension: LweDimension) -> Self {
        Self::from_container(vec![fill_with; lwe_dimension.0])
    }

    /// Allocate a new owned [`LweSecretKey`] and fill it with binary coefficients.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweSecretKey creation
    /// let lwe_dimension = LweDimension(742);
    ///
    /// // Create the PRNG
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    /// let mut secret_generator = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    ///
    /// let lwe_secret_key: LweSecretKeyOwned<u64> =
    ///     LweSecretKey::generate_new_binary(lwe_dimension, &mut secret_generator);
    ///
    /// // Check all coefficients are not zero as we just generated a new key
    /// // Note probability of this assert failing is (1/2)^lwe_dimension or ~4.3 * 10^-224 for an
    /// // LWE dimension of 742.
    /// assert!(!lwe_secret_key.as_ref().iter().all(|&elt| elt == 0));
    /// ```
    pub fn generate_new_binary<Gen>(
        lwe_dimension: LweDimension,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> Self
    where
        Scalar: Numeric + RandomGenerable<UniformBinary>,
        Gen: ByteRandomGenerator,
    {
        let mut lwe_sk = Self::new_empty_key(Scalar::ZERO, lwe_dimension);
        generate_binary_lwe_secret_key(&mut lwe_sk, generator);
        lwe_sk
    }
}
