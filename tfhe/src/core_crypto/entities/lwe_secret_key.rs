use crate::core_crypto::commons::parameters::LweDimension;
use crate::core_crypto::commons::traits::*;

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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LweSecretKey<C: Container> {
    data: C,
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
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LweSecretKey creation
    /// let lwe_dimension = LweDimension(600);
    ///
    /// // Create a new LweSecretKey
    /// let lwe_secret_key = LweSecretKey::new(0u64, lwe_dimension);
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
        LweSecretKey { data: container }
    }

    /// Return the [`LweDimension`] of the [`LweSecretKey`].
    ///
    /// See [`LweSecretKey::from_container`] for usage.
    pub fn lwe_dimension(&self) -> LweDimension {
        LweDimension(self.data.container_len())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LweSecretKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

/// An [`LweSecretKey`] owning the memory for its own storage.
pub type LweSecretKeyOwned<Scalar> = LweSecretKey<Vec<Scalar>>;

impl<Scalar> LweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new owned [`LweSecretKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LweSecretKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_binary_lwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// See [`LweSecretKey::from_container`] for usage.
    pub fn new(fill_with: Scalar, lwe_dimension: LweDimension) -> LweSecretKeyOwned<Scalar> {
        LweSecretKeyOwned::from_container(vec![fill_with; lwe_dimension.0])
    }
}
