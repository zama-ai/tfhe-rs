//! Module containing the definition of the GlweSecretKey.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{RandomGenerable, UniformBinary};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`GLWE secret key`](`GlweSecretKey`)
///
/// # Formal Definition
///
/// ## GLWE Secret Key
///
/// We consider a secret key:
/// $$\vec{S} =\left( S\_0, \ldots, S\_{k-1}\right) \in \mathcal{R}^{k}$$
/// The $k$ polynomials composing $\vec{S}$ contain each $N$ integers coefficients that have been
/// sampled from some distribution which is either uniformly binary, uniformly ternary, gaussian or
/// even uniform.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GlweSecretKey<C: Container> {
    data: C,
    polynomial_size: PolynomialSize,
}

impl<T, C: Container<Element = T>> AsRef<[T]> for GlweSecretKey<C> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>> AsMut<[T]> for GlweSecretKey<C> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>> GlweSecretKey<C> {
    /// Create a [`GlweSecretKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate a
    /// [`GlweSecretKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_binary_glwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// This docstring exhibits [`GlweSecretKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweSecretKey creation
    /// let glwe_dimension = GlweDimension(1);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Create a new GlweSecretKey
    /// let glwe_secret_key = GlweSecretKey::new_empty_key(0u64, glwe_dimension, polynomial_size);
    ///
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = glwe_secret_key.into_container();
    ///
    /// // Recreate a secret key using from_container
    /// let glwe_secret_key = GlweSecretKey::from_container(underlying_container, polynomial_size);
    ///
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    /// ```
    pub fn from_container(container: C, polynomial_size: PolynomialSize) -> Self {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a GlweSecretKey"
        );
        assert!(
            container.container_len() % polynomial_size.0 == 0,
            "The provided container length is not valid. \
        It needs to be dividable by polynomial_size. \
        Got container length: {} and polynomial_size: {polynomial_size:?}",
            container.container_len()
        );
        GlweSecretKey {
            data: container,
            polynomial_size,
        }
    }

    /// Return the [`GlweDimension`] of the [`GlweSecretKey`].
    ///
    /// See [`GlweSecretKey::from_container`] for usage.
    pub fn glwe_dimension(&self) -> GlweDimension {
        GlweDimension(self.data.container_len() / self.polynomial_size.0)
    }

    /// Return the [`PolynomialSize`] of the [`GlweSecretKey`].
    ///
    /// See [`GlweSecretKey::from_container`] for usage.
    pub fn polynomial_size(&self) -> PolynomialSize {
        self.polynomial_size
    }

    /// Consume the [`GlweSecretKey`] and return it interpreted as an [`LweSecretKey`].
    pub fn into_lwe_secret_key(self) -> LweSecretKey<C> {
        LweSecretKey::from_container(self.data)
    }

    /// Borrowes and returns the [`GlweSecretKey`] views as an [`LweSecretKey`].
    pub fn as_lwe_secret_key(&self) -> LweSecretKey<&[C::Element]> {
        LweSecretKey::from_container(self.data.as_ref())
    }

    /// Interpret the [`GlweSecretKey`] as a [`PolynomialList`].
    pub fn as_polynomial_list(&self) -> PolynomialListView<'_, C::Element> {
        PolynomialListView::from_container(self.as_ref(), self.polynomial_size)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`GlweSecretKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }
}

/// A [`GlweSecretKey`] owning the memory for its own storage.
pub type GlweSecretKeyOwned<Scalar> = GlweSecretKey<Vec<Scalar>>;

impl<Scalar> GlweSecretKeyOwned<Scalar>
where
    Scalar: Copy,
{
    /// Allocate memory and create a new empty owned [`GlweSecretKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate a [`GlweSecretKey`] you need to call
    /// [`generate_new_binary`](`Self::generate_new_binary`) or
    /// [`crate::core_crypto::algorithms::generate_binary_glwe_secret_key`] (or other generation
    /// functions working with different coefficient distributions) using this secret key as
    /// output.
    ///
    /// See [`GlweCiphertext::from_container`] for usage.
    pub fn new_empty_key(
        value: Scalar,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKeyOwned<Scalar> {
        GlweSecretKeyOwned::from_container(
            vec![value; glwe_dimension.0 * polynomial_size.0],
            polynomial_size,
        )
    }

    /// Allocate a new owned [`GlweSecretKey`] and fill it with binary coefficients.
    ///
    /// # Example
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for GlweSecretKey creation
    /// let glwe_size = GlweSize(2);
    /// let polynomial_size = PolynomialSize(1024);
    ///
    /// // Create the PRNG
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    /// let mut secret_generator =
    ///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
    ///
    /// let glwe_secret_key: GlweSecretKeyOwned<u64> = GlweSecretKey::generate_new_binary(
    ///     glwe_size.to_glwe_dimension(),
    ///     polynomial_size,
    ///     &mut secret_generator,
    /// );
    ///
    /// // Check all coefficients are not zero as we just generated a new key
    /// // Note probability of this assert failing is (1/2)^polynomial_size or ~5.6 * 10^-309 for a
    /// // polynomial size of 1024.
    /// assert!(glwe_secret_key.as_ref().iter().all(|&elt| elt == 0) == false);
    /// ```
    pub fn generate_new_binary<Gen>(
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
        generator: &mut SecretRandomGenerator<Gen>,
    ) -> GlweSecretKeyOwned<Scalar>
    where
        Scalar: Numeric + RandomGenerable<UniformBinary>,
        Gen: ByteRandomGenerator,
    {
        let mut glwe_sk = Self::new_empty_key(Scalar::ZERO, glwe_dimension, polynomial_size);
        generate_binary_glwe_secret_key(&mut glwe_sk, generator);
        glwe_sk
    }
}
