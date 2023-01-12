use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A [`seeded GLWE ciphertext`](`SeededLweCiphertext`).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SeededLweCiphertext<Scalar> {
    data: Scalar,
    lwe_size: LweSize,
    compression_seed: CompressionSeed,
}

impl<Scalar> SeededLweCiphertext<Scalar> {
    /// Create a [`SeededLweCiphertext`] from a scalar.
    ///
    /// # Note
    ///
    /// This function only wraps a scalar in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext`] using
    /// this ciphertext as output.
    ///
    /// This docstring exhibits [`SeededLweCiphertext`] primitives usage.
    ///
    ///F # Example
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweCiphertextList creation
    /// let lwe_dimension = LweDimension(742);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweCiphertext
    /// let mut seeded_lwe =
    ///     SeededLweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), seeder.seed().into());
    ///
    /// assert_eq!(seeded_lwe.lwe_size(), lwe_dimension.to_lwe_size());
    ///
    /// let compression_seed = seeded_lwe.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_data: u64 = seeded_lwe.into_scalar();
    ///
    /// // Recreate a list using from_container
    /// let seeded_lwe = SeededLweCiphertext::from_scalar(
    ///     underlying_data,
    ///     lwe_dimension.to_lwe_size(),
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_lwe.lwe_size(), lwe_dimension.to_lwe_size());
    ///
    /// // Decompress the list
    /// let lwe_list = seeded_lwe.decompress_into_lwe_ciphertext();
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// ```
    pub fn from_scalar(
        scalar: Scalar,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
    ) -> SeededLweCiphertext<Scalar> {
        SeededLweCiphertext {
            data: scalar,
            lwe_size,
            compression_seed,
        }
    }

    /// Return the [`LweSize`] of the [`SeededLweCiphertext`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`CompressionSeed`] of the [`SeededLweCiphertext`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Return an immutable view to the [`LweBody`] of a [`SeededLweCiphertext`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn get_body(&self) -> LweBody<&Scalar> {
        LweBody(&self.data)
    }

    /// Return the stored scalar containing the body of the [`SeededLweCiphertext`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn into_scalar(self) -> Scalar {
        self.data
    }

    /// Consume the [`SeededLweCiphertext`] and decompress it into a standard
    /// [`LweCiphertext`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn decompress_into_lwe_ciphertext(self) -> LweCiphertextOwned<Scalar>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_ct = LweCiphertext::new(Scalar::ZERO, self.lwe_size());
        decompress_seeded_lwe_ciphertext::<_, _, ActivatedRandomGenerator>(
            &mut decompressed_ct,
            &self,
        );
        decompressed_ct
    }

    /// Allocate memory and create a new owned [`SeededLweCiphertext`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_lwe_ciphertext`] using this ciphertext as
    /// output.
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn new(
        scalar: Scalar,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
    ) -> SeededLweCiphertext<Scalar> {
        SeededLweCiphertext::from_scalar(scalar, lwe_size, compression_seed)
    }
}

impl<Scalar> SeededLweCiphertext<Scalar> {
    /// Mutable variant of [`SeededLweCiphertext::get_body`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn get_mut_body(&mut self) -> LweBody<&mut Scalar> {
        LweBody(&mut self.data)
    }
}
