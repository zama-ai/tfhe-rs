//! Module containing the definition of the [`SeededLweCiphertext`].

use tfhe_versionable::Versionize;

use crate::conformance::ParameterSetConformant;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::backward_compatibility::entities::seeded_lwe_ciphertext::SeededLweCiphertextVersions;
use crate::core_crypto::commons::math::random::{CompressionSeed, DefaultRandomGenerator};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::misc::check_encrypted_content_respects_mod;

/// A [`seeded GLWE ciphertext`](`SeededLweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Versionize)]
#[versionize(SeededLweCiphertextVersions)]
pub struct SeededLweCiphertext<Scalar: UnsignedInteger> {
    data: Scalar,
    lwe_size: LweSize,
    compression_seed: CompressionSeed,
    ciphertext_modulus: CiphertextModulus<Scalar>,
}

impl<T: UnsignedInteger> ParameterSetConformant for SeededLweCiphertext<T> {
    type ParameterSet = LweCiphertextConformanceParams<T>;

    fn is_conformant(&self, lwe_ct_parameters: &LweCiphertextConformanceParams<T>) -> bool {
        let Self {
            data,
            lwe_size,
            compression_seed: _,
            ciphertext_modulus,
        } = self;

        check_encrypted_content_respects_mod::<T, &[T]>(
            &std::slice::from_ref(data),
            lwe_ct_parameters.ct_modulus,
        ) && *lwe_size == lwe_ct_parameters.lwe_dim.to_lwe_size()
            && *ciphertext_modulus == lwe_ct_parameters.ct_modulus
    }
}

// These accessors are used to create invalid objects and test the conformance functions
// But these functions should not be used in other contexts, hence the `#[cfg(test)]`
#[cfg(test)]
#[allow(dead_code)]
impl<Scalar: UnsignedInteger> SeededLweCiphertext<Scalar> {
    pub(crate) fn get_mut_lwe_size(&mut self) -> &mut LweSize {
        &mut self.lwe_size
    }

    pub(crate) fn get_mut_compressed_seed(&mut self) -> &mut CompressionSeed {
        &mut self.compression_seed
    }

    pub(crate) fn get_mut_ciphertext_modulus(&mut self) -> &mut CiphertextModulus<Scalar> {
        &mut self.ciphertext_modulus
    }

    pub(crate) fn get_mut_data(&mut self) -> &mut Scalar {
        &mut self.data
    }
}

impl<Scalar: UnsignedInteger> SeededLweCiphertext<Scalar> {
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
    /// ```rust
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweCiphertextList creation
    /// let lwe_dimension = LweDimension(742);
    /// let ciphertext_modulus = CiphertextModulus::new_native();
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweCiphertext
    /// let seeded_lwe = SeededLweCiphertext::new(
    ///     0u64,
    ///     lwe_dimension.to_lwe_size(),
    ///     seeder.seed().into(),
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(seeded_lwe.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe.ciphertext_modulus(), ciphertext_modulus);
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
    ///     ciphertext_modulus,
    /// );
    ///
    /// assert_eq!(seeded_lwe.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe.ciphertext_modulus(), ciphertext_modulus);
    ///
    /// // Decompress the list
    /// let lwe_list = seeded_lwe.decompress_into_lwe_ciphertext();
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(lwe_list.ciphertext_modulus(), ciphertext_modulus);
    /// ```
    pub fn from_scalar(
        scalar: Scalar,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self {
            data: scalar,
            lwe_size,
            compression_seed,
            ciphertext_modulus,
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
        self.compression_seed.clone()
    }

    /// Return an immutable view to the [`LweBody`] of a [`SeededLweCiphertext`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn get_body(&self) -> LweBodyRef<'_, Scalar> {
        LweBodyRef::new(&self.data, self.ciphertext_modulus)
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
        let mut decompressed_ct =
            LweCiphertext::new(Scalar::ZERO, self.lwe_size(), self.ciphertext_modulus());
        decompress_seeded_lwe_ciphertext::<_, _, DefaultRandomGenerator>(
            &mut decompressed_ct,
            &self,
        );
        decompressed_ct
    }

    pub fn ciphertext_modulus(&self) -> CiphertextModulus<Scalar> {
        self.ciphertext_modulus
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
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> Self {
        Self::from_scalar(scalar, lwe_size, compression_seed, ciphertext_modulus)
    }
}

impl<Scalar: UnsignedInteger> SeededLweCiphertext<Scalar> {
    /// Mutable variant of [`SeededLweCiphertext::get_body`].
    ///
    /// See [`SeededLweCiphertext::from_scalar`] for usage.
    pub fn get_mut_body(&mut self) -> LweBodyRefMut<'_, Scalar> {
        LweBodyRefMut::new(&mut self.data, self.ciphertext_modulus)
    }
}
