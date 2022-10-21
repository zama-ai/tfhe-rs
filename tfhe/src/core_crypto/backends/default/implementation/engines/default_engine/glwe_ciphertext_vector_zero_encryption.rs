use crate::core_crypto::prelude::{CiphertextCount, GlweCiphertextCount, Variance};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
};
use crate::core_crypto::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorZeroEncryptionEngine, GlweCiphertextVectorZeroEncryptionError,
};
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GlweCiphertextVectorZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl GlweCiphertextVectorZeroEncryptionEngine<GlweSecretKey32, GlweCiphertextVector32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_count = GlweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let ciphertext_vector =
    ///     engine.zero_encrypt_glwe_ciphertext_vector(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_vector.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> Result<GlweCiphertextVector32, GlweCiphertextVectorZeroEncryptionError<Self::EngineError>>
    {
        GlweCiphertextVectorZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_glwe_ciphertext_vector_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> GlweCiphertextVector32 {
        let mut ciphertext_vector = ImplGlweList::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(count.0),
        );
        key.0.encrypt_zero_glwe_list(
            &mut ciphertext_vector,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertextVector32(ciphertext_vector)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorZeroEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl GlweCiphertextVectorZeroEncryptionEngine<GlweSecretKey64, GlweCiphertextVector64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweCiphertextCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let ciphertext_count = GlweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let ciphertext_vector =
    ///     engine.zero_encrypt_glwe_ciphertext_vector(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_vector.glwe_ciphertext_count(), ciphertext_count);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> Result<GlweCiphertextVector64, GlweCiphertextVectorZeroEncryptionError<Self::EngineError>>
    {
        GlweCiphertextVectorZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_glwe_ciphertext_vector_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        noise: Variance,
        count: GlweCiphertextCount,
    ) -> GlweCiphertextVector64 {
        let mut ciphertext_vector = ImplGlweList::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(count.0),
        );
        key.0.encrypt_zero_glwe_list(
            &mut ciphertext_vector,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertextVector64(ciphertext_vector)
    }
}
