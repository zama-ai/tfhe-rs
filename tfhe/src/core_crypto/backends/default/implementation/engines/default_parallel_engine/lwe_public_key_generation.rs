use crate::core_crypto::backends::default::entities::{
    LwePublicKey32, LwePublicKey64, LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::prelude::{
    DefaultParallelEngine, LweCiphertextCount, LwePublicKeyZeroEncryptionCount, Variance,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorZeroEncryptionEngine, LwePublicKeyGenerationEngine,
    LwePublicKeyGenerationError,
};

/// # Description:
/// Implementation of [`LwePublicKeyGenerationEngine`] for [`DefaultParallelEngine`] that operates
/// on 32 bits integers.
impl LwePublicKeyGenerationEngine<LweSecretKey32, LwePublicKey32> for DefaultParallelEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweDimension, LwePublicKeyZeroEncryptionCount, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let lwe_public_key_zero_encryption_count = LwePublicKeyZeroEncryptionCount(42);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut par_engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let public_key: LwePublicKey32 = par_engine.generate_new_lwe_public_key(
    ///     &lwe_secret_key,
    ///     noise,
    ///     lwe_public_key_zero_encryption_count,
    /// )?;
    ///
    /// assert_eq!(public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     public_key.lwe_zero_encryption_count(),
    ///     lwe_public_key_zero_encryption_count
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_public_key(
        &mut self,
        lwe_secret_key: &LweSecretKey32,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<LwePublicKey32, LwePublicKeyGenerationError<Self::EngineError>> {
        LwePublicKeyGenerationError::perform_generic_checks(lwe_public_key_zero_encryption_count)?;
        Ok(unsafe {
            self.generate_new_lwe_public_key_unchecked(
                lwe_secret_key,
                noise,
                lwe_public_key_zero_encryption_count,
            )
        })
    }

    unsafe fn generate_new_lwe_public_key_unchecked(
        &mut self,
        lwe_secret_key: &LweSecretKey32,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> LwePublicKey32 {
        let encrypted_zeros = self.zero_encrypt_lwe_ciphertext_vector_unchecked(
            lwe_secret_key,
            noise,
            LweCiphertextCount(lwe_public_key_zero_encryption_count.0),
        );
        LwePublicKey32(encrypted_zeros.0)
    }
}

/// # Description:
/// Implementation of [`LwePublicKeyGenerationEngine`] for [`DefaultParallelEngine`] that operates
/// on 64 bits integers.
impl LwePublicKeyGenerationEngine<LweSecretKey64, LwePublicKey64> for DefaultParallelEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweDimension, LwePublicKeyZeroEncryptionCount, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let noise = Variance(2_f64.powf(-50.));
    /// let lwe_public_key_zero_encryption_count = LwePublicKeyZeroEncryptionCount(42);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut par_engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let lwe_secret_key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let public_key: LwePublicKey64 = par_engine.generate_new_lwe_public_key(
    ///     &lwe_secret_key,
    ///     noise,
    ///     lwe_public_key_zero_encryption_count,
    /// )?;
    ///
    /// assert_eq!(public_key.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     public_key.lwe_zero_encryption_count(),
    ///     lwe_public_key_zero_encryption_count
    /// );
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_new_lwe_public_key(
        &mut self,
        lwe_secret_key: &LweSecretKey64,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> Result<LwePublicKey64, LwePublicKeyGenerationError<Self::EngineError>> {
        LwePublicKeyGenerationError::perform_generic_checks(lwe_public_key_zero_encryption_count)?;
        Ok(unsafe {
            self.generate_new_lwe_public_key_unchecked(
                lwe_secret_key,
                noise,
                lwe_public_key_zero_encryption_count,
            )
        })
    }

    unsafe fn generate_new_lwe_public_key_unchecked(
        &mut self,
        lwe_secret_key: &LweSecretKey64,
        noise: Variance,
        lwe_public_key_zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> LwePublicKey64 {
        let encrypted_zeros = self.zero_encrypt_lwe_ciphertext_vector_unchecked(
            lwe_secret_key,
            noise,
            LweCiphertextCount(lwe_public_key_zero_encryption_count.0),
        );
        LwePublicKey64(encrypted_zeros.0)
    }
}
