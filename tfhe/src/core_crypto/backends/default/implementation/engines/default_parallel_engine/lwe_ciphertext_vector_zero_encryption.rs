use crate::core_crypto::prelude::{
    CiphertextCount, DefaultParallelEngine, LweCiphertextCount, PlaintextCount, Variance,
};

use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
};
use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::commons::crypto::lwe::LweList as ImplLweList;
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorZeroEncryptionEngine, LweCiphertextVectorZeroEncryptionError,
};
use crate::core_crypto::specification::entities::LweSecretKeyEntity;

/// # Description:
/// Implementation of [`LweCiphertextVectorZeroEncryptionEngine`] for [`DefaultParallelEngine`] that
/// operates on 32 bits integers.
impl LweCiphertextVectorZeroEncryptionEngine<LweSecretKey32, LweCiphertextVector32>
    for DefaultParallelEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let ciphertext_count = LweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut par_engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext_vector =
    ///     par_engine.zero_encrypt_lwe_ciphertext_vector(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(ciphertext_vector.lwe_ciphertext_count(), ciphertext_count);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorZeroEncryptionError<Self::EngineError>>
    {
        LweCiphertextVectorZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_vector_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> LweCiphertextVector32 {
        let mut vector = ImplLweList::allocate(
            0u32,
            key.lwe_dimension().to_lwe_size(),
            CiphertextCount(count.0),
        );
        let plaintexts = ImplPlaintextList::allocate(0u32, PlaintextCount(count.0));
        key.0.par_encrypt_lwe_list(
            &mut vector,
            &plaintexts,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertextVector32(vector)
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorZeroEncryptionEngine`] for [`DefaultParallelEngine`] that
/// operates on 64 bits integers.
impl LweCiphertextVectorZeroEncryptionEngine<LweSecretKey64, LweCiphertextVector64>
    for DefaultParallelEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{LweCiphertextCount, LweDimension, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(2);
    /// let ciphertext_count = LweCiphertextCount(3);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let mut par_engine = DefaultParallelEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    ///
    /// let ciphertext_vector =
    ///     par_engine.zero_encrypt_lwe_ciphertext_vector(&key, noise, ciphertext_count)?;
    /// #
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(ciphertext_vector.lwe_ciphertext_count(), ciphertext_count);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorZeroEncryptionError<Self::EngineError>>
    {
        LweCiphertextVectorZeroEncryptionError::perform_generic_checks(count)?;
        Ok(unsafe { self.zero_encrypt_lwe_ciphertext_vector_unchecked(key, noise, count) })
    }

    unsafe fn zero_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        noise: Variance,
        count: LweCiphertextCount,
    ) -> LweCiphertextVector64 {
        let mut vector = ImplLweList::allocate(
            0u64,
            key.lwe_dimension().to_lwe_size(),
            CiphertextCount(count.0),
        );
        let plaintexts = ImplPlaintextList::allocate(0u64, PlaintextCount(count.0));
        key.0.par_encrypt_lwe_list(
            &mut vector,
            &plaintexts,
            noise,
            &mut self.encryption_generator,
        );
        LweCiphertextVector64(vector)
    }
}
