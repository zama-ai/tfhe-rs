use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::specification::engines::{
    LweCiphertextVectorDiscardingDecryptionEngine, LweCiphertextVectorDiscardingDecryptionError,
};

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    LweCiphertextVectorDiscardingDecryptionEngine<
        LweSecretKey32,
        LweCiphertextVector32,
        PlaintextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, PlaintextCount, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey32 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let mut plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector: LweCiphertextVector32 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// engine.discard_decrypt_lwe_ciphertext_vector(
    ///     &key,
    ///     &mut plaintext_vector,
    ///     &ciphertext_vector,
    /// )?;
    /// #
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(18));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        output: &mut PlaintextVector32,
        input: &LweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorDiscardingDecryptionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_lwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut PlaintextVector32,
        input: &LweCiphertextVector32,
    ) {
        key.0.decrypt_lwe_list(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextVectorDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    LweCiphertextVectorDiscardingDecryptionEngine<
        LweSecretKey64,
        LweCiphertextVector64,
        PlaintextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     LweCiphertextCount, LweDimension, PlaintextCount, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: LweSecretKey64 = engine.generate_new_lwe_secret_key(lwe_dimension)?;
    /// let mut plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector: LweCiphertextVector64 =
    ///     engine.encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// engine.discard_decrypt_lwe_ciphertext_vector(
    ///     &key,
    ///     &mut plaintext_vector,
    ///     &ciphertext_vector,
    /// )?;
    /// #
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(18));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextVector64,
        input: &LweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorDiscardingDecryptionError<Self::EngineError>> {
        LweCiphertextVectorDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_lwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextVector64,
        input: &LweCiphertextVector64,
    ) {
        key.0.decrypt_lwe_list(&mut output.0, &input.0);
    }
}
