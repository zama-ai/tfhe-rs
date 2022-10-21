use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorDiscardingDecryptionEngine, GlweCiphertextVectorDiscardingDecryptionError,
};

/// # Description:
/// Implementation of [`GlweCiphertextVectorDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    GlweCiphertextVectorDiscardingDecryptionEngine<
        GlweSecretKey32,
        GlweCiphertextVector32,
        PlaintextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, PlaintextCount, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let mut plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// engine.discard_decrypt_glwe_ciphertext_vector(
    ///     &key,
    ///     &mut plaintext_vector,
    ///     &ciphertext_vector,
    /// )?;
    /// #
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(8));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertextVector32,
    ) -> Result<(), GlweCiphertextVectorDiscardingDecryptionError<Self::EngineError>> {
        GlweCiphertextVectorDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_glwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertextVector32,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorDiscardingDecryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    GlweCiphertextVectorDiscardingDecryptionEngine<
        GlweSecretKey64,
        GlweCiphertextVector64,
        PlaintextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     GlweDimension, PlaintextCount, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let mut plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    /// let ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)?;
    ///
    /// engine.discard_decrypt_glwe_ciphertext_vector(
    ///     &key,
    ///     &mut plaintext_vector,
    ///     &ciphertext_vector,
    /// )?;
    /// #
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(8));
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertextVector64,
    ) -> Result<(), GlweCiphertextVectorDiscardingDecryptionError<Self::EngineError>> {
        GlweCiphertextVectorDiscardingDecryptionError::perform_generic_checks(key, output, input)?;
        unsafe { self.discard_decrypt_glwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn discard_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertextVector64,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}
