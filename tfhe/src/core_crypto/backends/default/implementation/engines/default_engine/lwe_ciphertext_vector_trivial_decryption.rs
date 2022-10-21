use crate::core_crypto::commons::crypto::encoding::{
    Plaintext, PlaintextList as ImplPlaintextList,
};
use crate::core_crypto::prelude::{
    DefaultEngine, LweCiphertextVector32, LweCiphertextVector64, LweCiphertextVectorEntity,
    LweCiphertextVectorTrivialDecryptionEngine, LweCiphertextVectorTrivialDecryptionError,
    PlaintextCount, PlaintextVector32, PlaintextVector64,
};

impl LweCiphertextVectorTrivialDecryptionEngine<LweCiphertextVector32, PlaintextVector32>
    for DefaultEngine
{
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = vec![3_u32 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_vector: LweCiphertextVector32 =
    ///     engine.trivially_encrypt_lwe_ciphertext_vector(lwe_size, &plaintext_vector)?;
    /// let output: PlaintextVector32 =
    ///     engine.trivially_decrypt_lwe_ciphertext_vector(&ciphertext_vector)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(3));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector32,
    ) -> Result<PlaintextVector32, LweCiphertextVectorTrivialDecryptionError<Self::EngineError>>
    {
        unsafe { Ok(self.trivially_decrypt_lwe_ciphertext_vector_unchecked(input)) }
    }

    unsafe fn trivially_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector32,
    ) -> PlaintextVector32 {
        let count = PlaintextCount(input.lwe_ciphertext_count().0);
        let mut output = ImplPlaintextList::allocate(0u32, count);
        for (plaintext, ciphertext) in output.plaintext_iter_mut().zip(input.0.ciphertext_iter()) {
            *plaintext = Plaintext(ciphertext.get_body().0);
        }
        PlaintextVector32(output)
    }
}

impl LweCiphertextVectorTrivialDecryptionEngine<LweCiphertextVector64, PlaintextVector64>
    for DefaultEngine
{
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = vec![3_u64 << 20; 3];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_vector: LweCiphertextVector64 =
    ///     engine.trivially_encrypt_lwe_ciphertext_vector(lwe_size, &plaintext_vector)?;
    ///
    /// let output: PlaintextVector64 =
    ///     engine.trivially_decrypt_lwe_ciphertext_vector(&ciphertext_vector)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(3));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_lwe_ciphertext_vector(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> Result<PlaintextVector64, LweCiphertextVectorTrivialDecryptionError<Self::EngineError>>
    {
        unsafe { Ok(self.trivially_decrypt_lwe_ciphertext_vector_unchecked(input)) }
    }

    unsafe fn trivially_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        input: &LweCiphertextVector64,
    ) -> PlaintextVector64 {
        let count = PlaintextCount(input.lwe_ciphertext_count().0);
        let mut output = ImplPlaintextList::allocate(0u64, count);
        for (plaintext, ciphertext) in output.plaintext_iter_mut().zip(input.0.ciphertext_iter()) {
            *plaintext = Plaintext(ciphertext.get_body().0);
        }
        PlaintextVector64(output)
    }
}
