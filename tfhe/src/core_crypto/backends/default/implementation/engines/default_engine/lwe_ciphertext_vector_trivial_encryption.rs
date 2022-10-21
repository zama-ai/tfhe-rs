use crate::core_crypto::commons::crypto::lwe::LweList as ImplLweList;
use crate::core_crypto::prelude::{
    DefaultEngine, LweCiphertextVector32, LweCiphertextVector64,
    LweCiphertextVectorTrivialEncryptionEngine, LweCiphertextVectorTrivialEncryptionError, LweSize,
    PlaintextVector32, PlaintextVector64,
};

impl LweCiphertextVectorTrivialEncryptionEngine<PlaintextVector32, LweCiphertextVector32>
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
    ///
    /// assert_eq!(ciphertext_vector.lwe_dimension().to_lwe_size(), lwe_size);
    /// assert_eq!(
    ///     ciphertext_vector.lwe_ciphertext_count().0,
    ///     plaintext_vector.plaintext_count().0
    /// );
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_lwe_ciphertext_vector(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector32,
    ) -> Result<LweCiphertextVector32, LweCiphertextVectorTrivialEncryptionError<Self::EngineError>>
    {
        unsafe { Ok(self.trivially_encrypt_lwe_ciphertext_vector_unchecked(lwe_size, input)) }
    }

    unsafe fn trivially_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector32,
    ) -> LweCiphertextVector32 {
        let ciphertexts = ImplLweList::new_trivial_encryption(lwe_size, &input.0);

        LweCiphertextVector32(ciphertexts)
    }
}

impl LweCiphertextVectorTrivialEncryptionEngine<PlaintextVector64, LweCiphertextVector64>
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
    /// assert_eq!(ciphertext_vector.lwe_dimension().to_lwe_size(), lwe_size);
    /// assert_eq!(
    ///     ciphertext_vector.lwe_ciphertext_count().0,
    ///     plaintext_vector.plaintext_count().0
    /// );
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_lwe_ciphertext_vector(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector64,
    ) -> Result<LweCiphertextVector64, LweCiphertextVectorTrivialEncryptionError<Self::EngineError>>
    {
        unsafe { Ok(self.trivially_encrypt_lwe_ciphertext_vector_unchecked(lwe_size, input)) }
    }

    unsafe fn trivially_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        lwe_size: LweSize,
        input: &PlaintextVector64,
    ) -> LweCiphertextVector64 {
        let ciphertexts = ImplLweList::new_trivial_encryption(lwe_size, &input.0);

        LweCiphertextVector64(ciphertexts)
    }
}
