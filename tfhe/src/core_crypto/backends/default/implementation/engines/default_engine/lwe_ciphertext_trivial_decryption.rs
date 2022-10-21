use crate::core_crypto::commons::crypto::encoding::Plaintext as ImplPlaintext;
use crate::core_crypto::prelude::{
    DefaultEngine, LweCiphertext32, LweCiphertext64, LweCiphertextTrivialDecryptionEngine,
    LweCiphertextTrivialDecryptionError, Plaintext32, Plaintext64,
};

impl LweCiphertextTrivialDecryptionEngine<LweCiphertext32, Plaintext32> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext: LweCiphertext32 =
    ///     engine.trivially_encrypt_lwe_ciphertext(lwe_size, &plaintext)?;
    /// let output: Plaintext32 = engine.trivially_decrypt_lwe_ciphertext(&ciphertext)?;
    /// let res = engine.retrieve_plaintext(&output)?;
    /// assert_eq!(res, input);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_lwe_ciphertext(
        &mut self,
        input: &LweCiphertext32,
    ) -> Result<Plaintext32, LweCiphertextTrivialDecryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_decrypt_lwe_ciphertext_unchecked(input)) }
    }

    unsafe fn trivially_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        input: &LweCiphertext32,
    ) -> Plaintext32 {
        Plaintext32(ImplPlaintext(input.0.get_body().0))
    }
}

impl LweCiphertextTrivialDecryptionEngine<LweCiphertext64, Plaintext64> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{LweSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let lwe_size = LweSize(10);
    /// let input = 3_u64 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext: LweCiphertext64 =
    ///     engine.trivially_encrypt_lwe_ciphertext(lwe_size, &plaintext)?;
    ///
    /// let output: Plaintext64 = engine.trivially_decrypt_lwe_ciphertext(&ciphertext)?;
    /// let res = engine.retrieve_plaintext(&output)?;
    /// assert_eq!(res, input);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_lwe_ciphertext(
        &mut self,
        input: &LweCiphertext64,
    ) -> Result<Plaintext64, LweCiphertextTrivialDecryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_decrypt_lwe_ciphertext_unchecked(input)) }
    }

    unsafe fn trivially_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        input: &LweCiphertext64,
    ) -> Plaintext64 {
        Plaintext64(ImplPlaintext(input.0.get_body().0))
    }
}
