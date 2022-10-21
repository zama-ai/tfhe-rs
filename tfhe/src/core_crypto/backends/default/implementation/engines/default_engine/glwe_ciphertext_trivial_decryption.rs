use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::commons::math::tensor::AsRefTensor;
use crate::core_crypto::prelude::{
    DefaultEngine, GlweCiphertext32, GlweCiphertext64, GlweCiphertextTrivialDecryptionEngine,
    GlweCiphertextTrivialDecryptionError, PlaintextVector32, PlaintextVector64,
};

impl GlweCiphertextTrivialDecryptionEngine<GlweCiphertext32, PlaintextVector32> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext: GlweCiphertext32 = engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &plaintext_vector)?;
    /// let output: PlaintextVector32 = engine.trivially_decrypt_glwe_ciphertext(&ciphertext)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(polynomial_size.0));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext32,
    ) -> Result<PlaintextVector32, GlweCiphertextTrivialDecryptionError<Self::EngineError>> {
        Ok(unsafe { self.trivially_decrypt_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn trivially_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext32,
    ) -> PlaintextVector32 {
        PlaintextVector32(ImplPlaintextList::from_container(
            input.0.get_body().as_tensor().as_container().to_vec(),
        ))
    }
}

impl GlweCiphertextTrivialDecryptionEngine<GlweCiphertext64, PlaintextVector64> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let input = vec![3_u64 << 20; polynomial_size.0];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext: GlweCiphertext64 = engine
    ///     .trivially_encrypt_glwe_ciphertext(glwe_dimension.to_glwe_size(), &plaintext_vector)?;
    /// let output: PlaintextVector64 = engine.trivially_decrypt_glwe_ciphertext(&ciphertext)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(polynomial_size.0));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_glwe_ciphertext(
        &mut self,
        input: &GlweCiphertext64,
    ) -> Result<PlaintextVector64, GlweCiphertextTrivialDecryptionError<Self::EngineError>> {
        Ok(unsafe { self.trivially_decrypt_glwe_ciphertext_unchecked(input) })
    }

    unsafe fn trivially_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        input: &GlweCiphertext64,
    ) -> PlaintextVector64 {
        PlaintextVector64(ImplPlaintextList::from_container(
            input.0.get_body().as_tensor().as_container().to_vec(),
        ))
    }
}
