use crate::core_crypto::commons::crypto::encoding::PlaintextList as ImplPlaintextList;
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::prelude::{
    DefaultEngine, GlweCiphertextVector32, GlweCiphertextVector64, GlweCiphertextVectorEntity,
    GlweCiphertextVectorTrivialDecryptionEngine, GlweCiphertextVectorTrivialDecryptionError,
    PlaintextCount, PlaintextVector32, PlaintextVector64,
};

impl GlweCiphertextVectorTrivialDecryptionEngine<GlweCiphertextVector32, PlaintextVector32>
    for DefaultEngine
{
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
    /// let input = vec![3_u32 << 20; 2 * polynomial_size.0];
    /// let ciphertext_count = GlweCiphertextCount(2);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_vector: GlweCiphertextVector32 = engine
    ///     .trivially_encrypt_glwe_ciphertext_vector(
    ///         glwe_dimension.to_glwe_size(),
    ///         ciphertext_count,
    ///         &plaintext_vector,
    ///     )?;
    /// let output: PlaintextVector32 =
    ///     engine.trivially_decrypt_glwe_ciphertext_vector(&ciphertext_vector)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(8));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVector32,
    ) -> Result<PlaintextVector32, GlweCiphertextVectorTrivialDecryptionError<Self::EngineError>>
    {
        Ok(unsafe { self.trivially_decrypt_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn trivially_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVector32,
    ) -> PlaintextVector32 {
        let count = PlaintextCount(input.glwe_ciphertext_count().0 * input.polynomial_size().0);
        let sub_count = PlaintextCount(input.polynomial_size().0);
        let mut output = ImplPlaintextList::allocate(0u32, count);
        for (mut plaintext, ciphertext) in output
            .sublist_iter_mut(sub_count)
            .zip(input.0.ciphertext_iter())
        {
            plaintext
                .as_mut_tensor()
                .fill_with_copy(ciphertext.get_body().as_tensor());
        }
        PlaintextVector32(output)
    }
}

impl GlweCiphertextVectorTrivialDecryptionEngine<GlweCiphertextVector64, PlaintextVector64>
    for DefaultEngine
{
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
    /// let input = vec![3_u64 << 50; 2 * polynomial_size.0];
    /// let ciphertext_count = GlweCiphertextCount(2);
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let ciphertext_vector: GlweCiphertextVector64 = engine
    ///     .trivially_encrypt_glwe_ciphertext_vector(
    ///         glwe_dimension.to_glwe_size(),
    ///         ciphertext_count,
    ///         &plaintext_vector,
    ///     )?;
    /// let output: PlaintextVector64 =
    ///     engine.trivially_decrypt_glwe_ciphertext_vector(&ciphertext_vector)?;
    ///
    /// assert_eq!(output.plaintext_count(), PlaintextCount(8));
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_decrypt_glwe_ciphertext_vector(
        &mut self,
        input: &GlweCiphertextVector64,
    ) -> Result<PlaintextVector64, GlweCiphertextVectorTrivialDecryptionError<Self::EngineError>>
    {
        Ok(unsafe { self.trivially_decrypt_glwe_ciphertext_vector_unchecked(input) })
    }

    unsafe fn trivially_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        input: &GlweCiphertextVector64,
    ) -> PlaintextVector64 {
        let count = PlaintextCount(input.glwe_ciphertext_count().0 * input.polynomial_size().0);
        let sub_count = PlaintextCount(input.polynomial_size().0);
        let mut output = ImplPlaintextList::allocate(0u64, count);
        for (mut plaintext, ciphertext) in output
            .sublist_iter_mut(sub_count)
            .zip(input.0.ciphertext_iter())
        {
            plaintext
                .as_mut_tensor()
                .fill_with_copy(ciphertext.get_body().as_tensor());
        }
        PlaintextVector64(output)
    }
}
