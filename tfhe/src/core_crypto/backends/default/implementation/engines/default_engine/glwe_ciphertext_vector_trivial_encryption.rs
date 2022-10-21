use crate::core_crypto::prelude::GlweSize;

use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::glwe::GlweList as ImplGlweList;
use crate::core_crypto::prelude::{
    CiphertextCount, GlweCiphertextCount, PlaintextVectorEntity, PolynomialSize,
};
use crate::core_crypto::specification::engines::{
    GlweCiphertextVectorTrivialEncryptionEngine, GlweCiphertextVectorTrivialEncryptionError,
};

impl GlweCiphertextVectorTrivialEncryptionEngine<PlaintextVector32, GlweCiphertextVector32>
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
    ///
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_ciphertext_count(), ciphertext_count);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_glwe_ciphertext_vector(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector32,
    ) -> Result<GlweCiphertextVector32, GlweCiphertextVectorTrivialEncryptionError<Self::EngineError>>
    {
        GlweCiphertextVectorTrivialEncryptionError::perform_generic_checks(
            glwe_ciphertext_count,
            input,
        )?;
        unsafe {
            Ok(self.trivially_encrypt_glwe_ciphertext_vector_unchecked(
                glwe_size,
                glwe_ciphertext_count,
                input,
            ))
        }
    }

    unsafe fn trivially_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector32,
    ) -> GlweCiphertextVector32 {
        let mut ciphertext_vector: ImplGlweList<Vec<u32>> = ImplGlweList::allocate(
            0_u32,
            PolynomialSize(input.plaintext_count().0 / glwe_ciphertext_count.0),
            glwe_size.to_glwe_dimension(),
            CiphertextCount(glwe_ciphertext_count.0),
        );
        ciphertext_vector.fill_with_trivial_encryption(&input.0);
        GlweCiphertextVector32(ciphertext_vector)
    }
}

impl GlweCiphertextVectorTrivialEncryptionEngine<PlaintextVector64, GlweCiphertextVector64>
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
    ///
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_ciphertext_count(), ciphertext_count);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_glwe_ciphertext_vector(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector64,
    ) -> Result<GlweCiphertextVector64, GlweCiphertextVectorTrivialEncryptionError<Self::EngineError>>
    {
        GlweCiphertextVectorTrivialEncryptionError::perform_generic_checks(
            glwe_ciphertext_count,
            input,
        )?;
        unsafe {
            Ok(self.trivially_encrypt_glwe_ciphertext_vector_unchecked(
                glwe_size,
                glwe_ciphertext_count,
                input,
            ))
        }
    }

    unsafe fn trivially_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        glwe_size: GlweSize,
        glwe_ciphertext_count: GlweCiphertextCount,
        input: &PlaintextVector64,
    ) -> GlweCiphertextVector64 {
        let mut ciphertext_vector: ImplGlweList<Vec<u64>> = ImplGlweList::allocate(
            0_u64,
            PolynomialSize(input.plaintext_count().0 / glwe_ciphertext_count.0),
            glwe_size.to_glwe_dimension(),
            CiphertextCount(glwe_ciphertext_count.0),
        );
        ciphertext_vector.fill_with_trivial_encryption(&input.0);
        GlweCiphertextVector64(ciphertext_vector)
    }
}
