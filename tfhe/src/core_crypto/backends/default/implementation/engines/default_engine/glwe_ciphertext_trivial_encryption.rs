use crate::core_crypto::prelude::GlweSize;

use crate::core_crypto::backends::default::entities::{
    GlweCiphertext32, GlweCiphertext64, PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::core_crypto::specification::engines::{
    GlweCiphertextTrivialEncryptionEngine, GlweCiphertextTrivialEncryptionError,
};

use crate::core_crypto::backends::default::engines::DefaultEngine;

impl GlweCiphertextTrivialEncryptionEngine<PlaintextVector32, GlweCiphertext32> for DefaultEngine {
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
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_glwe_ciphertext(
        &mut self,
        glwe_size: GlweSize,
        input: &PlaintextVector32,
    ) -> Result<GlweCiphertext32, GlweCiphertextTrivialEncryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_encrypt_glwe_ciphertext_unchecked(glwe_size, input)) }
    }

    unsafe fn trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        glwe_size: GlweSize,
        input: &PlaintextVector32,
    ) -> GlweCiphertext32 {
        let ciphertext: ImplGlweCiphertext<Vec<u32>> =
            ImplGlweCiphertext::new_trivial_encryption(glwe_size, &input.0);
        GlweCiphertext32(ciphertext)
    }
}

impl GlweCiphertextTrivialEncryptionEngine<PlaintextVector64, GlweCiphertext64> for DefaultEngine {
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
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_glwe_ciphertext(
        &mut self,
        glwe_size: GlweSize,
        input: &PlaintextVector64,
    ) -> Result<GlweCiphertext64, GlweCiphertextTrivialEncryptionError<Self::EngineError>> {
        unsafe { Ok(self.trivially_encrypt_glwe_ciphertext_unchecked(glwe_size, input)) }
    }

    unsafe fn trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        glwe_size: GlweSize,
        input: &PlaintextVector64,
    ) -> GlweCiphertext64 {
        let ciphertext: ImplGlweCiphertext<Vec<u64>> =
            ImplGlweCiphertext::new_trivial_encryption(glwe_size, &input.0);
        GlweCiphertext64(ciphertext)
    }
}
