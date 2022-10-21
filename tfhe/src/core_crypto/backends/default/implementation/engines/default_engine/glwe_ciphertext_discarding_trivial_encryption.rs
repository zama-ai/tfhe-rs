use crate::core_crypto::backends::default::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweCiphertextMutView32, GlweCiphertextMutView64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::specification::engines::{
    GlweCiphertextDiscardingTrivialEncryptionEngine, GlweCiphertextDiscardingTrivialEncryptionError,
};

use crate::core_crypto::backends::default::engines::DefaultEngine;

impl GlweCiphertextDiscardingTrivialEncryptionEngine<PlaintextVector32, GlweCiphertext32>
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
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let ct_container = vec![0_u32; glwe_dimension.to_glwe_size().0 * polynomial_size.0];
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let mut ciphertext: GlweCiphertext32 =
    ///     engine.create_glwe_ciphertext_from(ct_container, polynomial_size)?;
    /// engine.discard_trivially_encrypt_glwe_ciphertext(&mut ciphertext, &plaintext_vector)?;
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn discard_trivially_encrypt_glwe_ciphertext(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &PlaintextVector32,
    ) -> Result<(), GlweCiphertextDiscardingTrivialEncryptionError<Self::EngineError>> {
        GlweCiphertextDiscardingTrivialEncryptionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_trivially_encrypt_glwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut GlweCiphertext32,
        input: &PlaintextVector32,
    ) {
        output.0.fill_with_trivial_encryption(&input.0);
    }
}

impl GlweCiphertextDiscardingTrivialEncryptionEngine<PlaintextVector64, GlweCiphertext64>
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
    /// let input = vec![3_u64 << 20; polynomial_size.0];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let ct_container = vec![0_u64; glwe_dimension.to_glwe_size().0 * polynomial_size.0];
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let mut ciphertext: GlweCiphertext64 =
    ///     engine.create_glwe_ciphertext_from(ct_container, polynomial_size)?;
    /// engine.discard_trivially_encrypt_glwe_ciphertext(&mut ciphertext, &plaintext_vector)?;
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn discard_trivially_encrypt_glwe_ciphertext(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &PlaintextVector64,
    ) -> Result<(), GlweCiphertextDiscardingTrivialEncryptionError<Self::EngineError>> {
        GlweCiphertextDiscardingTrivialEncryptionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_trivially_encrypt_glwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut GlweCiphertext64,
        input: &PlaintextVector64,
    ) {
        output.0.fill_with_trivial_encryption(&input.0);
    }
}

impl GlweCiphertextDiscardingTrivialEncryptionEngine<PlaintextVector32, GlweCiphertextMutView32<'_>>
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
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut ct_container = vec![0_u32; glwe_dimension.to_glwe_size().0 * polynomial_size.0];
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let mut ciphertext: GlweCiphertextMutView32 =
    ///     engine.create_glwe_ciphertext_from(&mut ct_container[..], polynomial_size)?;
    /// engine.discard_trivially_encrypt_glwe_ciphertext(&mut ciphertext, &plaintext_vector)?;
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn discard_trivially_encrypt_glwe_ciphertext(
        &mut self,
        output: &mut GlweCiphertextMutView32,
        input: &PlaintextVector32,
    ) -> Result<(), GlweCiphertextDiscardingTrivialEncryptionError<Self::EngineError>> {
        GlweCiphertextDiscardingTrivialEncryptionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_trivially_encrypt_glwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut GlweCiphertextMutView32,
        input: &PlaintextVector32,
    ) {
        output.0.fill_with_trivial_encryption(&input.0);
    }
}

impl GlweCiphertextDiscardingTrivialEncryptionEngine<PlaintextVector64, GlweCiphertextMutView64<'_>>
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
    /// let input = vec![3_u64 << 20; polynomial_size.0];
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let mut ct_container = vec![0_u64; glwe_dimension.to_glwe_size().0 * polynomial_size.0];
    /// // DISCLAIMER: trivial encryption is NOT secure, and DOES NOT hide the message at all.
    /// let mut ciphertext: GlweCiphertextMutView64 =
    ///     engine.create_glwe_ciphertext_from(&mut ct_container[..], polynomial_size)?;
    /// engine.discard_trivially_encrypt_glwe_ciphertext(&mut ciphertext, &plaintext_vector)?;
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn discard_trivially_encrypt_glwe_ciphertext(
        &mut self,
        output: &mut GlweCiphertextMutView64,
        input: &PlaintextVector64,
    ) -> Result<(), GlweCiphertextDiscardingTrivialEncryptionError<Self::EngineError>> {
        GlweCiphertextDiscardingTrivialEncryptionError::perform_generic_checks(output, input)?;
        unsafe { self.discard_trivially_encrypt_glwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_trivially_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut GlweCiphertextMutView64,
        input: &PlaintextVector64,
    ) {
        output.0.fill_with_trivial_encryption(&input.0);
    }
}
