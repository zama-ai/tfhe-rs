use crate::core_crypto::prelude::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize,
};

use crate::core_crypto::backends::default::entities::{
    GgswCiphertext32, GgswCiphertext64, Plaintext32, Plaintext64,
};
use crate::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext as ImplGgswCiphertext;
use crate::core_crypto::specification::engines::{
    GgswCiphertextScalarTrivialEncryptionEngine, GgswCiphertextScalarTrivialEncryptionError,
};

use crate::core_crypto::backends::default::engines::DefaultEngine;

/// # Description:
/// Implementation of [`GgswCiphertextScalarTrivialEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl GgswCiphertextScalarTrivialEncryptionEngine<Plaintext32, GgswCiphertext32> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// let input = 3_u32 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext32 = engine.create_plaintext_from(&input)?;
    /// let ciphertext: GgswCiphertext32 = engine.trivially_encrypt_scalar_ggsw_ciphertext(
    ///     polynomial_size,
    ///     glwe_dimension.to_glwe_size(),
    ///     level,
    ///     base_log,
    ///     &plaintext,
    /// )?;
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext.decomposition_base_log(), base_log);
    /// assert_eq!(ciphertext.decomposition_level_count(), level);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_scalar_ggsw_ciphertext(
        &mut self,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        input: &Plaintext32,
    ) -> Result<GgswCiphertext32, GgswCiphertextScalarTrivialEncryptionError<Self::EngineError>>
    {
        unsafe {
            Ok(self.trivially_encrypt_scalar_ggsw_ciphertext_unchecked(
                polynomial_size,
                glwe_size,
                decomposition_level_count,
                decomposition_base_log,
                input,
            ))
        }
    }

    unsafe fn trivially_encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        input: &Plaintext32,
    ) -> GgswCiphertext32 {
        let ciphertext: ImplGgswCiphertext<Vec<u32>> = ImplGgswCiphertext::new_trivial_encryption(
            polynomial_size,
            glwe_size,
            decomposition_level_count,
            decomposition_base_log,
            &input.0,
        );
        GgswCiphertext32(ciphertext)
    }
}

/// # Description:
/// Implementation of [`GgswCiphertextScalarTrivialEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl GgswCiphertextScalarTrivialEncryptionEngine<Plaintext64, GgswCiphertext64> for DefaultEngine {
    /// # Example:
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    ///
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// let input = 3_u64 << 20;
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let plaintext: Plaintext64 = engine.create_plaintext_from(&input)?;
    /// let ciphertext: GgswCiphertext64 = engine.trivially_encrypt_scalar_ggsw_ciphertext(
    ///     polynomial_size,
    ///     glwe_dimension.to_glwe_size(),
    ///     level,
    ///     base_log,
    ///     &plaintext,
    /// )?;
    ///
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// # Ok(())
    /// # }
    /// ```
    fn trivially_encrypt_scalar_ggsw_ciphertext(
        &mut self,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        input: &Plaintext64,
    ) -> Result<GgswCiphertext64, GgswCiphertextScalarTrivialEncryptionError<Self::EngineError>>
    {
        unsafe {
            Ok(self.trivially_encrypt_scalar_ggsw_ciphertext_unchecked(
                polynomial_size,
                glwe_size,
                decomposition_level_count,
                decomposition_base_log,
                input,
            ))
        }
    }

    unsafe fn trivially_encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        polynomial_size: PolynomialSize,
        glwe_size: GlweSize,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        input: &Plaintext64,
    ) -> GgswCiphertext64 {
        let ciphertext: ImplGgswCiphertext<Vec<u64>> = ImplGgswCiphertext::new_trivial_encryption(
            polynomial_size,
            glwe_size,
            decomposition_level_count,
            decomposition_base_log,
            &input.0,
        );
        GgswCiphertext64(ciphertext)
    }
}
