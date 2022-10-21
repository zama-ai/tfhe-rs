use crate::core_crypto::prelude::Variance;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GgswCiphertext32, GgswCiphertext64, GlweSecretKey32, GlweSecretKey64, Plaintext32, Plaintext64,
};
use crate::core_crypto::specification::engines::{
    GgswCiphertextScalarDiscardingEncryptionEngine, GgswCiphertextScalarDiscardingEncryptionError,
};

/// # Description:
/// Implementation of [`GgswCiphertextScalarDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl GgswCiphertextScalarDiscardingEncryptionEngine<GlweSecretKey32, Plaintext32, GgswCiphertext32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key_1: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let mut ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key_1, &plaintext, noise, level, base_log)?;
    /// // We're going to re-encrypt the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// engine.discard_encrypt_scalar_ggsw_ciphertext(&key_2, &mut ciphertext, &plaintext, noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_scalar_ggsw_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GgswCiphertext32,
        input: &Plaintext32,
        noise: Variance,
    ) -> Result<(), GgswCiphertextScalarDiscardingEncryptionError<Self::EngineError>> {
        GgswCiphertextScalarDiscardingEncryptionError::perform_generic_checks(key, output)?;
        unsafe { self.discard_encrypt_scalar_ggsw_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GgswCiphertext32,
        input: &Plaintext32,
        noise: Variance,
    ) {
        key.0.encrypt_constant_ggsw(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`GgswCiphertextScalarDiscardingEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl GgswCiphertextScalarDiscardingEncryptionEngine<GlweSecretKey64, Plaintext64, GgswCiphertext64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize, Variance, *,
    /// };
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let level = DecompositionLevelCount(1);
    /// let base_log = DecompositionBaseLog(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key_1: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    /// let mut ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key_1, &plaintext, noise, level, base_log)?;
    /// // We're going to re-encrypt the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// engine.discard_encrypt_scalar_ggsw_ciphertext(&key_2, &mut ciphertext, &plaintext, noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_scalar_ggsw_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GgswCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) -> Result<(), GgswCiphertextScalarDiscardingEncryptionError<Self::EngineError>> {
        GgswCiphertextScalarDiscardingEncryptionError::perform_generic_checks(key, output)?;
        unsafe { self.discard_encrypt_scalar_ggsw_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GgswCiphertext64,
        input: &Plaintext64,
        noise: Variance,
    ) {
        key.0.encrypt_constant_ggsw(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
