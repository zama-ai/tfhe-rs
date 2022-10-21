use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount, Variance};

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GgswCiphertext32, GgswCiphertext64, GlweSecretKey32, GlweSecretKey64, Plaintext32, Plaintext64,
};
use crate::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext as ImplGgswCiphertext;
use crate::core_crypto::specification::engines::{
    GgswCiphertextScalarEncryptionEngine, GgswCiphertextScalarEncryptionError,
};
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GgswCiphertextScalarEncryptionEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl GgswCiphertextScalarEncryptionEngine<GlweSecretKey32, Plaintext32, GgswCiphertext32>
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
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_scalar_ggsw_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Result<GgswCiphertext32, GgswCiphertextScalarEncryptionError<Self::EngineError>> {
        Ok(unsafe {
            self.encrypt_scalar_ggsw_ciphertext_unchecked(
                key,
                input,
                noise,
                decomposition_level_count,
                decomposition_base_log,
            )
        })
    }

    unsafe fn encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &Plaintext32,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> GgswCiphertext32 {
        let mut ciphertext = ImplGgswCiphertext::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
            decomposition_level_count,
            decomposition_base_log,
        );
        key.0.encrypt_constant_ggsw(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GgswCiphertext32(ciphertext)
    }
}

/// # Description:
/// Implementation of [`GgswCiphertextScalarEncryptionEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl GgswCiphertextScalarEncryptionEngine<GlweSecretKey64, Plaintext64, GgswCiphertext64>
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
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext = engine.create_plaintext_from(&input)?;
    ///
    /// let ciphertext =
    ///     engine.encrypt_scalar_ggsw_ciphertext(&key, &plaintext, noise, level, base_log)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_scalar_ggsw_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> Result<GgswCiphertext64, GgswCiphertextScalarEncryptionError<Self::EngineError>> {
        Ok(unsafe {
            self.encrypt_scalar_ggsw_ciphertext_unchecked(
                key,
                input,
                noise,
                decomposition_level_count,
                decomposition_base_log,
            )
        })
    }

    unsafe fn encrypt_scalar_ggsw_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &Plaintext64,
        noise: Variance,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
    ) -> GgswCiphertext64 {
        let mut ciphertext = ImplGgswCiphertext::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
            decomposition_level_count,
            decomposition_base_log,
        );
        key.0.encrypt_constant_ggsw(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GgswCiphertext64(ciphertext)
    }
}
