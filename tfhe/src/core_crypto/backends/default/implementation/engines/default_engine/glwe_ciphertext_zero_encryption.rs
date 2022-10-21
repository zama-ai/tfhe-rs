use crate::core_crypto::prelude::Variance;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64,
};
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::core_crypto::specification::engines::{
    GlweCiphertextZeroEncryptionEngine, GlweCiphertextZeroEncryptionError,
};
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GlweCiphertextZeroEncryptionEngine`] for [`DefaultEngine`] that operates on
/// 32 bits integers.
impl GlweCiphertextZeroEncryptionEngine<GlweSecretKey32, GlweCiphertext32> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let ciphertext = engine.zero_encrypt_glwe_ciphertext(&key, noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        noise: Variance,
    ) -> Result<GlweCiphertext32, GlweCiphertextZeroEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.zero_encrypt_glwe_ciphertext_unchecked(key, noise) })
    }

    unsafe fn zero_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        noise: Variance,
    ) -> GlweCiphertext32 {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
        );
        key.0
            .encrypt_zero_glwe(&mut ciphertext, noise, &mut self.encryption_generator);
        GlweCiphertext32(ciphertext)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextZeroEncryptionEngine`] for [`DefaultEngine`] that operates on
/// 64 bits integers.
impl GlweCiphertextZeroEncryptionEngine<GlweSecretKey64, GlweCiphertext64> for DefaultEngine {
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(1024);
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    ///
    /// let ciphertext = engine.zero_encrypt_glwe_ciphertext(&key, noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn zero_encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        noise: Variance,
    ) -> Result<GlweCiphertext64, GlweCiphertextZeroEncryptionError<Self::EngineError>> {
        Ok(unsafe { self.zero_encrypt_glwe_ciphertext_unchecked(key, noise) })
    }

    unsafe fn zero_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        noise: Variance,
    ) -> GlweCiphertext64 {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
        );
        key.0
            .encrypt_zero_glwe(&mut ciphertext, noise, &mut self.encryption_generator);
        GlweCiphertext64(ciphertext)
    }
}
