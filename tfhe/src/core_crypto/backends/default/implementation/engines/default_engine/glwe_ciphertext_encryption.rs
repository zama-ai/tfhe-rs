use crate::core_crypto::prelude::Variance;

use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextVector32,
    PlaintextVector64,
};
use crate::core_crypto::commons::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::core_crypto::specification::engines::{
    GlweCiphertextEncryptionEngine, GlweCiphertextEncryptionError,
};
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GlweCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates on 32
/// bits integers.
impl GlweCiphertextEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphertext32>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<GlweCiphertext32, GlweCiphertextEncryptionError<Self::EngineError>> {
        GlweCiphertextEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> GlweCiphertext32 {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
        );
        key.0.encrypt_glwe(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertext32(ciphertext)
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates on 64
/// bits integers.
impl GlweCiphertextEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphertext64>
    for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::{GlweDimension, PolynomialSize, Variance, *};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 =
    ///     engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let ciphertext = engine.encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<GlweCiphertext64, GlweCiphertextEncryptionError<Self::EngineError>> {
        GlweCiphertextEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> GlweCiphertext64 {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
        );
        key.0.encrypt_glwe(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertext64(ciphertext)
    }
}
