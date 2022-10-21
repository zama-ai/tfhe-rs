use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::engines::DefaultEngine;
use crate::core_crypto::backends::default::entities::{
    GlweSecretKey32, GlweSecretKey64, GlweSeededCiphertext32, GlweSeededCiphertext64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::glwe::GlweSeededCiphertext as ImplGlweSeededCiphertext;
use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
use crate::core_crypto::prelude::Variance;
use crate::core_crypto::specification::engines::{
    GlweSeededCiphertextEncryptionEngine, GlweSeededCiphertextEncryptionError,
};
use crate::core_crypto::specification::entities::GlweSecretKeyEntity;

/// # Description:
/// Implementation of [`GlweSeededCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates
/// on 32 bits integers.
impl
    GlweSeededCiphertextEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweSeededCiphertext32>
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
    /// let seeded_ciphertext =
    ///     engine.encrypt_glwe_seeded_ciphertext(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(seeded_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(seeded_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_seeded_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<GlweSeededCiphertext32, GlweSeededCiphertextEncryptionError<Self::EngineError>>
    {
        GlweSeededCiphertextEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_seeded_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> GlweSeededCiphertext32 {
        let mut output = ImplGlweSeededCiphertext::allocate(
            key.polynomial_size(),
            key.glwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );

        key.0
            .encrypt_seeded_glwe::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        GlweSeededCiphertext32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSeededCiphertextEncryptionEngine`] for [`DefaultEngine`] that operates
/// on 64 bits integers.
impl
    GlweSeededCiphertextEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweSeededCiphertext64>
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
    /// let seeded_ciphertext =
    ///     engine.encrypt_glwe_seeded_ciphertext(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(seeded_ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(seeded_ciphertext.polynomial_size(), polynomial_size);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_seeded_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<GlweSeededCiphertext64, GlweSeededCiphertextEncryptionError<Self::EngineError>>
    {
        GlweSeededCiphertextEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_seeded_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_seeded_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> GlweSeededCiphertext64 {
        let mut output = ImplGlweSeededCiphertext::allocate(
            key.polynomial_size(),
            key.glwe_dimension(),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );

        key.0
            .encrypt_seeded_glwe::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        GlweSeededCiphertext64(output)
    }
}
