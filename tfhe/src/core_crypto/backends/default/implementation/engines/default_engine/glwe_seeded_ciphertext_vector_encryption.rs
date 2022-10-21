use super::ActivatedRandomGenerator;
use crate::core_crypto::backends::default::implementation::engines::DefaultEngine;
use crate::core_crypto::backends::default::implementation::entities::{
    GlweSecretKey32, GlweSecretKey64, GlweSeededCiphertextVector32, GlweSeededCiphertextVector64,
    PlaintextVector32, PlaintextVector64,
};
use crate::core_crypto::commons::crypto::glwe::GlweSeededList as ImplGlweSeededList;
use crate::core_crypto::commons::math::random::{CompressionSeed, Seeder};
use crate::core_crypto::prelude::{CiphertextCount, Variance};
use crate::core_crypto::specification::engines::{
    GlweSeededCiphertextVectorEncryptionEngine, GlweSeededCiphertextVectorEncryptionError,
};
use crate::core_crypto::specification::entities::{
    GlweSecretKeyEntity, PlaintextVectorEntity,
};

/// # Description:
/// Implementation of [`GlweSeededCiphertextVectorEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 32 bits integers.
impl
    GlweSeededCiphertextVectorEncryptionEngine<
        GlweSecretKey32,
        PlaintextVector32,
        GlweSeededCiphertextVector32,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey32 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let seeded_ciphertext_vector =
    ///     engine.encrypt_glwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(
    /// #     seeded_ciphertext_vector.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(seeded_ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(seeded_ciphertext_vector.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_seeded_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<
        GlweSeededCiphertextVector32,
        GlweSeededCiphertextVectorEncryptionError<Self::EngineError>,
    > {
        GlweSeededCiphertextVectorEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_seeded_ciphertext_vector_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> GlweSeededCiphertextVector32 {
        let mut output = ImplGlweSeededList::allocate(
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(input.plaintext_count().0 / key.polynomial_size().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );

        key.0
            .encrypt_seeded_glwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        GlweSeededCiphertextVector32(output)
    }
}

/// # Description:
/// Implementation of [`GlweSeededCiphertextVectorEncryptionEngine`] for [`DefaultEngine`] that
/// operates on 64 bits integers.
impl
    GlweSeededCiphertextVectorEncryptionEngine<
        GlweSecretKey64,
        PlaintextVector64,
        GlweSeededCiphertextVector64,
    > for DefaultEngine
{
    /// # Example:
    /// ```
    /// use tfhe::core_crypto::prelude::Variance;
    /// use tfhe::core_crypto::prelude::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use tfhe::core_crypto::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// // Unix seeder must be given a secret input.
    /// // Here we just give it 0, which is totally unsafe.
    /// const UNSAFE_SECRET: u128 = 0;
    /// let mut engine = DefaultEngine::new(Box::new(UnixSeeder::new(UNSAFE_SECRET)))?;
    /// let key: GlweSecretKey64 = engine.generate_new_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector_from(&input)?;
    ///
    /// let seeded_ciphertext_vector =
    ///     engine.encrypt_glwe_seeded_ciphertext_vector(&key, &plaintext_vector, noise)?;
    /// #
    /// assert_eq!(
    /// #     seeded_ciphertext_vector.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    /// assert_eq!(seeded_ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(seeded_ciphertext_vector.glwe_dimension(), glwe_dimension);
    ///
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn encrypt_glwe_seeded_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<
        GlweSeededCiphertextVector64,
        GlweSeededCiphertextVectorEncryptionError<Self::EngineError>,
    > {
        GlweSeededCiphertextVectorEncryptionError::perform_generic_checks(key, input)?;
        Ok(unsafe { self.encrypt_glwe_seeded_ciphertext_vector_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_seeded_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> GlweSeededCiphertextVector64 {
        let mut output = ImplGlweSeededList::allocate(
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(input.plaintext_count().0 / key.polynomial_size().0),
            CompressionSeed {
                seed: self.seeder.seed(),
            },
        );

        key.0
            .encrypt_seeded_glwe_list::<_, _, _, _, _, ActivatedRandomGenerator>(
                &mut output,
                &input.0,
                noise,
                &mut self.seeder,
            );

        GlweSeededCiphertextVector64(output)
    }
}
